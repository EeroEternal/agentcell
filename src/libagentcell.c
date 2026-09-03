/*
 * libagentcell.c — C ABI over the sand internals (RFC 0001, Gap 5).
 *
 * Unity build: sand.c is #included with main() renamed, so every
 * isolation layer (cgroups, namespaces, pivot, Landlock, seccomp,
 * veth/egress) is literally the CLI's code — no second implementation
 * to drift.  die() longjmps back to the caller instead of exiting the
 * hosting process (see sand.c).
 */
/* must precede any system header: sand.c's feature-test macros apply
 * to the unity build too */
#define _GNU_SOURCE
#include "agentcell.h"

#define main sand_main
#include "sand.c"
#undef main

/* teardown bookkeeping per spawned cell */
struct cell_rec {
    pid_t pid;
    int   have_cg;
    char  cgpath[PATH_MAX];
    unsigned long long cgid;    /* 0 = not LSM-registered */
    void *stack;                /* freed in release(): the child runs on
                                 * it until execvp, so it must outlive
                                 * spawn() — munmap here would kill it */
};
static struct cell_rec g_recs[16];

static double mem_total_frac(double frac)
{
    FILE *f = fopen("/proc/meminfo", "r");
    char k[64];
    long v = 0;
    while (f && fscanf(f, "%63s %ld kB", k, &v) == 2)
        if (!strcmp(k, "MemTotal:"))
            break;
    if (f) fclose(f);
    return (double)v * 1024 * frac;
}

static struct cell_rec *free_rec(void)
{
    for (int i = 0; i < 16; i++)
        if (!g_recs[i].pid)
            return &g_recs[i];
    return NULL;
}

int agentcell_spawn(const struct agentcell_config *cfg,
                    const char *argv[], const char *envp[],
                    int stdin_fd, int stdout_fd, int stderr_fd,
                    pid_t *out_pid)
{
    if (!cfg || !argv || !argv[0] || !out_pid)
        return -EINVAL;
    if (stdin_fd < -1 || stdout_fd < -1 || stderr_fd < -1)
        return -EINVAL;

    struct cell_rec *rec = free_rec();
    if (!rec)
        return -EBUSY;          /* release() before spawning more */
    rec->pid = 0;
    rec->stack = NULL;          /* freed in agentcell_release */

    /* ---- fresh globals for this spawn (statics persist in the lib) */
    memset(&C, 0, sizeof C);
    snprintf(g_newroot, sizeof g_newroot, "%s", "/tmp/agentcell-root.XXXXXX");
    g_cgpath[0] = 0;
    g_have_cg = 0;
    g_veth_on = 0;
    g_lsm_on = 0;
    g_lsm_cgid = 0;
    g_serve = 0;                 /* serve/--ask stay CLI-only for now */
    g_spawn_fds[0] = stdin_fd;
    g_spawn_fds[1] = stdout_fd;
    g_spawn_fds[2] = stderr_fd;
    g_spawn_envp = (char **)envp;

    jmp_buf jb;
    g_die_jmp = &jb;
    int rc = setjmp(jb);
    if (rc) {                   /* die() fired */
        g_die_jmp = NULL;
        g_spawn_fds[0] = g_spawn_fds[1] = g_spawn_fds[2] = -1;
        g_spawn_envp = NULL;
        if (g_have_cg) rmdir(g_cgpath);
        rmdir(g_newroot);
        if (rec->stack) free(rec->stack);
        rec->pid = 0;
        return -rc;
    }

    /* ---- config mapping */
    C.mem_bytes = cfg->mem_bytes ? (long)cfg->mem_bytes
                                 : (long)mem_total_frac(0.6);
    if (cfg->cpu_cores > 0)
        snprintf(C.cpu_max, sizeof C.cpu_max, "%ld 100000",
                 (long)(cfg->cpu_cores * 100000));
    C.pids    = cfg->pids ? (int)cfg->pids : 256;
    C.netmode = (cfg->net == AGENTCELL_NET_HOST || cfg->net == AGENTCELL_NET_VETH)
                ? cfg->net : NET_NONE;
    C.secure     = cfg->secure;
    C.no_landlock = cfg->no_landlock;
    C.no_seccomp  = cfg->no_seccomp;
    C.argv = (char *const *)(void *)argv;   /* const discarded via void* */

    if (cfg->workdir) {
        if (!realpath(cfg->workdir, C.workdir)) die("workdir");
    } else {
        char def[PATH_MAX];
        snprintf(def, sizeof def, "%s/agent-work",
                 getenv("HOME") ?: "/tmp");
        mmkdir_p(def, 0755);
        if (!realpath(def, C.workdir)) die(def);
    }
    if (cfg->rootfs) {
        struct stat st;
        if (!realpath(cfg->rootfs, C.rootfs)) die("rootfs");
        if (stat(C.rootfs, &st) < 0 || !S_ISDIR(st.st_mode)) die("rootfs");
    }
    if (cfg->egress) {
        const char *c = strrchr(cfg->egress, ':');
        if (!c || !c[1] || c == cfg->egress) die("--egress HOST:PORT");
        snprintf(C.egress_host, sizeof C.egress_host, "%.*s",
                 (int)(c - cfg->egress), cfg->egress);
        snprintf(C.egress_port, sizeof C.egress_port, "%s", c + 1);
        C.netmode = NET_VETH;
    }

    /* ---- the sand one-shot path, minus the waiting */
    g_uid = getuid();           /* main() sets these in the CLI; the
                                 * library must do it for itself — else
                                 * uid_map maps 0->0 and EPERMs */
    g_gid = getgid();
    if (!mkdtemp(g_newroot)) die("mkdtemp");
    cgroup_setup();
    if (pipe(g_sync) < 0) die("pipe");

    const size_t SZ = 1 << 20;
    rec->stack = malloc(SZ);    /* owned by the cell until it exits */
    if (!rec->stack) die("malloc");
    char *stack = rec->stack;

    const int ns = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
                   CLONE_NEWUTS |
                   (C.netmode != NET_HOST ? CLONE_NEWNET : 0);
    pid_t pid = clone(child_main, stack + SZ, ns | SIGCHLD, NULL);
    if (pid < 0)
        die("clone (userns disabled? sysctl kernel.unprivileged_userns_clone)");

    close(g_sync[0]);
    write_uid_maps(pid);

    if (g_have_cg) {
        char p[PATH_MAX], v[32];
        snprintf(p, sizeof p, "%s/cgroup.procs", g_cgpath);
        snprintf(v, sizeof v, "%d", pid);
        write_file(p, v);
    }
    if (C.secure && g_have_cg)
        lsm_register();         /* warn-only if daemon is down */
    if (C.netmode == NET_VETH)
        net_veth_register(pid); /* fallback to no-net on failure */

    char syncmsg[192] = "x";
    if (g_veth_on)
        snprintf(syncmsg, sizeof syncmsg, "x %s %s %s",
                 C.veth_if, C.veth_ip, C.veth_gw);
    if (write(g_sync[1], syncmsg, strlen(syncmsg)) < 0) warn2("sync child");
    close(g_sync[1]);

    /* the child's copies of the globals are COW — safe to reset here */
    g_spawn_fds[0] = g_spawn_fds[1] = g_spawn_fds[2] = -1;
    g_spawn_envp = NULL;

    memset(rec, 0, sizeof *rec);
    rec->pid = pid;
    rec->have_cg = g_have_cg;
    snprintf(rec->cgpath, sizeof rec->cgpath, "%s", g_cgpath);
    rec->cgid = g_lsm_cgid;
    /* keep the stack: the child runs on it until execvp; released in
     * agentcell_release() after the caller's waitpid() */

    g_die_jmp = NULL;
    *out_pid = pid;
    return 0;
}

int agentcell_release(pid_t pid)
{
    if (pid <= 0)
        return -EINVAL;
    for (int i = 0; i < 16; i++) {
        if (g_recs[i].pid != pid)
            continue;
        char cmd[64];
        snprintf(cmd, sizeof cmd, "NETDOWN %d", (int)pid);
        lsm_cmd(cmd, NULL, 0);              /* tolerated if absent */
        if (g_recs[i].cgid) {
            snprintf(cmd, sizeof cmd, "CLR %llu", g_recs[i].cgid);
            lsm_cmd(cmd, NULL, 0);
        }
        if (g_recs[i].have_cg)
            rmdir(g_recs[i].cgpath);
        if (g_recs[i].stack)
            free(g_recs[i].stack);
        memset(&g_recs[i], 0, sizeof g_recs[i]);
        return 0;
    }
    return 0;    /* unknown pid: NETDOWN already best-efforted above? no —
                    but tolerate double-release without error */
}

const char *agentcell_version(void)
{
    return "agentcell 0.1.0 (FFI)";
}
