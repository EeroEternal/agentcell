/*
 * sand.c — a from-scratch agent sandbox using raw Linux primitives.
 *
 * Layers of defense (applied per child process):
 *   1. cgroup v2 resource limits (cpu.max / memory.max / pids.max)
 *   2. namespaces via clone(2): user mount pid net ipc uts cgroup
 *   3. minimal root: tmpfs root + pivot_root(2), read-only bind mounts for
 *      /usr /etc /opt, rw tmpfs for /tmp /run /var/tmp, fresh /proc, fresh
 *      /dev with 5 bound device nodes
 *   4. Landlock LSM: path-based allowlist (what may be read / written / exec'd)
 *   5. Seccomp-BPF: hand-built sock_filter deny-list (module loads, ptrace,
 *      bpf, new mount API, io_uring, keyring, time-setting, ...)
 *
 * Runs 100% unprivileged — user namespaces give the child "root" that maps
 * to your normal uid outside, so a breakout gains nothing.
 *
 * Build:  cc -O2 -o sand sand.c
 * Usage:  ./sand [--mem 2G] [--cpu 2] [--pids 256] [--net none|host]
 *                [--workdir DIR] [--ro DIR]... [--rw DIR]... -- CMD [ARGS]
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAXBIND 32

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static void die(const char *msg)
{
    fprintf(stderr, "sand: %s: %s\n", msg, strerror(errno));
    exit(1);
}

static void warn2(const char *msg)
{
    fprintf(stderr, "sand: %s: %s (continuing)\n", msg, strerror(errno));
}

static const char *basename_of(const char *p)
{
    const char *r = strrchr(p, '/');
    return r ? r + 1 : p;
}

static void write_file(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) { warn2(path); return; }
    if (write(fd, val, strlen(val)) < 0) warn2(path);
    close(fd);
}

static void mmkdir(const char *p, mode_t m)
{
    if (mkdir(p, m) < 0 && errno != EEXIST)
        die(p);
}

static void mmkdir_p(const char *path, mode_t m)
{
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++)
        if (*p == '/') { *p = 0; mmkdir(tmp, m); *p = '/'; }
    mmkdir(tmp, m);
}

static void bind_mount(const char *src, const char *dst, int ro, int rec)
{
    unsigned long fl = MS_BIND | (rec ? MS_REC : 0);
    if (mount(src, dst, NULL, fl, NULL) < 0) {
        char msg[PATH_MAX * 2];
        snprintf(msg, sizeof msg, "bind %s -> %s", src, dst);
        die(msg);
    }
    if (ro)
        if (mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY |
                  (rec ? MS_REC : 0), NULL) < 0)
            die("remount ro");
}

static void tmpfs_mount(const char *dst, const char *opts)
{
    if (mount("tmpfs", dst, "tmpfs", MS_NOSUID | MS_NODEV, opts) < 0)
        die(dst);
}

/* ------------------------------------------------------------------ */
/* config                                                              */
/* ------------------------------------------------------------------ */

struct cfg {
    long mem_bytes;
    char cpu_max[64];
    int  pids;
    int  net_none;
    char workdir[PATH_MAX];
    char *ro[MAXBIND]; int n_ro;
    char *rw[MAXBIND]; int n_rw;
    struct bind { char src[PATH_MAX]; char dst[PATH_MAX]; int ro; }
         binds[MAXBIND]; int n_binds;
    int  no_landlock;
    int  no_seccomp;
    int  secure;                    /* register with agentlsm daemon */
    char deny[MAXBIND][256];        /* extra LSM deny prefixes */
    int  n_deny;
    int  timeout;
    char *const *argv;
};

static struct cfg C = {
    .mem_bytes = 2L << 30,
    .cpu_max   = "200000 100000",
    .pids      = 256,
    .net_none  = 1,
    .workdir   = "",
};

static uid_t g_uid;
static gid_t g_gid;
static int   g_sync[2];              /* parent -> child: uid maps ready */
static char  g_newroot[] = "/tmp/agentcell-root.XXXXXX";
static char  g_cgpath[PATH_MAX];
static int   g_have_cg;

/* ---- long-running (serve) mode ---- */
static int   g_serve;                 /* 1 = jail stays alive, serves execs */
static int   g_host_sock = -1;        /* supervisor end of the socketpair   */
static int   g_jail_sock = -1;        /* jail end, inherited by the child   */
static char  g_sock_path[PATH_MAX];   /* host-facing unix socket            */
static char  g_info_path[PATH_MAX];   /* sidecar with cg path, execs, ...   */
static long  g_execs;
static __u64 g_lsm_cgid;              /* cell id at the agentlsm daemon    */
static int   g_lsm_on;

static void lsm_register(void);       /* defined with the exec client code */
static void lsm_unregister(void);

static void write_info(pid_t jail)
{
    FILE *f = fopen(g_info_path, "w");
    if (!f) return;
    fprintf(f, "sup=%d\njail=%d\nstarted=%ld\ncg=%s\nexecs=%ld\n"
               "secure=%d\ncgid=%llu\n",
            (int)getpid(), (int)jail, (long)time(NULL),
            g_have_cg ? g_cgpath : "-", g_execs,
            C.secure, (unsigned long long)g_lsm_cgid);
    fclose(f);
}

/* read one line "key value" from a cgroup file like cpu.stat */
static long cg_stat(const char *cg, const char *file, const char *key)
{
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s/%s", cg, file);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    long v = -1;
    char line[256], k[64];
    while (fgets(line, sizeof line, f))
        if (sscanf(line, "%63s %ld", k, &v) == 2 && !strcmp(k, key))
            break;
    fclose(f);
    return v;
}

static long cg_num(const char *cg, const char *file)
{
    char p[PATH_MAX]; long v = -1;
    snprintf(p, sizeof p, "%s/%s", cg, file);
    FILE *f = fopen(p, "r");
    if (f) { if (fscanf(f, "%ld", &v) != 1) v = -1; fclose(f); }
    return v;
}

static void fmt_human(long bytes, char *out, size_t n)
{
    if (bytes < 0)            snprintf(out, n, "-");
    else if (bytes < 1<<20)   snprintf(out, n, "%ldK", bytes >> 10);
    else if (bytes < 1<<30)   snprintf(out, n, "%ldM", bytes >> 20);
    else                      snprintf(out, n, "%.1fG", bytes / 1073741824.0);
}

static int cell_info(const char *sock_base, pid_t *sup, pid_t *jail,
                     long *started, char *cg, size_t cgn, long *execs)
{
    char p[PATH_MAX];
    snprintf(p, sizeof p, "%s.info", sock_base);
    FILE *f = fopen(p, "r");
    if (!f) return -1;
    char line[256];
    cg[0] = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strncmp(line, "sup=", 4))     *sup = atoi(line + 4);
        else if (!strncmp(line, "jail=", 5))   *jail = atoi(line + 5);
        else if (!strncmp(line, "started=", 8)) *started = atol(line + 8);
        else if (!strncmp(line, "cg=", 3)) { line[strcspn(line, "\n")] = 0;
                                              snprintf(cg, cgn, "%s", line + 3); }
        else if (!strncmp(line, "execs=", 6))  *execs = atol(line + 6);
    }
    fclose(f);
    return 0;
}

static int list_cells(void)
{
    const char *rt = getenv("XDG_RUNTIME_DIR");
    if (!rt) rt = "/tmp";
    DIR *d = opendir(rt);
    if (!d) { perror(rt); return 1; }

    printf("%-22s %-8s %-9s %-8s %-7s %-7s %s\n",
           "SOCKET", "SUP", "UPTIME", "EXECS", "CPU(s)", "MEM", "PIDS");
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) {
        size_t nlen = strlen(e->d_name);
        if (nlen < 5 || strcmp(e->d_name + nlen - 5, ".sock") ||
            strncmp(e->d_name, "agentcell-", 10))
            continue;
        char base[PATH_MAX];
        snprintf(base, sizeof base, "%s/%s", rt, e->d_name);

        pid_t sup = 0, jail = 0; long started = 0, execs = 0;
        char cg[PATH_MAX] = "";
        if (cell_info(base, &sup, &jail, &started, cg, sizeof cg, &execs) < 0)
            continue;
        if (kill(sup, 0) < 0 && errno == ESRCH) continue;  /* stale */
        found++;

        long up = time(NULL) - started;
        char mem[16];
        long memc = cg[0] && strcmp(cg, "-") ? cg_num(cg, "memory.current") : -1;
        fmt_human(memc, mem, sizeof mem);
        long usec = cg[0] && strcmp(cg, "-") ? cg_stat(cg, "cpu.stat", "usage_usec") : -1;
        long pids = cg[0] && strcmp(cg, "-") ? cg_num(cg, "pids.current") : -1;

        printf("%-22s %-8d %02ld:%02ld:%02ld %-8ld %-7ld %-7s %ld\n",
               e->d_name, sup, up / 3600, (up / 60) % 60, up % 60,
               execs, usec < 0 ? -1 : usec / 1000000, mem, pids);
    }
    closedir(d);
    return found ? 0 : 1;
}

static int top_cells(const char *sock)
{
    char base[PATH_MAX];
    const char *dot = strstr(sock, ".sock");
    if (!dot) { fprintf(stderr, "sand: not a cell socket: %s\n", sock); return 2; }
    snprintf(base, sizeof base, "%.*s", (int)(dot - sock + 5), sock);

    pid_t sup, jail; long started, execs; char cg[PATH_MAX];
    if (cell_info(base, &sup, &jail, &started, cg, sizeof cg, &execs) < 0) {
        fprintf(stderr, "sand: no info for %s\n", sock); return 1;
    }
    fprintf(stderr, "cell pid %d  cg %s  — Ctrl-C to stop\n\n", jail, cg);

    long prev_usec = 0;
    for (;;) {
        long usec = cg_stat(cg, "cpu.stat", "usage_usec");
        long mem  = cg_num(cg, "memory.current");
        long pids = cg_num(cg, "pids.current");
        long memmax = cg_num(cg, "memory.max");
        long dusec = usec - prev_usec; prev_usec = usec;
        char mems[16], maxs[16];
        fmt_human(mem, mems, sizeof mems);
        fmt_human(memmax, maxs, sizeof maxs);
        printf("\rcpu %6ldms/s  mem %s/%s  pids %ld  execs %ld    ",
               dusec / 1000, mems, maxs, pids, execs);
        fflush(stdout);
        sleep(1);
        /* refresh execs from sidecar */
        cell_info(base, &sup, &jail, &started, cg, sizeof cg, &execs);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 1. cgroup v2 limits (unprivileged, via systemd's delegated subtree) */
/* ------------------------------------------------------------------ */

static void cgroup_setup(void)
{
    char self[PATH_MAX] = {0}, base[PATH_MAX], line[512], p[PATH_MAX], v[64];
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) return;
    while (fgets(line, sizeof line, f))
        if (strncmp(line, "0::", 3) == 0) {
            line[strcspn(line, "\n")] = 0;
            snprintf(self, sizeof self, "%s", line + 3);
        }
    fclose(f);
    if (!self[0]) return;

    /* systemd session scopes are leaf cgroups — children are only allowed
     * under the delegated user@UID.service root. Cut the path there.     */
    snprintf(base, sizeof base, "/sys/fs/cgroup%s", self);
    char *svc = strstr(base, "/user@");
    if (svc) {
        char *slash = strchr(svc + 1, '/');
        if (slash) {
            /* keep app-XXX.slice prefixes? no: go straight under the service */
            *slash = 0;
            /* re-extend: base now ends at user@1000.service */
        }
    }

    /* arm controllers for our children; EPERM is fine if not delegated */
    snprintf(p, sizeof p, "%s/cgroup.subtree_control", base);
    write_file(p, "+cpu +memory +pids");

    snprintf(g_cgpath, sizeof g_cgpath, "%s/agentcell-%d", base, (int)getpid());
    if (mkdir(g_cgpath, 0755) < 0) {
        warn2("create cgroup (running without resource limits)");
        return;
    }

    snprintf(p, sizeof p, "%s/cpu.max", g_cgpath);     write_file(p, C.cpu_max);
    snprintf(v, sizeof v, "%ld", C.mem_bytes);
    snprintf(p, sizeof p, "%s/memory.max", g_cgpath);  write_file(p, v);
    snprintf(v, sizeof v, "%d", C.pids);
    snprintf(p, sizeof p, "%s/pids.max", g_cgpath);    write_file(p, v);
    g_have_cg = 1;
}

/* ------------------------------------------------------------------ */
/* 2+3. build a minimal root in a tmpfs, then pivot_root               */
/* ------------------------------------------------------------------ */

#define NR(path) snprintf(p, sizeof p, "%s%s", g_newroot, path)

static void do_mounts(void)
{
    char p[PATH_MAX];

    /* whole namespace private: nothing propagates back to the host */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        die("make mounts private");

    /* the new root itself is a tiny tmpfs */
    if (mount("tmpfs", g_newroot, "tmpfs", MS_NOSUID, "size=16m,mode=0755") < 0)
        die("newroot tmpfs");

    /* read-only OS view: on Arch /bin,/lib… are symlinks into /usr */
    NR("/usr");    mmkdir(p, 0755); bind_mount("/usr", p, 1, 1);
    NR("/etc");    mmkdir(p, 0755); bind_mount("/etc", p, 1, 1);
    NR("/opt");    mmkdir(p, 0755); bind_mount("/opt", p, 1, 1);

    NR("/bin");    if (symlink("usr/bin",  p) && errno != EEXIST) die("symlink /bin");
    NR("/sbin");   if (symlink("usr/bin",  p) && errno != EEXIST) die("symlink /sbin");
    NR("/lib");    if (symlink("usr/lib",  p) && errno != EEXIST) die("symlink /lib");
    NR("/lib64");  if (symlink("usr/lib",  p) && errno != EEXIST) die("symlink /lib64");

    /* the agent's writable workspace */
    NR("/home/agent"); mmkdir_p(p, 0755);
    bind_mount(C.workdir, p, 0, 0);

    /* extra binds land under /mnt/<basename> */
    NR("/mnt"); mmkdir(p, 0755);
    for (int i = 0; i < C.n_ro; i++) {
        char dst[PATH_MAX];
        snprintf(dst, sizeof dst, "%s/mnt/%s", g_newroot, basename_of(C.ro[i]));
        mmkdir_p(dst, 0755);
        bind_mount(C.ro[i], dst, 1, 1);
    }
    for (int i = 0; i < C.n_rw; i++) {
        char dst[PATH_MAX];
        snprintf(dst, sizeof dst, "%s/mnt/%s", g_newroot, basename_of(C.rw[i]));
        mmkdir_p(dst, 0755);
        bind_mount(C.rw[i], dst, 0, 1);
    }

    /* custom mounts: exact paths inside the sandbox */
    for (int i = 0; i < C.n_binds; i++) {
        char dst[PATH_MAX];
        snprintf(dst, sizeof dst, "%s%s", g_newroot, C.binds[i].dst);
        mmkdir_p(dst, 0755);
        bind_mount(C.binds[i].src, dst, C.binds[i].ro, 1);
    }

    /* scratch space: tmpfs = RAM speed (2.1 GB/s vs 509 MB/s SSD here) */
    NR("/tmp");     mmkdir(p, 01777);  tmpfs_mount(p, "size=1g,mode=1777");
    NR("/var/tmp"); mmkdir_p(p, 01777); tmpfs_mount(p, "size=128m,mode=1777");
    NR("/run");     mmkdir(p, 0755);   tmpfs_mount(p, "size=64m,mode=755");
    /* with host networking, systemd-resolved lives behind /run/systemd —
     * bind it ro so /etc/resolv.conf's symlink and the resolver socket work */
    if (!C.net_none) {
        NR("/run/systemd"); mmkdir(p, 0755);
        /* note: no ro-remount — the mount is owned by the init userns and
         * EPERMs; but real DAC applies (agent uid == our uid on host)    */
        if (mount("/run/systemd", p, NULL, MS_BIND | MS_REC, NULL) < 0)
            warn2("bind /run/systemd (DNS may fail)");
    }

    /* fresh /proc for our PID namespace (the child is PID 1 of it) */
    NR("/proc"); mmkdir(p, 0555);
    if (mount("proc", p, "proc", MS_NOSUID | MS_NODEV, NULL) < 0)
        warn2("mount proc");

    /* /sys + cgroup2: allowed in our own userns, tolerate failure */
    NR("/sys"); mmkdir(p, 0555);
    if (mount("sysfs", p, "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV, NULL) < 0)
        warn2("mount sysfs");
    {
        char q[PATH_MAX];
        snprintf(q, sizeof q, "%s/fs/cgroup", p);
        mmkdir_p(q, 0555);
        if (mount("cgroup2", q, "cgroup2", MS_RDONLY | MS_NOSUID | MS_NODEV,
                  NULL) < 0)
            warn2("mount cgroup2");
    }

    /* minimal /dev: tmpfs + 5 bound device nodes + the usual symlinks */
    NR("/dev"); mmkdir(p, 0755); tmpfs_mount(p, "size=1m,mode=755");
    static const char *devs[] = { "null", "zero", "full", "random", "urandom" };
    for (unsigned i = 0; i < sizeof devs / sizeof *devs; i++) {
        char src[64], dst[PATH_MAX];
        snprintf(src, sizeof src, "/dev/%s", devs[i]);
        snprintf(dst, sizeof dst, "%s/dev/%s", g_newroot, devs[i]);
        int fd = open(dst, O_CREAT | O_EXCL, 0666);   /* reserve the name */
        if (fd >= 0) close(fd);
        if (mount(src, dst, NULL, MS_BIND, NULL) < 0) {
            unlink(dst);
            char msg[128];
            snprintf(msg, sizeof msg, "bind /dev/%s", devs[i]);
            die(msg);
        }
    }
    NR("/dev/fd");     if (symlink("/proc/self/fd",    p) && errno != EEXIST) die("symlink fd");
    NR("/dev/stdin");  if (symlink("/proc/self/fd/0",  p) && errno != EEXIST) die("symlink stdin");
    NR("/dev/stdout"); if (symlink("/proc/self/fd/1",  p) && errno != EEXIST) die("symlink stdout");
    NR("/dev/stderr"); if (symlink("/proc/self/fd/2",  p) && errno != EEXIST) die("symlink stderr");

    /* the hole where the host root lands during pivot_root */
    NR("/.put_old"); mmkdir(p, 0755);
}

/* ------------------------------------------------------------------ */
/* 4. Landlock — path allowlist                                        */
/* ------------------------------------------------------------------ */

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 11)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 16)
#endif

#ifndef SYS_landlock_create_ruleset
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule       445
#define SYS_landlock_restrict_self  446
#endif

static void ll_allow(int ruleset_fd, const char *path, u_int64_t access)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) { warn2(path); return; }
    struct landlock_path_beneath_attr pb = {
        .allowed_access = access,
        .parent_fd = fd,
    };
    if (syscall(SYS_landlock_add_rule, ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
        warn2(path);
    close(fd);
}

static void landlock_apply(void)
{
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0,
                      LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) { warn2("landlock unavailable"); return; }

    u_int64_t ro = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE |
                   LANDLOCK_ACCESS_FS_READ_DIR;
    u_int64_t rw = ro | LANDLOCK_ACCESS_FS_WRITE_FILE |
                   LANDLOCK_ACCESS_FS_REMOVE_DIR  | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                   LANDLOCK_ACCESS_FS_MAKE_CHAR   | LANDLOCK_ACCESS_FS_MAKE_DIR |
                   LANDLOCK_ACCESS_FS_MAKE_REG    | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                   LANDLOCK_ACCESS_FS_MAKE_FIFO   | LANDLOCK_ACCESS_FS_MAKE_SYM |
                   LANDLOCK_ACCESS_FS_MAKE_BLOCK;
    u_int64_t handled = rw;
    if (abi >= 2) { rw |= LANDLOCK_ACCESS_FS_REFER;      handled |= LANDLOCK_ACCESS_FS_REFER; }
    if (abi >= 3) { rw |= LANDLOCK_ACCESS_FS_TRUNCATE;   handled |= LANDLOCK_ACCESS_FS_TRUNCATE; }
    if (abi >= 5) { rw |= LANDLOCK_ACCESS_FS_IOCTL_DEV;  handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV; }

    struct landlock_ruleset_attr attr = { .handled_access_fs = handled };
    int fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0);
    if (fd < 0) { warn2("landlock_create_ruleset"); return; }

    /* read-only OS view (the / rule makes the root listable; writes are
     * still blocked everywhere except where an rw rule applies)          */
    ll_allow(fd, "/",    ro);
    ll_allow(fd, "/usr",  ro);
    ll_allow(fd, "/etc",  ro);
    ll_allow(fd, "/opt",  ro);
    ll_allow(fd, "/proc", ro);
    ll_allow(fd, "/sys",  ro);

    /* writable scratch + workspace */
    ll_allow(fd, "/tmp",        rw);
    ll_allow(fd, "/var/tmp",    rw);
    ll_allow(fd, "/run",        rw);
    ll_allow(fd, "/dev",        rw);
    ll_allow(fd, "/home/agent", rw);

    /* extra binds */
    for (int i = 0; i < C.n_ro; i++) {
        char p[PATH_MAX];
        snprintf(p, sizeof p, "/mnt/%s", basename_of(C.ro[i]));
        ll_allow(fd, p, ro);
    }
    for (int i = 0; i < C.n_rw; i++) {
        char p[PATH_MAX];
        snprintf(p, sizeof p, "/mnt/%s", basename_of(C.rw[i]));
        ll_allow(fd, p, rw);
    }

    /* custom mounts */
    for (int i = 0; i < C.n_binds; i++)
        ll_allow(fd, C.binds[i].dst, C.binds[i].ro ? ro : rw);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("no_new_privs");
    if (syscall(SYS_landlock_restrict_self, fd, 0) < 0)
        warn2("landlock_restrict_self");
    close(fd);
}

/* ------------------------------------------------------------------ */
/* 5. Seccomp — raw BPF deny-list                                      */
/* ------------------------------------------------------------------ */

#define DENY_EPERM (SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
#define DENY_KILL  (SECCOMP_RET_KILL_PROCESS)

/* seccomp_data layout: nr @0 (int), arch @4 (u32), ip @8, args[0] @16 */
#define OFF_NR   0
#define OFF_ARCH 4
#define OFF_ARG0 16

static struct sock_filter g_flt[512];
static int g_n;

static void f_push(struct sock_filter f) { g_flt[g_n++] = f; }

/* deny-list collected here, compiled to a balanced binary-search tree */
static long g_deny[128];
static int  g_ndeny;

static void deny(long nr)
{
    g_deny[g_ndeny++] = nr;
}

static int cmp_long(const void *a, const void *b)
{
    long x = *(const long *)a, y = *(const long *)b;
    return x < y ? -1 : x > y;
}

/*
 * Emit a binary search tree over the sorted deny list. Classic BPF only
 * allows forward jumps, so the layout per node is:
 *
 *   [node]   JGT mid, ->right   (patched below)
 *            JEQ mid, 0, 1      (== mid -> RET below; != -> left subtree)
 *            RET EPERM
 *   [left subtree: values < mid]
 *   [right subtree: values > mid]
 *
 * O(log n) comparisons per syscall instead of a linear JEQ chain.
 */
static void emit_bst(int lo, int hi)
{
    if (lo > hi)
        return;
    int mid = (lo + hi) / 2;
    int node = g_n;

    f_push((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K,
                                        g_deny[mid], 0, 0)); /* jt patched */
    f_push((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                        g_deny[mid], 0, 1));
    f_push((struct sock_filter)BPF_STMT(BPF_RET | BPF_K, DENY_EPERM));

    emit_bst(lo, mid - 1);                    /* values < mid */

    int right = g_n;                          /* right subtree start */
    g_flt[node].jt = right - node - 1;        /* nr > mid -> right */

    emit_bst(mid + 1, hi);                    /* values > mid */
}

/* "syscall does not exist" — makes libc fall back to the old API.
 * Used for clone3: callers retry with clone(2), which we flag-filter. */
static void deny_enosys(long nr)
{
    f_push((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
    f_push((struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)));
}

static void seccomp_apply(void)
{
    /* [0] load arch
     * [1] if arch == AUDIT_ARCH_X86_64 jump over kill
     * [2] kill process (wrong arch → never make it to a syscall)
     * [3] load syscall nr
     */
    f_push((struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    f_push((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                        AUDIT_ARCH_X86_64, 1, 0));
    f_push((struct sock_filter)BPF_STMT(BPF_RET | BPF_K, DENY_KILL));
    f_push((struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    /* clone(2) stays allowed, but never with CLONE_NEWUSER / CLONE_NEWNET:
     *   [k]   if nr != SYS_clone jump +4 (nr register still valid)
     *   [k+1] load args[0] (low 32 bits of clone flags)
     *   [k+2] if flags & mask == 0 jump +1 (flags clean → ok)
     *   [k+3] EPERM
     *   [k+4] reload nr for the deny chain below
     */
    f_push((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 4));
    f_push((struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
    f_push((struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                        CLONE_NEWUSER | CLONE_NEWNET, 0, 1));
    f_push((struct sock_filter)BPF_STMT(BPF_RET | BPF_K, DENY_EPERM));
    f_push((struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, OFF_NR));

    /* kernel / modules / debugging */
    deny(SYS_bpf);                deny(SYS_perf_event_open);
    deny(SYS_init_module);        deny(SYS_finit_module);
    deny(SYS_delete_module);      deny(SYS_kexec_load);
    deny(SYS_kexec_file_load);    deny(SYS_reboot);
    deny(SYS_swapon);             deny(SYS_swapoff);
#ifdef SYS_acpi
    deny(SYS_acpi);
#endif
    /* inspecting / injecting into other processes */
    deny(SYS_ptrace);             deny(SYS_process_vm_readv);
    deny(SYS_process_vm_writev);  deny(SYS_kcmp);
    deny(SYS_pidfd_getfd);        deny(SYS_process_madvise);
#ifdef SYS_process_mrelease
    deny(SYS_process_mrelease);
#endif
    /* namespace / mount escapes */
    deny(SYS_mount);              deny(SYS_umount2);
    deny(SYS_pivot_root);         deny(SYS_unshare);
    deny(SYS_setns);              deny(SYS_open_by_handle_at);
    deny(SYS_name_to_handle_at);
    deny(SYS_fsopen);             deny(SYS_fsconfig);
    deny(SYS_fsmount);            deny(SYS_fspick);
    deny(SYS_move_mount);         deny(SYS_open_tree);
    deny(SYS_mount_setattr);
    /* clone3: ENOSYS so libc falls back to clone(2), which is masked */
    deny_enosys(SYS_clone3);
    /* keyring, time, io_uring and other sharp edges */
    deny(SYS_keyctl);             deny(SYS_add_key);
    deny(SYS_request_key);        deny(SYS_fanotify_init);
    deny(SYS_clock_settime);
#ifdef SYS_clock_settime64
    deny(SYS_clock_settime64);
#endif
    deny(SYS_settimeofday);       deny(SYS_adjtimex);
    deny(SYS_vhangup);            deny(SYS_syslog);
    deny(SYS_ioperm);             deny(SYS_iopl);
    deny(SYS_quotactl);           deny(SYS_quotactl_fd);
    deny(SYS_userfaultfd);        deny(SYS_uselib);
    deny(SYS_lookup_dcookie);
    deny(SYS_io_uring_setup);     deny(SYS_io_uring_enter);
    deny(SYS_io_uring_register);
#ifdef SYS_vm86
    deny(SYS_vm86);               deny(SYS_vm86old);
#endif

    /* deny-list -> sorted balanced BST: O(log n) per syscall */
    qsort(g_deny, g_ndeny, sizeof g_deny[0], cmp_long);
    emit_bst(0, g_ndeny - 1);

    /* everything else is allowed */
    f_push((struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog prog = { .len = (unsigned short)g_n, .filter = g_flt };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("no_new_privs");
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_LOG, &prog) < 0)
        die("seccomp install");
}

/* ------------------------------------------------------------------ */
/* bring loopback up inside an empty netns                             */
/* ------------------------------------------------------------------ */

static void net_lo_up(void)
{
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return;
    memset(&ifr, 0, sizeof ifr);
    strcpy(ifr.ifr_name, "lo");
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0 && !(ifr.ifr_flags & IFF_UP)) {
        ifr.ifr_flags |= IFF_UP;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) warn2("ifup lo");
    }
    close(s);
}

/* ------------------------------------------------------------------ */
/* long-running mode: the jail stays alive, commands stream in over a  */
/* unix socket. Connection fds are passed across the namespace with   */
/* SCM_RIGHTS, so data flows client <-> jailed command directly.      */
/* wire format (little endian):                                        */
/*   request:  u32 argc { u32 len, bytes }*argc  u32 stdin_len bytes   */
/*   response: raw stdout/stderr, then u32 exit status, then EOF      */
/* ------------------------------------------------------------------ */

static void put_u32(char *b, uint32_t v)
{
    b[0] = v; b[1] = v >> 8; b[2] = v >> 16; b[3] = v >> 24;
}

static uint32_t get_u32(const char *b)
{
    return (uint8_t)b[0] | ((uint8_t)b[1] << 8) |
           ((uint8_t)b[2] << 16) | ((uint32_t)(uint8_t)b[3] << 24);
}

static int read_full(int fd, void *buf, size_t n)
{
    char *p = buf;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const char *p = buf;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r <= 0) return -1;
        p += r; n -= r;
    }
    return 0;
}

/* the jail side: run one command with its stdio on the client socket */
static void handle_conn(int conn)
{
    enum { MAXARGS = 256 };
    char *argv[MAXARGS + 1] = {0};
    uint32_t argc;

    if (read_full(conn, &argc, 4) || argc == 0 || argc > MAXARGS)
        goto out;

    for (uint32_t i = 0; i < argc; i++) {
        uint32_t len;
        if (read_full(conn, &len, 4) || len == 0 || len > 65536)
            goto out;
        argv[i] = malloc(len + 1);
        if (!argv[i] || read_full(conn, argv[i], len))
            goto out;
        argv[i][len] = 0;
    }

    /* optional stdin blob -> memfd (allowed: memfd_create isn't denied) */
    uint32_t slen;
    int in_fd = open("/dev/null", O_RDONLY);
    if (!read_full(conn, &slen, 4) && slen) {
        in_fd = syscall(SYS_memfd_create, "stdin", 0);
        char buf[65536];
        while (slen) {
            size_t chunk = slen > sizeof buf ? sizeof buf : slen;
            if (read_full(conn, buf, chunk)) break;
            if (write_full(in_fd, buf, chunk)) break;
            slen -= chunk;
        }
        lseek(in_fd, 0, SEEK_SET);
    }

    pid_t p = fork();
    if (p == 0) {
        dup2(in_fd, 0);
        dup2(conn, 1);
        dup2(conn, 2);
        for (int fd = 3; fd < 64; fd++) close(fd);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(in_fd);

    int st = 0;
    waitpid(p, &st, 0);
    uint32_t code = WIFEXITED(st) ? (uint32_t)WEXITSTATUS(st)
                  : WIFSIGNALED(st) ? 128u + (uint32_t)WTERMSIG(st) : 1;
    write_full(conn, &(uint32_t){0}, 0);   /* no-op keeps gcc quiet */
    put_u32((char *)&code, code);
    write_full(conn, &code, 4);

out:
    for (uint32_t i = 0; argv[i]; i++) free(argv[i]);
    close(conn);
}

/* the jail side: receive client fds from the supervisor, forever */
static void jail_server(int fd)
{
    for (;;) {
        char cmd;
        char cbuf[CMSG_SPACE(sizeof(int))];
        struct iovec iov = { .iov_base = &cmd, .iov_len = 1 };
        struct msghdr msg = {0};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf;
        msg.msg_controllen = sizeof cbuf;

        ssize_t r = recvmsg(fd, &msg, 0);
        if (r <= 0)
            break;                       /* supervisor gone -> die */
        struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
        if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
            continue;
        handle_conn(*(int *)CMSG_DATA(c));
    }
    _exit(0);
}

/* supervisor: hand one client connection into the jail */
static void send_fd(int sock, int fd)
{
    char b = 'E';
    char cbuf[CMSG_SPACE(sizeof(int))];
    struct iovec iov = { .iov_base = &b, .iov_len = 1 };
    struct msghdr msg = {0};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof cbuf;
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(c) = fd;
    sendmsg(sock, &msg, 0);
}

/* supervisor: accept on the host socket until the jail dies */
static volatile sig_atomic_t g_stop;

static void on_stop(int sig) { (void)sig; g_stop = 1; }

static void serve_loop(pid_t jail)
{
    close(g_jail_sock);
    signal(SIGINT, on_stop);
    signal(SIGTERM, on_stop);

    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    const char *rt = getenv("XDG_RUNTIME_DIR");
    if (!rt) rt = "/tmp";
    snprintf(g_sock_path, sizeof g_sock_path, "%s/agentcell-%d.sock", rt,
             (int)jail);
    unlink(g_sock_path);
    snprintf(a.sun_path, sizeof a.sun_path, "%s", g_sock_path);
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) +
                     strlen(a.sun_path) + 1;
    if (bind(lfd, (struct sockaddr *)&a, alen) < 0 ||
        listen(lfd, 16) < 0)
        die("listen socket");
    chmod(g_sock_path, 0600);

    snprintf(g_info_path, sizeof g_info_path, "%s.info", g_sock_path);
    write_info(jail);

    fprintf(stderr, "sand: serving %s  (jail pid %d, Ctrl-C to stop)\n",
            g_sock_path, jail);

    for (;;) {
        if (g_stop) break;
        struct pollfd pf[2] = {
            { .fd = lfd,         .events = POLLIN },
            { .fd = g_host_sock, .events = POLLIN },
        };
        if (poll(pf, 2, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        /* jail closed its end? */
        if (pf[1].revents) {
            char b;
            if (recv(g_host_sock, &b, 1, MSG_PEEK | MSG_DONTWAIT) <= 0)
                break;
        }
        if (pf[0].revents & POLLIN) {
            int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0) {
                send_fd(g_host_sock, c);
                close(c);
                g_execs++;
                write_info(jail);
            }
        }
        int st;
        if (waitpid(jail, &st, WNOHANG) == jail)
            break;
    }

    kill(jail, SIGKILL);
    waitpid(jail, NULL, 0);
    lsm_unregister();
    unlink(g_sock_path);
    unlink(g_info_path);
    fprintf(stderr, "sand: jail stopped\n");
}

/* host client: sand exec SOCK [--] CMD ARGS... */
static int client_exec(char **av)
{
    /* av = [SOCK, ("--"), CMD, ARGS...] */
    if (!av[0] || !av[1]) {
        fprintf(stderr, "usage: sand exec SOCK [--] CMD ARGS...\n");
        return 2;
    }
    char *sock = av[0];
    char **args = av + 1;
    if (!strcmp(args[0], "--")) {
        if (!args[1]) { fprintf(stderr, "sand: no command after --\n"); return 2; }
        args++;
    }

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", sock);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
        fprintf(stderr, "sand: connect %s: %s\n", av[0], strerror(errno));
        return 2;
    }

    /* build request: argc + args + stdin blob */
    size_t cap = 1 << 16, len = 0;
    char *req = malloc(cap);
    if (!req) return 2;
    uint32_t argc = 0;
    for (char **p = args; *p; p++) argc++;

    #define APPEND(ptr, n) do { \
        if (len + (n) > cap) { \
            while (len + (n) > cap) cap <<= 1; \
            req = realloc(req, cap); \
            if (!req) return 2; \
        } \
        memcpy(req + len, ptr, (n)); len += (n); \
    } while (0)

    char b4[4];
    put_u32(b4, argc);
    APPEND(b4, 4);
    for (char **p = args; *p; p++) {
        put_u32(b4, strlen(*p));
        APPEND(b4, 4);
        APPEND(*p, strlen(*p));
    }

    /* stdin: pipe it in whole (up to 64M); tty stdin is skipped */
    size_t in_len = 0;
    char *in_buf = NULL;
    if (!isatty(0)) {
        size_t icap = 1 << 16;
        in_buf = malloc(icap);
        for (;;) {
            if (in_len == icap) {
                icap <<= 1;
                in_buf = realloc(in_buf, icap);
                if (!in_buf) return 2;
            }
            ssize_t r = read(0, in_buf + in_len, icap - in_len);
            if (r <= 0 || in_len > (64u << 20)) break;
            in_len += r;
        }
    }
    put_u32(b4, in_len);
    APPEND(b4, 4);
    if (in_len) APPEND(in_buf, in_len);

    if (write_full(s, req, len)) { fprintf(stderr, "sand: send failed\n"); return 2; }
    shutdown(s, SHUT_WR);

    /* stream the reply; last 4 bytes are the exit status */
    cap = 1 << 16; len = 0;
    char *rep = malloc(cap);
    for (;;) {
        if (len == cap) {
            cap <<= 1;
            rep = realloc(rep, cap);
            if (!rep) return 2;
        }
        ssize_t r = read(s, rep + len, cap - len);
        if (r <= 0) break;
        len += r;
    }
    if (len < 4) { fprintf(stderr, "sand: protocol error\n"); return 2; }
    fwrite(rep, 1, len - 4, stdout);
    fflush(stdout);
    return (int)get_u32(rep + len - 4);
}

/* ------------------------------------------------------------------ */
/* agentlsm integration: sand --secure registers this cell's cgroup   */
/* with the root daemon (sudo agentlsm serve) over /run/agentcell/.   */
/* Denials happen in-kernel at the LSM layer; events stream back to   */
/* whoever WATCHes the daemon (sand lsm -f).                          */
/* ------------------------------------------------------------------ */

#define LSM_SOCK "/run/agentcell/lsm.sock"

static int lsm_connect(void)
{
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", LSM_SOCK);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) {
        close(s);
        return -1;
    }
    return s;
}

/* send one command line, read the one-line reply ("OK"/"ERR..."/"END")
 * — always read it, even if the caller doesn't care: closing first
 * would turn the daemon's reply write into SIGPIPE/EPIPE */
static int lsm_cmd(const char *cmd, char *rep, size_t repn)
{
    int s = lsm_connect();
    if (s < 0) return -1;
    char line[320], scratch[64];
    snprintf(line, sizeof line, "%s\n", cmd);
    if (write_full(s, line, strlen(line)) < 0) { close(s); return -1; }
    if (!rep) { rep = scratch; repn = sizeof scratch; }
    ssize_t r = read(s, rep, repn - 1);
    if (r > 0) rep[r] = 0;
    close(s);
    return r > 0 ? 0 : -1;
}

/* arm this cell's policy at the daemon; called after cgroup park */
static void lsm_register(void)
{
    struct stat st;
    if (stat(g_cgpath, &st) < 0) return;
    g_lsm_cgid = (__u64)st.st_ino;

    /* defaults keep secrets of the host out of agent reach; note the
     * prefixes are paths AS SEEN INSIDE the cell (that's what d_path
     * yields for its bind mounts) */
    const char *def[2] = { "/etc/shadow", "/etc/gshadow" };
    int n = C.n_deny ? C.n_deny : 2;

    int s = lsm_connect();
    if (s < 0) {
        fprintf(stderr, "sand: --secure: agentlsm daemon not running "
                        "(sudo agentlsm serve) — LSM enforcement OFF\n");
        return;
    }

    int ok = 0;
    for (int i = 0; i < n; i++) {
        const char *pfx = C.n_deny ? C.deny[i] : def[i];
        char cmd[320], rep[64];
        snprintf(cmd, sizeof cmd, "ADD %llu %s",
                 (unsigned long long)g_lsm_cgid, pfx);
        if (write_full(s, cmd, strlen(cmd)) || write_full(s, "\n", 1) ||
            read(s, rep, sizeof rep - 1) <= 0 || strncmp(rep, "OK", 2))
            { close(s); fprintf(stderr, "sand: agentlsm ADD failed\n"); return; }
        ok++;
    }
    close(s);
    g_lsm_on = 1;
    fprintf(stderr, "sand: LSM armed: %d deny prefix%s via agentlsm "
                    "(cgid %llu)\n", ok, ok == 1 ? "" : "es",
                    (unsigned long long)g_lsm_cgid);
}

static void lsm_unregister(void)
{
    if (!g_lsm_on) return;
    g_lsm_on = 0;
    char cmd[64];
    snprintf(cmd, sizeof cmd, "CLR %llu", (unsigned long long)g_lsm_cgid);
    lsm_cmd(cmd, NULL, 0);
}

/* cgid -> cell-name table built from the *.info sidecars */
struct cellname { __u64 cgid; char name[64]; };

static int build_cell_table(struct cellname *cells, int max)
{
    int ncells = 0;
    const char *rt = getenv("XDG_RUNTIME_DIR");
    if (!rt) rt = "/tmp";
    DIR *d = opendir(rt);
    if (!d) return 0;
    struct dirent *e;
    while ((e = readdir(d)) && ncells < max) {
        size_t nlen = strlen(e->d_name);
        if (nlen < 5 || strcmp(e->d_name + nlen - 5, ".sock") ||
            strncmp(e->d_name, "agentcell-", 10))
            continue;
        char base[PATH_MAX], cg[PATH_MAX] = "", line[256];
        snprintf(base, sizeof base, "%s/%s.info", rt, e->d_name);
        FILE *f = fopen(base, "r");
        if (!f) continue;
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, "cg=", 3)) {
                line[strcspn(line, "\n")] = 0;
                snprintf(cg, sizeof cg, "%s", line + 3);
                break;
            }
        fclose(f);
        struct stat st;
        if (cg[0] && !stat(cg, &st)) {
            cells[ncells].cgid = (__u64)st.st_ino;
            snprintf(cells[ncells].name, 64, "%s", e->d_name);
            ncells++;
        }
    }
    closedir(d);
    return ncells;
}

static const char *cell_of(const struct cellname *cells, int n, __u64 cgid)
{
    for (int i = 0; i < n; i++)
        if (cells[i].cgid == cgid) return cells[i].name;
    return "?";
}

/* resolve a user-supplied cell selector — sock path, sock basename,
 * unique name prefix, or a raw cgid (all digits) — to a cgroup id */
static int resolve_target(const char *sel, const struct cellname *cells,
                          int ncells, __u64 *cgid, char *nameout, size_t nn)
{
    int alldigit = 1;
    for (const char *p = sel; *p; p++)
        if (!isdigit((unsigned char)*p)) { alldigit = 0; break; }
    if (alldigit) {
        *cgid = strtoull(sel, NULL, 10);
        snprintf(nameout, nn, "%s", cell_of(cells, ncells, *cgid));
        return 0;
    }
    const char *base = strrchr(sel, '/');
    base = base ? base + 1 : sel;
    int hit = -1, hits = 0;
    for (int i = 0; i < ncells; i++) {
        if (!strcmp(cells[i].name, base) ||
            !strncmp(cells[i].name, base, strlen(base)))
            { hit = i; hits++; }
    }
    if (hits == 1) {
        *cgid = cells[hit].cgid;
        snprintf(nameout, nn, "%s", cells[hit].name);
        return 0;
    }
    return -1;
}

/* sand lsm deny|allow|reset CELL PREFIX... — hot policy updates for a
 * running cell. "deny" also works on cells started WITHOUT --secure:
 * registering the cgroup id with the daemon is all it takes. */
static int lsm_ctl_cmd(char *sub, char **av)
{
    if (!av[0] || (strcmp(sub, "reset") && !av[1])) {
        fprintf(stderr, "usage: sand lsm %s CELL %s\n", sub,
                !strcmp(sub, "reset") ? "" : "PREFIX...");
        return 2;
    }
    struct cellname cells[MAXBIND];
    int ncells = build_cell_table(cells, MAXBIND);
    __u64 cgid;
    char name[64];
    if (resolve_target(av[0], cells, ncells, &cgid, name, sizeof name) < 0) {
        fprintf(stderr, "sand: cannot resolve cell '%s'", av[0]);
        if (ncells)
            fprintf(stderr, " — running cells:");
        fprintf(stderr, "\n");
        for (int i = 0; i < ncells; i++)
            fprintf(stderr, "  %s\n", cells[i].name);
        return 1;
    }

    char cmd[320], rep[64];
    int rc = 0, n = 0;

    if (!strcmp(sub, "reset")) {
        snprintf(cmd, sizeof cmd, "CLR %llu", (unsigned long long)cgid);
        if (lsm_cmd(cmd, rep, sizeof rep) < 0 || strncmp(rep, "OK", 2)) {
            fprintf(stderr, "sand: agentlsm reset failed%s%s\n",
                    rep[0] ? ": " : "", rep);
            return 1;
        }
        printf("%s reset (all rules) — effective immediately\n", name);
        return 0;
    }

    for (char **p = &av[1]; *p; p++) {
        snprintf(cmd, sizeof cmd, "%s %llu %s",
                 !strcmp(sub, "deny") ? "ADD" : "DEL",
                 (unsigned long long)cgid, *p);
        if (lsm_cmd(cmd, rep, sizeof rep) < 0 || strncmp(rep, "OK", 2)) {
            fprintf(stderr, "sand: agentlsm %s %s failed%s%s\n", sub, *p,
                    rep[0] ? ": " : "", rep);
            rc = 1;
        } else {
            n++;
            printf("%s %s %s — effective immediately\n", name, sub, *p);
        }
    }
    (void)n;
    return rc;
}

/* sand lsm [-f]: enforcement status, and live denial events.
 * cgroup ids are resolved to cell names via the *.info sidecars. */
static int lsm_status(char **av)
{
    setvbuf(stdout, NULL, _IOLBF, 0);   /* live events, flush per line */
    if (av[0] && (!strcmp(av[0], "deny") || !strcmp(av[0], "allow") ||
                  !strcmp(av[0], "reset")))
        return lsm_ctl_cmd(av[0], av + 1);
    int follow = av[0] && (!strcmp(av[0], "-f") || !strcmp(av[0], "--follow"));

    struct cellname cells[MAXBIND];
    int ncells = build_cell_table(cells, MAXBIND);

    /* LIST: armed policies */
    int s = lsm_connect();
    if (s < 0) {
        fprintf(stderr, "sand: agentlsm daemon not running "
                        "(start it: sudo agentlsm serve)\n");
        return 1;
    }
    write_full(s, "LIST\n", 5);
    char lrep[320];
    ssize_t r;
    printf("%-10s %-26s %s\n", "CGID", "CELL", "DENY PREFIX");
    while ((r = read(s, lrep, sizeof lrep - 1)) > 0) {
        lrep[r] = 0;
        char *p = lrep, *nl;
        while ((nl = strchr(p, '\n'))) {
            *nl = 0;
            unsigned long long cgid;
            char pfx[256];
            if (!strncmp(p, "END", 3)) goto listed;
            if (sscanf(p, "%llu %255s", &cgid, pfx) == 2)
                printf("%-10llu %-26s %s\n", cgid,
                       cell_of(cells, ncells, cgid), pfx);
            p = nl + 1;
        }
    }
listed:
    if (!follow) { close(s); return 0; }

    /* WATCH: stream denial events, resolving cgid -> cell */
    printf("-- following LSM denials (Ctrl-C to stop) --\n");
    write_full(s, "WATCH\n", 6);
    for (;;) {
        ssize_t n = read(s, lrep, sizeof lrep - 1);
        if (n <= 0) break;
        lrep[n] = 0;
        char *p = lrep, *nl;
        while ((nl = strchr(p, '\n'))) {
            *nl = 0;
            unsigned long long cgid;
            char path[256];
            if (sscanf(p, "EV %llu %255s", &cgid, path) == 2)
                printf("%s  DENY %s\n", cell_of(cells, ncells, cgid), path);
            p = nl + 1;
        }
    }
    close(s);
    return 0;
}

/* ------------------------------------------------------------------ */
/* child: future PID 1 of the sandbox                                  */
/* ------------------------------------------------------------------ */

static int child_main(void *arg)
{
    (void)arg;

    /* die with the supervisor */
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);

    /* wait until parent wrote our uid_map / gid_map AND parked us in the
     * sandbox cgroup (must happen while we still share its cgroup view)  */
    char b;
    if (read(g_sync[0], &b, 1) != 1) _exit(126);

    /* now adopt a private cgroup view rooted at the sandbox cgroup */
    if (unshare(CLONE_NEWCGROUP) < 0) warn2("cgroup namespace");

    do_mounts();

    /* swap roots — the host filesystem disappears entirely */
    if (chdir(g_newroot) < 0) die("chdir newroot");
    if (syscall(SYS_pivot_root, ".", ".put_old") < 0) die("pivot_root");
    if (chdir("/") < 0) die("chdir /");
    umount2("/.put_old", MNT_DETACH);
    rmdir("/.put_old");

    /* root tmpfs itself becomes read-only; submounts keep their own perms */
    if (mount(NULL, "/", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0)
        warn2("remount / ro");

    if (!C.no_landlock) landlock_apply();
    if (!C.no_seccomp)  seccomp_apply();
    if (C.net_none)     net_lo_up();

    if (chdir("/home/agent") < 0) warn2("chdir workdir");

    clearenv();
    setenv("HOME",   "/home/agent", 1);
    setenv("PATH",   "/usr/bin:/bin", 1);
    setenv("TMPDIR", "/tmp", 1);
    setenv("SHELL",  "/bin/bash", 1);
    setenv("LANG",   "C.UTF-8", 1);
    setenv("TERM",   "xterm-256color", 1);

    if (g_serve) {
        close(g_host_sock);
        jail_server(g_jail_sock);      /* never returns */
    }

    char *def[] = { "/bin/bash", NULL };
    char **av = C.argv ? (char **)C.argv : def;
    execvp(av[0], av);
    die("execvp");
    return 1;
}

/* ------------------------------------------------------------------ */
/* parent: clone + write uid maps + cgroup + wait                      */
/* ------------------------------------------------------------------ */

static long parse_mem(const char *s)
{
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s) die("bad --mem value");
    switch (*end) {
    case 'G': case 'g': v <<= 30; break;
    case 'M': case 'm': v <<= 20; break;
    case 'K': case 'k': v <<= 10; break;
    case '\0': break;
    default: die("bad --mem suffix");
    }
    return v;
}

static void write_uid_maps(pid_t pid)
{
    char path[128], buf[128];
    int fd;

    snprintf(path, sizeof path, "/proc/%d/setgroups", pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) { if (write(fd, "deny", 4) < 0) warn2("setgroups"); close(fd); }

    snprintf(path, sizeof path, "/proc/%d/uid_map", pid);
    snprintf(buf, sizeof buf, "0 %d 1\n", g_uid);
    fd = open(path, O_WRONLY);
    if (fd < 0) die("open uid_map");
    if (write(fd, buf, strlen(buf)) < 0) die("write uid_map");
    close(fd);

    snprintf(path, sizeof path, "/proc/%d/gid_map", pid);
    snprintf(buf, sizeof buf, "0 %d 1\n", g_gid);
    fd = open(path, O_WRONLY);
    if (fd < 0) die("open gid_map");
    if (write(fd, buf, strlen(buf)) < 0) die("write gid_map");
    close(fd);
}

static void usage(FILE *out)
{
    fprintf(out,
"usage: sand [options] -- CMD [ARGS...]\n"
"\n"
"options:\n"
"  --mem SIZE    memory.max  (512M, 2G, bytes; default 2G)\n"
"  --cpu N       cpu.max quota in cores (0.5, 2; default 2)\n"
"  --pids N      pids.max    (default 256)\n"
"  --net MODE    none | host (default none — loopback only, no routes)\n"
"  --workdir DIR writable workspace (default ~/agent-work)\n"
"  --ro DIR      extra read-only bind (repeatable, lands in /mnt/NAME)\n"
"  --rw DIR      extra read-write bind (repeatable, lands in /mnt/NAME)\n"
"  --bind S:D    mount host path S at path D inside the sandbox (rw)\n"
"  --bind-ro S:D same, but read-only\n"
"  --timeout S   kill payload after S seconds\n"
"  --secure      arm kernel LSM policy via the agentlsm daemon\n"
"                (deny /etc/shadow & /etc/gshadow by default)\n"
"  --deny PREFIX extra LSM deny prefix (repeatable, implies --secure;\n"
"                paths as seen INSIDE the sandbox, e.g. /mnt/NAME)\n"
"  --no-landlock | --no-seccomp   debug switches\n"
"\n"
"long-running mode (isolation set up once, then reused):\n"
"  sand serve [options]       start a jailed exec server, prints SOCK\n"
"  sand exec SOCK [--] CMD..  run CMD inside that jail\n"
"  sand cells | sand top      list running cells / live view\n"
"  sand lsm [-f]              LSM policies, live denials (needs agentlsm)\n"
"  sand lsm deny CELL PREFIX..  hot-add deny rule to a RUNNING cell\n"
"  sand lsm allow CELL PREFIX..  hot-remove; reset CELL: drop all rules\n");
}

int main(int argc, char **argv)
{
    g_uid = getuid();
    g_gid = getgid();

    /* subcommands */
    if (argc > 1 && !strcmp(argv[1], "exec"))
        return client_exec(argv + 2);
    if (argc > 1 && !strcmp(argv[1], "cells"))
        return list_cells();
    if (argc > 1 && !strcmp(argv[1], "top"))
        return top_cells(argv[2]);
    if (argc > 1 && !strcmp(argv[1], "lsm"))
        return lsm_status(argv + 2);
    if (argc > 1 && !strcmp(argv[1], "serve")) {
        g_serve = 1;
        argv++;
        argc--;
    }

    /* default memory limit = 60% of RAM (avoids reclaim storms; --mem wins) */
    {
        FILE *f = fopen("/proc/meminfo", "r");
        char k[64]; long v;
        while (f && fscanf(f, "%63s %ld kB", k, &v) == 2)
            if (!strcmp(k, "MemTotal:")) {
                C.mem_bytes = (long)((double)v * 1024 * 0.6);
                break;
            }
        if (f) fclose(f);
    }

    static struct option opts[] = {
        {"mem",         required_argument, 0, 'm'},
        {"cpu",         required_argument, 0, 'c'},
        {"pids",        required_argument, 0, 'P'},
        {"net",         required_argument, 0, 'n'},
        {"workdir",     required_argument, 0, 'w'},
        {"ro",          required_argument, 0, 'r'},
        {"rw",          required_argument, 0, 'W'},
        {"bind",        required_argument, 0, 'b'},
        {"bind-ro",     required_argument, 0, 'B'},
        {"timeout",     required_argument, 0, 't'},
        {"secure",      no_argument, &C.secure, 1},
        {"deny",        required_argument, 0, 'd'},
        {"no-landlock", no_argument, &C.no_landlock, 1},
        {"no-seccomp",  no_argument, &C.no_seccomp, 1},
        {"help",        no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };
    int o;
    while ((o = getopt_long(argc, argv, "+", opts, 0)) != -1) {
        switch (o) {
        case 'm': C.mem_bytes = parse_mem(optarg); break;
        case 'c': {
            double q = atof(optarg);
            if (q <= 0)
                snprintf(C.cpu_max, sizeof C.cpu_max, "max 100000");
            else
                snprintf(C.cpu_max, sizeof C.cpu_max, "%ld 100000",
                         (long)(q * 100000));
            break;
        }
        case 'P': C.pids = atoi(optarg); break;
        case 'n':
            if (!strcmp(optarg, "host")) C.net_none = 0;
            else if (strcmp(optarg, "none")) { usage(stderr); return 2; }
            break;
        case 'w':
            if (!realpath(optarg, C.workdir)) die(optarg);
            break;
        case 'r': if (C.n_ro < MAXBIND) C.ro[C.n_ro++] = optarg; break;
        case 'W': if (C.n_rw < MAXBIND) C.rw[C.n_rw++] = optarg; break;
        case 'b': case 'B': {
            if (C.n_binds >= MAXBIND) break;
            char *colon = strchr(optarg, ':');
            if (!colon || colon == optarg || colon[1] != '/') {
                fprintf(stderr, "sand: --bind needs SRC:DST (DST absolute)\n");
                return 2;
            }
            *colon = 0;
            struct bind *b = &C.binds[C.n_binds];
            if (!realpath(optarg, b->src)) die(optarg);
            snprintf(b->dst, sizeof b->dst, "%s", colon + 1);
            for (char *e = b->dst + strlen(b->dst) - 1;
                 e > b->dst && *e == '/'; e--) *e = 0;
            b->ro = (o == 'B');
            C.n_binds++;
            break;
        }
        case 't': C.timeout = atoi(optarg); break;
        case 'd':
            if (C.n_deny < MAXBIND) {
                snprintf(C.deny[C.n_deny], 256, "%s", optarg);
                C.n_deny++;
            }
            C.secure = 1;               /* --deny implies --secure */
            break;
        case 'h': usage(stdout); return 0;
        case 0: break;
        default: usage(stderr); return 2;
        }
    }
    if (optind < argc) C.argv = (char *const *)&argv[optind];

    /* default workspace */
    if (!C.workdir[0]) {
        char def[PATH_MAX];
        snprintf(def, sizeof def, "%s/agent-work", getenv("HOME") ?: "/tmp");
        mmkdir_p(def, 0755);
        if (!realpath(def, C.workdir)) die(def);
    }

    /* resolve extra binds to absolute paths now (host paths vanish later) */
    for (int i = 0; i < C.n_ro; i++) {
        char *r = realpath(C.ro[i], NULL);
        if (!r) die(C.ro[i]);
        C.ro[i] = r;
    }
    for (int i = 0; i < C.n_rw; i++) {
        char *r = realpath(C.rw[i], NULL);
        if (!r) die(C.rw[i]);
        C.rw[i] = r;
    }

    if (!mkdtemp(g_newroot)) die("mkdtemp");

    cgroup_setup();

    if (pipe(g_sync) < 0) die("pipe");

    if (g_serve) {
        int sp[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) < 0)
            die("socketpair");
        g_host_sock = sp[0];
        g_jail_sock = sp[1];
    }

    const int ns = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC |
                   CLONE_NEWUTS |
                   (C.net_none ? CLONE_NEWNET : 0);

    const size_t SZ = 1 << 20;
    char *stack = malloc(SZ);
    if (!stack) die("malloc");

    pid_t pid = clone(child_main, stack + SZ, ns | SIGCHLD, NULL);
    if (pid < 0) die("clone (userns disabled? sysctl kernel.unprivileged_userns_clone)");

    close(g_sync[0]);

    /* give the child its identity: uid 0 inside == uid 1000 outside */
    write_uid_maps(pid);

    /* park the whole payload in its own cgroup — must happen while the
     * child still shares our cgroup view, before it unshares its own   */
    if (g_have_cg) {
        char p[PATH_MAX], v[32];
        snprintf(p, sizeof p, "%s/cgroup.procs", g_cgpath);
        snprintf(v, sizeof v, "%d", pid);
        write_file(p, v);
        fprintf(stderr, "sand: pid %d  cgroup %s\n", pid, g_cgpath);
    }

    if (C.secure && g_have_cg)
        lsm_register();

    if (write(g_sync[1], "x", 1) < 0) warn2("sync child");

    if (g_serve)
        serve_loop(pid);         /* reaps the jail, cleans socket+cgroup */

    /* survive terminal Ctrl-C so we can reap the child and clean up */
    signal(SIGINT,  SIG_IGN);
    signal(SIGTERM, SIG_IGN);

    int status = 0;
    if (C.timeout > 0) {
        int left = C.timeout;
        while (waitpid(pid, &status, WNOHANG) == 0) {
            if (left-- <= 0) { kill(pid, SIGKILL); break; }
            sleep(1);
        }
        waitpid(pid, &status, 0);
    } else {
        waitpid(pid, &status, 0);
    }

    if (g_have_cg) rmdir(g_cgpath);
    lsm_unregister();
    rmdir(g_newroot);

    if (WIFEXITED(status))
        fprintf(stderr, "sand: exited %d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(stderr, "sand: killed by signal %d\n", WTERMSIG(status));
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
