// SPDX-License-Identifier: GPL-2.0
/*
 * agentlsm.c — loader/daemon for the AgentCell BPF LSM enforcement.
 *
 * One-shot modes (debugging / bisect):
 *   sudo ./agentlsm --cgroup PATH [--deny PREFIX]... [--audit]
 *   sudo ./agentlsm --any-cgroup [--deny PREFIX]...
 *   sudo ./agentlsm --block-all SECONDS [--cgroup PATH]
 *                     deny every open — scoped to PATH's cgroup when
 *                     given, system-wide otherwise (DANGER: EPERMs
 *                     every process, incl. your shell/agent harness)
 *
 * Daemon mode (the real thing):
 *   sudo ./agentlsm serve
 *
 *     Attaches lsm/file_open once and manages per-cell policies for
 *     many sandbox cgroups over a control socket, so unprivileged
 *     `sand --secure` can register its cell without any root helper
 *     per launch.  Protocol (one request per line, replies OK/ERR/END):
 *
 *       ADD <cgid> <prefix>    arm one deny rule for that cgroup id
 *       DEL <cgid> <prefix>    drop one rule
 *       CLR <cgid>             cell died: drop all its rules
 *       LIST                   "cgid prefix" lines, then END
 *       WATCH [classes]        from now on: "EV <cgid> <CLASS> <text>"
 *                              lines; classes: deny,exec,open,net,trip
 *                              (comma-separated, default all)
 *
 *     Denials are enforced (-EPERM) AND reported to watchers.  The
 *     daemon also carries agentmon's tracepoint probes (exec / open /
 *     connect) plus a raw_syscalls/sys_exit probe for TRIP events —
 *     seccomp-denied syscalls never reach the entry tracepoints, but
 *     their -EPERM return is visible on the exit path.  One watcher
 *     stream for everything.
 *
 * Socket: /run/agentcell/lsm.sock (0666 — single-user trust model for
 * now: anyone local may register policy; document before sharing).
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* bpf_elf[] and bpf_elf_len come from the -include'd xxd header */

#define PLEN        64
#define ACT_DENY    2
#define LSM_SOCK    "/run/agentcell/lsm.sock"
#define MAX_WATCH   64

static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

/* event classes — keep in sync with agentlsm.bpf.c */
#define EV_DENY    1
#define EV_EXEC    2
#define EV_OPEN    3
#define EV_CONNECT 4
#define EV_TRIP    5

struct evt {
    __u64 cgid;
    __u32 tgid;
    __u32 type;
    __u32 nr;
    char  comm[16];
    char  path[192];
};

static const char *attempt_name(unsigned nr)
{
    switch (nr) {
    case 165: return "mount";
    case 166: return "umount2";
    case 155: return "pivot_root";
    case 272: return "unshare";
    case 308: return "setns";
    case 435: return "clone3";
    case 321: return "bpf";
    case 298: return "perf_event_open";
    case 101: return "ptrace";
    case 250: return "keyctl";
    case 175: return "init_module";
    case 176: return "delete_module";
    case 323: return "userfaultfd";
    case 425: return "io_uring_setup";
    case 430: return "fsopen";          /* new mount API */
    case 431: return "fsconfig";
    case 432: return "fsmount";
    case 433: return "fspick";
    case 429: return "move_mount";
    case 428: return "open_tree";
    case 442: return "mount_setattr";
    case 202: return "ioperm";
    case 110: return "iopl";
    default:  return "?";
    }
}

/* ---- shared bpf state ------------------------------------------------ */

static struct bpf_object *g_obj;
static int g_fd_policy, g_fd_cells, g_fd_cellpol, g_fd_events;

static int bpf_load_attach(__u64 target_cgid, int enforce,
                           __u64 block_until_ns, __u64 block_cgid, int mode)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct bpf_object *obj = bpf_object__open_mem(bpf_elf, bpf_elf_len, NULL);
    if (!obj) { fprintf(stderr, "agentlsm: open failed\n"); return -1; }

    /* rodata layout: target_cgid@0, enforce@8, mode@12,
     * block_until@16, block_cgid@24 */
    struct {
        __u64 target_cgid;
        int  enforce;
        int  mode;
        __u64 block_until_ns;
        __u64 block_cgid;
    } __attribute__((packed)) cfg = { target_cgid, enforce, mode,
                                      block_until_ns, block_cgid };

    struct bpf_map *ro = bpf_object__find_map_by_name(obj, ".rodata");
    if (!ro || bpf_map__set_initial_value(ro, &cfg, sizeof cfg)) {
        fprintf(stderr, "agentlsm: cannot set config\n"); return -1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "agentlsm: load failed: %s\n", strerror(errno));
        return -1;
    }

    /* attach every program in the object: the lsm/file_open hook plus
     * the tracepoint probes (exec/open/connect/escape-attempts) */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            fprintf(stderr, "agentlsm: attach %s failed: %s\n"
                            "  (is 'bpf' in /sys/kernel/security/lsm?)\n",
                    bpf_program__name(prog), strerror(errno));
            return -1;
        }
    }

    g_obj        = obj;
    g_fd_policy  = bpf_object__find_map_fd_by_name(obj, "policy");
    g_fd_cells   = bpf_object__find_map_fd_by_name(obj, "cells");
    g_fd_cellpol = bpf_object__find_map_fd_by_name(obj, "cellpol");
    g_fd_events  = bpf_object__find_map_fd_by_name(obj, "events");
    if (g_fd_cells < 0 || g_fd_cellpol < 0) {
        fprintf(stderr, "agentlsm: serve maps missing\n"); return -1;
    }
    return 0;
}

static void bpf_detach(void)
{
    if (g_obj) bpf_object__close(g_obj);   /* takes all links with it */
    g_obj = NULL;
}

/* ---- serve mode ------------------------------------------------------- */

struct conn {
    int   fd;
    int   watcher;
    __u32 mask;                 /* event classes this watcher wants */
    char  buf[256];
    size_t len;
};
static struct conn g_conn[MAX_WATCH];

static void conn_drop(int i)
{
    close(g_conn[i].fd);
    g_conn[i].fd = -1;
    g_conn[i].watcher = 0;
    g_conn[i].mask = 0;
}

/* fan one formatted line out to all watchers (best effort); the
 * daemon's own log gets the high-signal classes only — the full
 * stream (OPEN especially) would flood it */
static void fanout(const char *line, __u32 classbit)
{
    if (classbit & ((1 << EV_DENY) | (1 << EV_TRIP))) {
        fputs(line, stdout);
        fflush(stdout);
    }
    for (int i = 0; i < MAX_WATCH; i++) {
        if (g_conn[i].fd < 0 || !g_conn[i].watcher) continue;
        if (!(g_conn[i].mask & classbit)) continue;
        if (write(g_conn[i].fd, line, strlen(line)) < 0)
            conn_drop(i);                   /* watcher went away */
    }
}

static int on_evt(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    struct evt *e = data;
    char info[300], line[400];
    const char *cls;
    __u32 bit;

    switch (e->type) {
    case EV_DENY:
        cls = "DENY"; bit = 1 << EV_DENY;
        snprintf(info, sizeof info, "%s[%u] %s", e->comm, e->tgid, e->path);
        break;
    case EV_EXEC:
        cls = "EXEC"; bit = 1 << EV_EXEC;
        snprintf(info, sizeof info, "%s[%u] %s", e->comm, e->tgid, e->path);
        break;
    case EV_OPEN:
        cls = "OPEN"; bit = 1 << EV_OPEN;
        snprintf(info, sizeof info, "%s[%u] %s", e->comm, e->tgid, e->path);
        break;
    case EV_CONNECT: {
        cls = "NET"; bit = 1 << EV_CONNECT;
        unsigned short fam;                      /* e->path = sockaddr */
        memcpy(&fam, e->path, 2);
        if (fam == 2 /* AF_INET */) {
            unsigned short port;
            unsigned char ip[4];
            memcpy(&port, e->path + 2, 2);
            memcpy(ip, e->path + 4, 4);
            snprintf(info, sizeof info, "%s[%u] connect %u.%u.%u.%u:%u",
                     e->comm, e->tgid, ip[0], ip[1], ip[2], ip[3],
                     ntohs(port));
        } else {
            snprintf(info, sizeof info, "%s[%u] connect family=%u",
                     e->comm, e->tgid, fam);
        }
        break;
    }
    case EV_TRIP:
        cls = "TRIP"; bit = 1 << EV_TRIP;
        snprintf(info, sizeof info, "%s[%u] blocked syscall %s (%u)",
                 e->comm, e->tgid, attempt_name(e->nr), e->nr);
        break;
    default:
        return 0;
    }
    snprintf(line, sizeof line, "EV %llu %s %s\n",
             (unsigned long long)e->cgid, cls, info);
    fanout(line, bit);
    return 0;
}

static int cell_add(__u64 cgid, const char *prefix)
{
    struct { __u64 cgid; char prefix[PLEN]; } k = {0};
    k.cgid = cgid;
    snprintf(k.prefix, PLEN, "%s", prefix);
    __u32 act = ACT_DENY;
    if (bpf_map_update_elem(g_fd_cellpol, &k, &act, BPF_ANY)) return -1;
    __u32 one = 1;
    if (bpf_map_update_elem(g_fd_cells, &cgid, &one, BPF_ANY)) return -1;
    return 0;
}

static int cell_del(__u64 cgid, const char *prefix)
{
    struct { __u64 cgid; char prefix[PLEN]; } k = {0};
    k.cgid = cgid;
    snprintf(k.prefix, PLEN, "%s", prefix);
    return bpf_map_delete_elem(g_fd_cellpol, &k);
}

/* drop every rule of a cell: walk cellpol with get_next_key */
static int cell_clr(__u64 cgid)
{
    struct { __u64 cgid; char prefix[PLEN]; } cur = {0}, nxt;
    for (;;) {
        if (bpf_map_get_next_key(g_fd_cellpol, &cur, &nxt)) break;
        if (nxt.cgid == cgid)
            bpf_map_delete_elem(g_fd_cellpol, &nxt);
        cur = nxt;
    }
    return bpf_map_delete_elem(g_fd_cells, &cgid);
}

/* handle one full request line; reply written to fd */
static void serve_line(int ci, char *line)
{
    char rep[128];
    while (*line == ' ') line++;

    if (!strncmp(line, "ADD ", 4)) {
        unsigned long long cgid;
        char prefix[PLEN];
        if (sscanf(line + 4, "%llu %63s", &cgid, prefix) == 2 &&
            !cell_add(cgid, prefix))
            snprintf(rep, sizeof rep, "OK\n");
        else
            snprintf(rep, sizeof rep, "ERR add\n");
    } else if (!strncmp(line, "DEL ", 4)) {
        unsigned long long cgid;
        char prefix[PLEN];
        if (sscanf(line + 4, "%llu %63s", &cgid, prefix) == 2 &&
            !cell_del(cgid, prefix))
            snprintf(rep, sizeof rep, "OK\n");
        else
            snprintf(rep, sizeof rep, "ERR del\n");
    } else if (!strncmp(line, "CLR ", 4)) {
        unsigned long long cgid;
        if (sscanf(line + 4, "%llu", &cgid) == 1 && !cell_clr(cgid))
            snprintf(rep, sizeof rep, "OK\n");
        else
            snprintf(rep, sizeof rep, "ERR clr\n");
    } else if (!strcmp(line, "LIST")) {
        struct { __u64 cgid; char prefix[PLEN]; } cur = {0}, nxt;
        for (;;) {
            if (bpf_map_get_next_key(g_fd_cellpol, &cur, &nxt)) break;
            char l[PLEN + 32];
            snprintf(l, sizeof l, "%llu %s\n",
                     (unsigned long long)nxt.cgid, nxt.prefix);
            if (write(g_conn[ci].fd, l, strlen(l)) < 0) { conn_drop(ci); return; }
            cur = nxt;
        }
        snprintf(rep, sizeof rep, "END\n");
    } else if (!strncmp(line, "WATCH", 5)) {
        /* WATCH [deny,exec,open,net,trip] — bare WATCH = all classes */
        __u32 mask = 0;
        char *p = line + 5;
        while (*p == ' ') p++;
        for (char *tok = strtok(p, ","); tok; tok = strtok(NULL, ",")) {
            if (!strcmp(tok, "deny"))  mask |= 1 << EV_DENY;
            if (!strcmp(tok, "exec"))  mask |= 1 << EV_EXEC;
            if (!strcmp(tok, "open"))  mask |= 1 << EV_OPEN;
            if (!strcmp(tok, "net") || !strcmp(tok, "connect"))
                mask |= 1 << EV_CONNECT;
            if (!strcmp(tok, "trip"))  mask |= 1 << EV_TRIP;
        }
        g_conn[ci].watcher = 1;
        g_conn[ci].mask = mask ? mask : ~0u;
        snprintf(rep, sizeof rep, "OK\n");
    } else if (!strcmp(line, "QUIT") || !strcmp(line, "BYE")) {
        conn_drop(ci);
        return;
    } else {
        snprintf(rep, sizeof rep, "ERR unknown\n");
    }
    if (write(g_conn[ci].fd, rep, strlen(rep)) < 0)
        conn_drop(ci);
}

static int serve_mode(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "agentlsm: serve must run as root\n");
        return 1;
    }
    if (bpf_load_attach(0, 1, 0, 0, 0 /* MODE_SERVE */)) return 1;

    mkdir("/run/agentcell", 0755);
    unlink(LSM_SOCK);

    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", LSM_SOCK);
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) +
                     strlen(a.sun_path) + 1;
    if (bind(lfd, (struct sockaddr *)&a, alen) < 0 || listen(lfd, 16) < 0) {
        perror("agentlsm: bind " LSM_SOCK); return 1;
    }
    chmod(LSM_SOCK, 0666);

    struct ring_buffer *rb =
        ring_buffer__new(g_fd_events, on_evt, NULL, NULL);
    if (!rb) { fprintf(stderr, "agentlsm: ringbuf failed\n"); return 1; }

    for (int i = 0; i < MAX_WATCH; i++) g_conn[i].fd = -1;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);   /* clients may vanish mid-write */
    printf("agentlsm: serving %s  (Ctrl-C to detach and stop)\n", LSM_SOCK);
    fflush(stdout);

    while (!g_stop) {
        /* 1) drain BPF events -> watchers */
        ring_buffer__poll(rb, 100);

        /* 2) accept new control clients */
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        poll(&pfd, 1, 0);
        if (pfd.revents & POLLIN) {
            int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0) {
                int slot = -1;
                for (int i = 0; i < MAX_WATCH; i++)
                    if (g_conn[i].fd < 0) { slot = i; break; }
                if (slot < 0) close(c);
                else {
                    g_conn[slot].fd = c;
                    g_conn[slot].watcher = 0;
                    g_conn[slot].mask = 0;
                    g_conn[slot].len = 0;
                }
            }
        }

        /* 3) read request lines from clients */
        for (int i = 0; i < MAX_WATCH; i++) {
            if (g_conn[i].fd < 0) continue;
            struct pollfd p = { .fd = g_conn[i].fd, .events = POLLIN };
            poll(&p, 1, 0);
            if (!(p.revents & POLLIN)) {
                if (p.revents & (POLLHUP | POLLERR)) conn_drop(i);
                continue;
            }
            char *b = g_conn[i].buf + g_conn[i].len;
            ssize_t r = read(g_conn[i].fd, b,
                             sizeof g_conn[i].buf - 1 - g_conn[i].len);
            if (r <= 0) { conn_drop(i); continue; }
            g_conn[i].len += r;
            g_conn[i].buf[g_conn[i].len] = 0;

            /* process complete lines */
            char *nl;
            while ((nl = strchr(g_conn[i].buf, '\n'))) {
                *nl = 0;
                serve_line(i, g_conn[i].buf);
                if (g_conn[i].fd < 0) break;         /* QUIT */
                size_t rest = strlen(nl + 1);
                memmove(g_conn[i].buf, nl + 1, rest);
                g_conn[i].len = rest;
                g_conn[i].buf[g_conn[i].len] = 0;
            }
            if (g_conn[i].len >= sizeof g_conn[i].buf - 1)
                g_conn[i].len = 0;                    /* junk flood guard */
        }
    }

    ring_buffer__free(rb);
    for (int i = 0; i < MAX_WATCH; i++)
        if (g_conn[i].fd >= 0) conn_drop(i);
    close(lfd);
    unlink(LSM_SOCK);
    bpf_detach();
    printf("agentlsm: detached\n");
    return 0;
}

/* ---- one-shot modes --------------------------------------------------- */

static int on_evt_oneshot(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    printf("DENY (audit) %llu %s\n",
           (unsigned long long)((struct evt *)data)->cgid,
           (const char *)((struct evt *)data)->path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "serve"))
        return serve_mode();

    const char *cgroup = NULL;
    const char *deny[64];
    int n_deny = 0, audit = 0, anycg = 0;
    double block_all = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--cgroup") && i + 1 < argc) cgroup = argv[++i];
        else if (!strcmp(argv[i], "--deny") && i + 1 < argc) deny[n_deny++] = argv[++i];
        else if (!strcmp(argv[i], "--audit")) audit = 1;
        else if (!strcmp(argv[i], "--any-cgroup")) anycg = 1;
        else if (!strcmp(argv[i], "--block-all") && i + 1 < argc)
            block_all = strtod(argv[++i], NULL);
        else {
            fprintf(stderr, "usage: %s serve\n"
                            "       %s --cgroup PATH [--deny PREFIX]... "
                            "[--audit] [--any-cgroup]\n"
                            "       %s --block-all SECONDS [--cgroup PATH]\n",
                    argv[0], argv[0], argv[0]);
            return 2;
        }
    }
    if (!block_all && !cgroup && !anycg) {
        fprintf(stderr, "agentlsm: --cgroup, --any-cgroup or --block-all "
                        "required (or 'serve')\n");
        return 2;
    }
    if (block_all && (block_all < 0.1 || block_all > 10.0)) {
        fprintf(stderr, "agentlsm: --block-all must be 0.1..10 seconds\n");
        return 2;
    }

    struct stat st = {0};
    if (cgroup && stat(cgroup, &st) < 0) { perror(cgroup); return 1; }

    if (geteuid() != 0) {
        fprintf(stderr, "agentlsm: must run as root (CAP_BPF + CAP_SYS_ADMIN "
                        "for LSM attach)\n");
        return 1;
    }

    if (block_all) {
        /* time-bounded deny-everything window, kernel-side deadline.
         * Scoped to --cgroup when given — the system-wide variant
         * EPERMs EVERY process on the machine, including the shell,
         * desktop or agent harness that launched it. */
        __u64 bcgid = (cgroup && !anycg) ? (__u64)st.st_ino : 0;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        __u64 until = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec
                    + (__u64)(block_all * 1e9) + 500000000ULL;
        if (bpf_load_attach(0, 0, until, bcgid, 0)) return 1;

        if (!bcgid)
            fprintf(stderr, "agentlsm: WARNING: no --cgroup — EVERY open "
                            "system-wide will fail for %.1fs\n", block_all);
        printf("agentlsm: BLOCK-ALL armed%s: opens DENIED for %.1fs "
               "(0.5s grace), kernel-side deadline, then auto-detach\n",
               bcgid ? " (cgroup-scoped)" : "", block_all);
        fflush(stdout);
        double total = 0.5 + block_all;
        while (total > 0 && !g_stop) {
            double step = total > 0.25 ? 0.25 : total;
            struct timespec ts = { (time_t)step,
                (long)((step - (time_t)step) * 1e9) };
            nanosleep(&ts, NULL);
            total -= step;
        }
        bpf_detach();
        printf("agentlsm: window over, detached\n");
        return 0;
    }

    if (bpf_load_attach((cgroup && !anycg) ? (__u64)st.st_ino : 0,
                        !audit, 0, 0, 1 /* MODE_FLAT */))
        return 1;

    if (n_deny == 0) {
        deny[n_deny++] = "/etc/shadow";
        deny[n_deny++] = "/etc/gshadow";
    }
    for (int i = 0; i < n_deny; i++) {
        char key[PLEN] = {0};
        snprintf(key, sizeof key, "%s", deny[i]);
        __u32 act = ACT_DENY;
        if (bpf_map_update_elem(g_fd_policy, key, &act, BPF_ANY)) {
            fprintf(stderr, "agentlsm: policy update failed: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    printf("agentlsm: enforcing=%d cgid=%llu deny-list:\n", !audit,
           (unsigned long long)((cgroup && !anycg) ? st.st_ino : 0));
    for (int i = 0; i < n_deny; i++) printf("  - %s\n", deny[i]);
    printf("Ctrl-C to detach\n");

    struct ring_buffer *rb = NULL;
    if (audit) {
        rb = ring_buffer__new(g_fd_events, on_evt_oneshot, NULL, NULL);
        if (!rb) fprintf(stderr, "agentlsm: ringbuf setup failed\n");
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    while (!g_stop) {
        if (audit && rb) {
            if (ring_buffer__poll(rb, 1000) == -EINTR)
                break;
        } else {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }

    if (rb) ring_buffer__free(rb);
    bpf_detach();
    printf("agentlsm: detached\n");
    return 0;
}
