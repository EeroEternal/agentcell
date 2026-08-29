// SPDX-License-Identifier: GPL-2.0
/*
 * agentlsm.c — loader/daemon for the AgentCell BPF LSM enforcement.
 *
 * One-shot modes (debugging / bisect):
 *   sudo ./agentlsm --cgroup PATH [--deny PREFIX]... [--audit]
 *   sudo ./agentlsm --any-cgroup [--deny PREFIX]...
 *   sudo ./agentlsm --block-all SECONDS   deny every open, system-wide
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
 *       WATCH                  from now on: "EV <cgid> <path>" lines
 *
 *     Denials are enforced (-EPERM) AND reported to watchers.
 *
 * Socket: /run/agentcell/lsm.sock (0666 — single-user trust model for
 * now: anyone local may register policy; document before sharing).
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
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

struct evt { __u64 cgid; char path[PLEN]; };

/* ---- shared bpf state ------------------------------------------------ */

static struct bpf_object *g_obj;
static struct bpf_link   *g_link;
static int g_fd_policy, g_fd_cells, g_fd_cellpol, g_fd_events;

static int bpf_load_attach(__u64 target_cgid, int enforce,
                           __u64 block_until_ns, int mode)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct bpf_object *obj = bpf_object__open_mem(bpf_elf, bpf_elf_len, NULL);
    if (!obj) { fprintf(stderr, "agentlsm: open failed\n"); return -1; }

    /* rodata layout: target_cgid@0, enforce@8, mode@12, block_until@16 */
    struct {
        __u64 target_cgid;
        int  enforce;
        int  mode;
        __u64 block_until_ns;
    } __attribute__((packed)) cfg = { target_cgid, enforce, mode,
                                      block_until_ns };

    struct bpf_map *ro = bpf_object__find_map_by_name(obj, ".rodata");
    if (!ro || bpf_map__set_initial_value(ro, &cfg, sizeof cfg)) {
        fprintf(stderr, "agentlsm: cannot set config\n"); return -1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "agentlsm: load failed: %s\n", strerror(errno));
        return -1;
    }

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "cell_file_open");
    if (!prog) { fprintf(stderr, "agentlsm: program not found\n"); return -1; }

    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "agentlsm: attach lsm/file_open failed: %s\n"
                        "  (is 'bpf' in /sys/kernel/security/lsm?)\n",
                strerror(errno));
        return -1;
    }

    g_obj        = obj;
    g_link       = link;
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
    if (g_link) bpf_link__destroy(g_link);
    if (g_obj)  bpf_object__close(g_obj);
    g_link = NULL; g_obj = NULL;
}

/* ---- serve mode ------------------------------------------------------- */

struct conn {
    int   fd;
    int   watcher;
    char  buf[256];
    size_t len;
};
static struct conn g_conn[MAX_WATCH];

static void conn_drop(int i)
{
    close(g_conn[i].fd);
    g_conn[i].fd = -1;
    g_conn[i].watcher = 0;
}

/* fan one formatted line out to all watchers (best effort) */
static void fanout(const char *line)
{
    fputs(line, stdout);                    /* daemon log too */
    fflush(stdout);
    for (int i = 0; i < MAX_WATCH; i++) {
        if (g_conn[i].fd < 0 || !g_conn[i].watcher) continue;
        if (write(g_conn[i].fd, line, strlen(line)) < 0)
            conn_drop(i);                   /* watcher went away */
    }
}

static int on_evt(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    struct evt *e = data;
    char line[PLEN + 48];
    snprintf(line, sizeof line, "EV %llu %s\n",
             (unsigned long long)e->cgid, e->path);
    fanout(line);
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
    } else if (!strcmp(line, "WATCH")) {
        g_conn[ci].watcher = 1;
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
    if (bpf_load_attach(0, 1, 0, 0 /* MODE_SERVE */)) return 1;

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
                            "       %s --block-all SECONDS\n",
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

    if (bpf_load_attach((cgroup && !anycg) ? (__u64)st.st_ino : 0,
                        !audit, 0, 1 /* MODE_FLAT */))
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

    if (block_all) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        __u64 until = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec
                    + (__u64)(block_all * 1e9) + 500000000ULL;
        bpf_detach();
        if (bpf_load_attach(0, 0, until, 0)) return 1;

        printf("agentlsm: BLOCK-ALL armed: opens DENIED for %.1fs "
               "(0.5s grace), kernel-side deadline, then auto-detach\n",
               block_all);
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
