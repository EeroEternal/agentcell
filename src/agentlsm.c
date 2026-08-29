// SPDX-License-Identifier: GPL-2.0
/*
 * agentlsm.c — loader for the AgentCell BPF LSM enforcement.
 *
 *   sudo ./agentlsm --cgroup PATH [--deny PREFIX]... [--audit]
 *   sudo ./agentlsm --block-all SECONDS    # decisive experiment:
 *                                          # deny ALL opens system-wide
 *                                          # for SECONDS (max 10),
 *                                          # 0.5s arming grace, then
 *                                          # auto-detach. Time-bounded
 *                                          # in-kernel, safe if killed.
 *
 * Default policy allows the sandbox's standard prefixes and denies
 * /etc/shadow + /etc/passwd- unless you pass your own --deny list
 * (then only that list is denied, everything else allowed).
 * Without --audit, denials are enforced with -EPERM.
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* bpf_elf[] and bpf_elf_len come from the -include'd xxd header */

static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

struct evt { char path[64]; };

static int on_evt(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    printf("DENY (audit) %s\n", (const char *)data);
    return 0;
}

int main(int argc, char **argv)
{
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
            fprintf(stderr, "usage: %s --cgroup PATH [--deny PREFIX]... [--audit]\n"
                            "                     [--any-cgroup]\n"
                            "       %s --block-all SECONDS\n"
                            "  --audit: log denials, don't enforce\n"
                            "  --any-cgroup: skip the cgroup check (bisect tool)\n",
                    argv[0], argv[0]);
            return 2;
        }
    }
    if (!block_all && !cgroup && !anycg) {
        fprintf(stderr, "agentlsm: --cgroup, --any-cgroup or --block-all required\n");
        return 2;
    }
    if (block_all) {
        if (block_all < 0.1 || block_all > 10.0) {
            fprintf(stderr, "agentlsm: --block-all must be 0.1..10 seconds\n");
            return 2;
        }
    }

    struct stat st = {0};
    if (cgroup) {
        if (stat(cgroup, &st) < 0) { perror(cgroup); return 1; }
    }
    __u64 cgid = st.st_ino;
    int enforce = !audit;

    if (geteuid() != 0) {
        fprintf(stderr, "agentlsm: must run as root (CAP_BPF + CAP_SYS_ADMIN "
                        "for LSM attach)\n");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /*
     * block-all window (ktime, CLOCK_MONOTONIC — same clock as
     * bpf_ktime_get_ns).  0.5s grace after attach so the test
     * harness is already running when denials begin.
     */
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    __u64 block_until = block_all
        ? (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec
          + ( __u64)(block_all * 1e9) + 500000000ULL
        : 0;

    size_t elf_len = bpf_elf_len;
    struct bpf_object *obj = bpf_object__open_mem(bpf_elf, elf_len, NULL);
    if (!obj) { fprintf(stderr, "agentlsm: open failed\n"); return 1; }

    struct bpf_map *ro = bpf_object__find_map_by_name(obj, ".rodata");
    /* layout must mirror the .rodata section: cgid@0, enforce@8,
     * pad@12, block_until_ns@16, size 24 */
    struct {
        __u64 cgid;
        int enforce;
        int pad;
        __u64 block_until_ns;
    } __attribute__((packed)) cfg = { (cgroup && !anycg) ? st.st_ino : 0,
                                      !audit, 0, block_until };
    (void)cgroup;
    if (!ro || bpf_map__set_initial_value(ro, &cfg, sizeof cfg)) {
        fprintf(stderr, "agentlsm: cannot set config\n"); return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "agentlsm: load failed: %s\n", strerror(errno));
        return 1;
    }

    /* populate the policy map: explicit deny list, or the default set */
    struct bpf_map *pol = bpf_object__find_map_by_name(obj, "policy");
    if (!pol) { fprintf(stderr, "agentlsm: no policy map\n"); return 1; }

    if (n_deny == 0 && !block_all) {
        deny[n_deny++] = "/etc/shadow";
        deny[n_deny++] = "/etc/gshadow";
    }
    for (int i = 0; i < n_deny; i++) {
        char key[64] = {0};
        snprintf(key, sizeof key, "%s", deny[i]);
        __u32 act = 2; /* ACT_DENY */
        if (bpf_map_update_elem(bpf_map__fd(pol), key, &act, BPF_ANY)) {
            fprintf(stderr, "agentlsm: policy update failed: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj,
                                                                "cell_file_open");
    if (!prog) { fprintf(stderr, "agentlsm: program not found\n"); return 1; }
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "agentlsm: attach lsm/file_open failed: %s\n"
                        "  (is 'bpf' in /sys/kernel/security/lsm?)\n",
                strerror(errno));
        return 1;
    }

    if (block_all) {
        double arm = 0.5, win = block_all;
        printf("agentlsm: BLOCK-ALL armed: attach ok\n"
               "  opens allowed  for the next %.1fs (arming grace)\n"
               "  opens DENIED  for %.1fs after that\n"
               "  then auto-detach (kernel-side deadline holds even if this "
               "process dies)\n", arm, win);
        fflush(stdout);
        /* sleep through grace+window without opening anything */
        double total = arm + win;
        while (total > 0 && !g_stop) {
            double step = total > 0.25 ? 0.25 : total;
            struct timespec ts = { (time_t)step,
                (long)((step - (time_t)step) * 1e9) };
            nanosleep(&ts, NULL);
            total -= step;
        }
        bpf_link__destroy(link);
        bpf_object__close(obj);
        printf("agentlsm: window over, detached\n");
        return 0;
    }

    printf("agentlsm: enforcing=%d cgid=%llu deny-list:\n", enforce,
           (unsigned long long)cgid);
    for (int i = 0; i < n_deny; i++) printf("  - %s\n", deny[i]);
    printf("Ctrl-C to detach\n");

    struct ring_buffer *rb = NULL;
    if (audit) {
        rb = ring_buffer__new(bpf_object__find_map_fd_by_name(obj, "events"),
                              on_evt, NULL, NULL);
        if (!rb) fprintf(stderr, "agentlsm: ringbuf setup failed\n");
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    while (!g_stop) {
        if (audit && rb) {
            if (ring_buffer__poll(rb, 1000) == -EINTR)
                break;
        } else {
            /* enforced idle: don't busy-spin the CPU */
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }

    if (rb) ring_buffer__free(rb);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    printf("agentlsm: detached\n");
    return 0;
}
