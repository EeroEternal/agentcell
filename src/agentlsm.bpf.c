// SPDX-License-Identifier: GPL-2.0
/*
 * agentlsm.bpf.c — BPF LSM enforcement for AgentCell.
 *
 * Attaches to lsm/file_open and enforces a path-prefix policy for
 * processes inside a sandbox cgroup: files under an ALLOW prefix open
 * normally, files under a DENY prefix get -EPERM at the LSM layer —
 * below Landlock and the read-only bind mounts, in kernel space.
 *
 * This is Landlock's job too (defense in depth), but BPF LSM is
 * programmable and hot-swappable: change the map, policy changes now.
 *
 * Requires the kernel's LSM list to include "bpf" (check
 * /sys/kernel/security/lsm) and root to load.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "arch/syscalls.h"   /* AC_SYS_*: per-arch numbers (BPF build
                              * selects via -D__TARGET_ARCH_*) */

#ifndef EPERM
#define EPERM 1
#endif

#define PLEN 64

/* action values in the policy map */
#define ACT_ALLOW 1
#define ACT_DENY   2

/* prefix -> action; longest matching prefix wins (one-shot modes) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[PLEN]);
    __type(value, __u32);
} policy SEC(".maps");

/* ---- serve mode (agentlsm serve): per-cell policies ----
 *
 * Each registered sandbox cgroup gets an entry in `cells` (this is the
 * cheap short-circuit: opens from the other ~10k processes on the
 * system cost ONE hash lookup) and per-prefix rules in `cellpol`,
 * keyed by {cgid, prefix}.  A DENY match enforces -EPERM and emits an
 * event (enforcement + visibility together).
 */
struct cellkey {
    __u64 cgid;
    char prefix[PLEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u32);
} cells SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct cellkey);
    __type(value, __u32);
} cellpol SEC(".maps");

/* event classes streamed to watchers (sand lsm -f) */
#define EV_DENY    1   /* LSM file_open denial         */
#define EV_EXEC    2   /* execve(path)                 */
#define EV_OPEN    3   /* openat(path)                 */
#define EV_CONNECT 4   /* connect(sockaddr)            */
#define EV_TRIP    5   /* blocked-syscall attempt (nr) */

struct evt {
    __u64 cgid;
    __u32 tgid;
    __u32 type;
    __u32 nr;
    char  comm[16];
    char  path[192];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* sys_enter tracepoint context — stable kernel ABI (matches the format
 * files under /sys/kernel/tracing/events/syscalls/sys_enter_XXX) */
struct tp_sys_enter {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           syscall_nr;
    unsigned long  args[6];
};

/* activity probes (merged from agentmon): only registered cells, one
 * hash lookup for the other ~10k processes — same short-circuit as
 * the LSM hook.  These tracepoints fire BEFORE seccomp, so escape
 * attempts (TRIP) are visible even though seccomp then denies them. */
static __always_inline struct evt *mon_reserve(__u32 type, __u32 nr)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    if (!bpf_map_lookup_elem(&cells, &cgid))
        return 0;
    struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 pt = bpf_get_current_pid_tgid();
    e->cgid = cgid;
    e->tgid = pt >> 32;
    e->type = type;
    e->nr   = nr;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    return e;
}

/* what did the agent exec? */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct tp_sys_enter *ctx)
{
    struct evt *e = mon_reserve(EV_EXEC, 59);
    if (!e) return 0;
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* which files is the agent touching? (openat: args[1] = pathname) */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct tp_sys_enter *ctx)
{
    struct evt *e = mon_reserve(EV_OPEN, 257);
    if (!e) return 0;
    bpf_probe_read_user_str(e->path, sizeof(e->path),
                            (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* where is the agent connecting? (connect: args[1] = sockaddr*) */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct tp_sys_enter *ctx)
{
    struct evt *e = mon_reserve(EV_CONNECT, 42);
    if (!e) return 0;
    bpf_probe_read_user(e->path, 16, (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

#ifndef ENOSYS
#define ENOSYS 38
#endif

/*
 * Escape attempts (TRIP): sys_ENTER tracepoints can't see them — the
 * kernel runs seccomp first, so a denied syscall never reaches the
 * entry probes.  But the syscall still goes through the exit path:
 * raw_syscalls/sys_exit fires with the return value seccomp chose
 * (-EPERM, or -ENOSYS for the clone3 fallback trick).  No audit-log
 * tail, no /proc race — the process is right here in its own exit
 * path, so the cgroup id is exact.
 */
struct tp_sys_exit {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           nr;
    long           ret;
};

static __always_inline int trip_nr(long nr)
{
    switch (nr) {
#define X(s) case AC_SYS_##s:
    AC_TRIP_X
#undef X
        return 1;
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int tp_sys_exit(struct tp_sys_exit *ctx)
{
    if (!trip_nr(ctx->nr))
        return 0;
    if (ctx->ret != -EPERM && ctx->ret != -ENOSYS)
        return 0;
    struct evt *e = mon_reserve(EV_TRIP, (__u32)ctx->nr);
    if (!e) return 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* set from userspace: 0 = audit only (log, allow) */
const volatile __u64 target_cgid = 0;
const volatile int enforce = 0;
/* MODE_SERVE: only the map-driven per-cell path runs.
 * MODE_FLAT:  the one-shot flat policy path runs (target_cgid may
 *             still be 0 = match every cgroup). */
#define MODE_SERVE 0
#define MODE_FLAT  1
const volatile int mode = MODE_SERVE;

/*
 * Decisive-experiment mode (--block-all N): deny EVERY file_open
 * until this monotonic ktime.  Time-bounded in the kernel, so even
 * if the loader is killed the denial self-expires.  Scoped to
 * block_cgid when set; 0 = system-wide — a deliberate debug hammer
 * that EPERMs every process on the machine, including the shell or
 * agent harness that launched it.
 */
const volatile __u64 block_until_ns = 0;
const volatile __u64 block_cgid = 0;

/* bpf_d_path kfunc is declared by vmlinux.h on modern kernels */

char _license[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(cell_file_open, struct file *file)
{
    if (block_until_ns) {
        /* block-all window: policy maps ignored; scoped to block_cgid
         * when set (0 = system-wide) */
        if (bpf_ktime_get_ns() < block_until_ns) {
            if (!block_cgid ||
                bpf_get_current_cgroup_id() == block_cgid)
                return -EPERM;
        }
        return 0;
    }

    __u64 cgid = bpf_get_current_cgroup_id();

    /* ---- serve mode: registered cell? (one lookup for everyone else) */
    if (bpf_map_lookup_elem(&cells, &cgid)) {
        char path[PLEN];
        long n = bpf_d_path(&file->f_path, path, sizeof(path));
        if (n < 0)
            return 0;

        int plen = 0;
        for (; plen < PLEN - 1 && path[plen]; plen++)
            ;

        for (int len = plen; len > 0; len--) {
            struct cellkey k = {0};
            k.cgid = cgid;
            for (int j = 0; j < PLEN - 1; j++) {
                if (j >= len) break;   /* blocks loop->memcpy conversion */
                k.prefix[j] = path[j];
            }
            __u32 *act = bpf_map_lookup_elem(&cellpol, &k);
            if (act) {
                if (*act == ACT_DENY) {
                    struct evt *e = bpf_ringbuf_reserve(&events,
                                                         sizeof(*e), 0);
                    if (e) {
                        __u64 pt = bpf_get_current_pid_tgid();
                        e->cgid = cgid;
                        e->tgid = pt >> 32;
                        e->type = EV_DENY;
                        e->nr   = 0;
                        bpf_get_current_comm(e->comm, sizeof(e->comm));
                        __builtin_memcpy(e->path, path, PLEN);
                        bpf_ringbuf_submit(e, 0);
                    }
                    return -EPERM;
                }
                break;   /* longest match: explicit allow */
            }
        }
        return 0;
    }

    /* ---- one-shot modes (--cgroup / --any-cgroup) ---- */
    if (mode != MODE_FLAT)
        return 0;
    if (target_cgid && cgid != target_cgid)
        return 0;

    char path[PLEN];
    long n = bpf_d_path(&file->f_path, path, sizeof(path));
    if (n < 0)
        return 0;

    /* path length (bpf_d_path returns length including the NUL) */
    int plen = 0;
    for (; plen < PLEN - 1 && path[plen]; plen++)
        ;

    /* longest-prefix match: try full path first, then chop.
     * pfx must be fully zeroed — the map key is all 64 bytes. */
    __u32 best = 0;
    for (int len = plen; len > 0; len--) {
        char pfx[PLEN] = {0};
        for (int j = 0; j < PLEN - 1; j++) {
            if (j >= len) break;   /* blocks loop->memcpy conversion */
            pfx[j] = path[j];
        }
        __u32 *act = bpf_map_lookup_elem(&policy, pfx);
        if (act) {
            best = *act;
            break;   /* longest match wins */
        }
    }

    if (best == ACT_DENY) {
        if (enforce)
            return -EPERM;      /* kernel-level denial */
        struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            __u64 pt = bpf_get_current_pid_tgid();
            e->cgid = cgid;
            e->tgid = pt >> 32;
            e->type = EV_DENY;
            e->nr   = 0;
            bpf_get_current_comm(e->comm, sizeof(e->comm));
            __builtin_memcpy(e->path, path, PLEN);
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}
