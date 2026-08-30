// SPDX-License-Identifier: GPL-2.0 (kernel-side BPF; repo is MIT)
/*
 * agentmon.bpf.c — eBPF audit probes for the agentcell sandbox.
 *
 * Attaches to syscall-entry tracepoints and streams events to a ring
 * buffer. Every probe filters on the cgroup id of the sandbox, so only
 * the sandboxed agent's activity is reported — not the whole system.
 *
 * Note: the kernel runs seccomp BEFORE the sys_enter tracepoints, so
 * the EV_ATTEMPT probes do NOT fire for syscalls the sandbox's seccomp
 * filter denies — those are covered by --audit mode (kernel audit log,
 * type=1326).  They still fire when watching cgroups without such a
 * filter (e.g. ad-hoc monitoring of non-sandboxed workloads).
 *
 * Compile: clang -target bpf -O2 -g -c agentmon.bpf.c -o agentmon.bpf.o
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define DLEN 192

enum ev_type {
    EV_EXEC    = 1,   /* execve(path)                       */
    EV_OPEN    = 2,   /* openat(path)                       */
    EV_CONNECT = 3,   /* connect(sockaddr)                  */
    EV_ATTEMPT = 4,   /* blocked-syscall attempt (see nr)   */
};

struct ev {
    __u64 ts;
    __u64 cgid;
    __u32 tgid;
    __u32 tid;
    __u32 type;
    __u32 nr;         /* syscall number (EV_ATTEMPT)       */
    char  comm[16];
    char  data[DLEN]; /* path string or raw sockaddr       */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/* set from userspace before load; 0 = no filtering */
const volatile __u64 target_cgid = 0;

/*
 * Layout of the syscalls/sys_enter_* tracepoint context. This is stable
 * kernel ABI (it matches the format files under
 * /sys/kernel/tracing/events/syscalls/sys_enter_XXX/format).
 */
struct tp_sys_enter {
    unsigned short common_type;
    unsigned char  common_flags;
    unsigned char  common_preempt_count;
    int            common_pid;
    long           syscall_nr;
    unsigned long  args[6];
};

static __always_inline struct ev *reserve(__u32 type, __u32 nr)
{
    if (target_cgid) {
        __u64 cgid = bpf_get_current_cgroup_id();
        if (cgid != target_cgid)
            return 0;
    }
    struct ev *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    __u64 pid = bpf_get_current_pid_tgid();
    e->ts   = bpf_ktime_get_ns();
    e->cgid = bpf_get_current_cgroup_id();
    e->tgid = pid >> 32;
    e->tid  = (__u32)pid;
    e->type = type;
    e->nr   = nr;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    return e;
}

/* what did the agent exec? */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct tp_sys_enter *ctx)
{
    struct ev *e = reserve(EV_EXEC, 59);
    if (!e) return 0;
    bpf_probe_read_user_str(e->data, DLEN, (const void *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* which files is the agent touching? (openat: args[1] = pathname) */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct tp_sys_enter *ctx)
{
    struct ev *e = reserve(EV_OPEN, 257);
    if (!e) return 0;
    bpf_probe_read_user_str(e->data, DLEN, (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* where is the agent connecting? (connect: args[1] = sockaddr*) */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct tp_sys_enter *ctx)
{
    struct ev *e = reserve(EV_CONNECT, 42);
    if (!e) return 0;
    bpf_probe_read_user(e->data, 16, (const void *)ctx->args[1]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Escape-attempt probes — syscalls the sandbox denies anyway, but you
 * want to KNOW about. x86_64 syscall numbers passed explicitly.
 */
#define ATTEMPT(name, nr)                                                  \
SEC("tracepoint/syscalls/sys_enter_" #name)                                \
int tp_att_##name(struct tp_sys_enter *ctx)                                \
{                                                                          \
    struct ev *e = reserve(EV_ATTEMPT, (nr));                              \
    if (!e) return 0;                                                      \
    bpf_ringbuf_submit(e, 0);                                              \
    return 0;                                                              \
}

ATTEMPT(mount,         165)
ATTEMPT(umount,       166)   /* tracepoint keeps the historic name */
ATTEMPT(pivot_root,    155)
ATTEMPT(unshare,       272)
ATTEMPT(setns,         308)
ATTEMPT(clone3,        435)
ATTEMPT(bpf,           321)
ATTEMPT(perf_event_open, 298)
ATTEMPT(ptrace,        101)
ATTEMPT(keyctl,        250)
ATTEMPT(init_module,   175)
ATTEMPT(delete_module, 176)
ATTEMPT(userfaultfd,   323)
ATTEMPT(io_uring_setup, 425)

char _license[] SEC("license") = "GPL";
