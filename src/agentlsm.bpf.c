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

#ifndef EPERM
#define EPERM 1
#endif

#define PLEN 64

/* action values in the policy map */
#define ACT_ALLOW 1
#define ACT_DENY   2

/* prefix -> action; longest matching prefix wins */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, char[PLEN]);
    __type(value, __u32);
} policy SEC(".maps");

struct evt {
    char path[PLEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} events SEC(".maps");

/* set from userspace: 0 = audit only (log, allow) */
const volatile __u64 target_cgid = 0;
const volatile int enforce = 0;

/*
 * Decisive-experiment mode (--block-all N): deny EVERY file_open,
 * system-wide, until this monotonic ktime.  Time-bounded in the
 * kernel, so even if the loader is killed the denial self-expires.
 */
const volatile __u64 block_until_ns = 0;

/* bpf_d_path kfunc is declared by vmlinux.h on modern kernels */

char _license[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(cell_file_open, struct file *file)
{
    if (block_until_ns) {
        /* block-all window: ignore cgroup and policy entirely */
        if (bpf_ktime_get_ns() < block_until_ns)
            return -EPERM;
        return 0;
    }

    if (target_cgid) {
        __u64 cgid = bpf_get_current_cgroup_id();
        if (cgid != target_cgid)
            return 0;
    }

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
            __builtin_memcpy(e->path, path, sizeof(e->path));
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}
