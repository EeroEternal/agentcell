# AgentCell OS — a purpose-built host for speed

This note is a **redesign of the machine AgentCell runs on**, not a rewrite of
`sand`. Isolation stays the same primitives (namespaces, pivot, Landlock,
seccomp-cBPF, cgroup v2). What changes is everything around them: kernel LSM
stack, root filesystem, process model, and networking.

Today AgentCell is fast on a **general-purpose** distro (~5 ms cold start,
~2 ms `sand exec`, +2.8% syscall tax). A dedicated OS can push cold start
toward ~1 ms and pre-warmed exec well under 1 ms — by **doing less work**,
not by putting eBPF inside the jail.

## Why a new OS at all

On Arch/Ubuntu the expensive parts are not “Intel vs AMD”:

| Cost | Typical | Cause |
|---|---|---|
| Cold start | ~5 ms | `clone` of 6 namespaces + **recursive bind of `/usr`** + Landlock + seccomp |
| Hot exec | ~2 ms | already amortized (`sand serve`) |
| Every syscall | +2.8% | seccomp **classic BPF** BST (fixed) |
| Every `open` | extra LSM | AppArmor + Landlock + optional BPF LSM **stacked** |

eBPF cannot replace seccomp (the kernel does not allow it). Loading BPF per
`./sand` would **slow** startup. The daemon already loads BPF **once**.

A purpose-built host attacks: **mount work**, **LSM stacking**, and **repeated
clone of the world**.

## Goals and non-goals

**Goals**

- Cold cell create: ~1 ms (small rootfs, few mounts).
- Pre-warmed command: ≪ 1 ms (cell pool, no `clone(NEWUSER|NEWNS|…)` per request).
- Syscall tax: ~+1–2% (shorter filter, fewer LSMs).
- Keep the sandbox **unprivileged**; root stays in one host daemon.

**Non-goals**

- Firecracker / gVisor / Kata (startup is tens–hundreds of ms).
- Per-cell BPF programs.
- `bpf()` / `io_uring` inside the jail (attack surface).
- “Faster because AMD/ARM” — startup is dominated by mounts and clone.

---

## 1. Kernel

### LSM list

Ideal `/sys/kernel/security/lsm`:

```
landlock
```

or, if kernel enforcement is required:

```
landlock,bpf
```

| Keep | Drop |
|---|---|
| Landlock (path rules, cheap) | AppArmor / SELinux (hook on every file op) |
| One global BPF LSM via `agentlsm serve` | integrity/IMA on the agent hot path |
| | loading BPF inside each cell |

When the BPF LSM is attached, **every** `open` on the machine pays a hash
lookup. That is acceptable only if the host exists to run cells — and the
program must short-circuit non-cell processes (AgentCell already does).

### Config sketch

- `CONFIG_USER_NS=y`, `CONFIG_CGROUP_BPF` unused for the jail itself
- `CONFIG_SECURITY_LANDLOCK=y`
- `CONFIG_BPF_LSM=y` only if `agentlsm` is in the product
- `CONFIG_SECCOMP_FILTER=y`
- `CONFIG_OVERLAY_FS=y`, `CONFIG_EROFS_FS=y` (or squashfs)
- No lockdep, kasan, kmemleak in production images
- `PREEMPT=none` or voluntary (throughput)
- Optional: `NO_HZ_FULL` + isolated CPUs for cell workers
- CPUFreq **performance** when latency matters

### Must remain

Unprivileged user namespaces, cgroup v2, seccomp, tmpfs, overlayfs.
`io_uring` stays **denied** in the cell unless the threat model explicitly
accepts it.

---

## 2. Root filesystem — one mount, not bind `/usr`

Recursive `MS_BIND` of the host `/usr` is the usual cold-start hog.

**Replace with a single read-only image:**

```
/opt/cell-root.erofs     # python, clang, pi, …
        │
   mount erofs (or squashfs) → cell /
   optional overlay upper = tmpfs (dies with the cell)
```

- Startup becomes: clone + 1–2 mounts + pivot — no walk of the host mount tree.
- Ship a **curated `/etc`** in the image (no host `shadow`, no systemd-resolved
  stub at `127.0.0.53`).
- Workspace remains a **real bind** (`/home/agent` → host dir) if persistence
  is wanted; scratch stays tmpfs.

erofs is preferred over squashfs for random reads (toolchain, interpreters).

`--overlay DIR` in today’s `sand` stays valid **inside** this image (copy-on-write
views of host project dirs). A whole-root overlay of `/` from a user namespace
is still the wrong tool (kernel rejects fs-root as lowerdir; DAC still applies).

---

## 3. Process model — cell pool

Today each `./sand -- cmd` rebuilds the world (~5 ms). `sand serve` already
amortizes that (~2 ms/exec). A dedicated OS should make **serve the default**:

```
boot
  └─ agentcelld          # root: one BPF object, veth pool, cell pool
        ├─ idle cells    # already pivoted, seccomp, Landlock
        └─ request       # SCM_RIGHTS into an idle cell (existing protocol)
```

| Path | Work |
|---|---|
| Boot / scale-out | `clone` + mounts + filters **once per pooled cell** |
| Agent command | `fork` + `exec` in an already-jailed pid 1 |
| Recycle | wipe tmpfs/overlay upper, or kill and replace from the pool |

Protocol is already there (`sand serve` / `sand exec`, streaming stdin).
The OS change is: **pre-create N cells**, don’t clone per HTTP request.

Expected: pre-warmed exec **well under 1 ms** (no `CLONE_NEWUSER|NEWNS|…`).

---

## 4. Syscall filter — keep cBPF, make it smaller

The +2.8% is seccomp. Linux **cannot** use eBPF as a seccomp filter.

On a dedicated host:

- Keep the **hand-built cBPF BST** (current design).
- Shorten the deny-list if the image has no need for those syscalls.
- Do **not** put syscall policy on `lsm/file_open` (heavier than `RET_ALLOW`).
- `--ask` (user-notify) is for humans, not the hot path.
- `--no-landlock` only if mount topology is already the policy.

---

## 5. Memory and disk

- Do **not** pin `memory.max` at the edge of RAM (reclaim storms). Today’s
  default (~60% of RAM) is the right idea; a dedicated box can omit per-cell
  `memory.max` and limit at a parent cgroup.
- Scratch = tmpfs (already).
- `io.max` only on cells that must be throttled; needs `io` in the cgroup
  subtree (often not delegated on desktop systemd — enable on this OS).
- NVMe multi-queue; avoid transparent hugepage compaction jitter for cells.

---

## 6. Network

If cells need the network:

**Pooled veth (preferred isolation)**

- One host bridge; **pre-created** `vethh*`/`vethc*` pairs.
- Daemon only `setns` + addresses — no `ip link add` per cell.
- One nftables MASQUERADE for `10.200.0.0/16` (already the AgentCell range).
- Optional **TC/XDP drop** on `vethh*` instead of a long iptables FORWARD chain.

**Host netns**

- Fastest; isolation is whatever the host firewall is. Acceptable on a
  single-tenant agent box.

DNS: put real nameservers in the cell image `/etc/resolv.conf`. Do not rely
on `127.0.0.53`.

---

## 7. Target picture

```
┌─ kernel ──────────────────────────────────────────────┐
│  LSM: landlock[,bpf]     no AppArmor/SELinux            │
│  seccomp + userns + cgroup2 + overlay + erofs           │
│  NO_HZ_FULL, isolated CPUs for cells                    │
└───────────────────────────────────────────────────────┘
┌─ userspace ───────────────────────────────────────────┐
│  agentcelld  — root, one BPF object, cell pool, veth    │
│  /opt/cell-root.erofs                                   │
│  minimal init — no desktop systemd stack                │
└───────────────────────────────────────────────────────┘
              │ unix socket / HTTP
     harness / gateway (unprivileged)
```

### Numbers (order of magnitude, not a promise)

| | General distro (now) | AgentCell OS |
|---|---|---|
| Cold create | ~5 ms | ~1 ms (tiny root, few mounts) |
| Pre-warmed exec | ~2 ms | ≪ 1 ms (pool, no clone) |
| Syscall tax | +2.8% | ~+1–2% (short filter, few LSMs) |
| `open` | Landlock + AppArmor (+bpf) | Landlock or bpf only |

---

## 8. What not to do

| Idea | Why not |
|---|---|
| eBPF instead of seccomp | Not a seccomp backend; verifier + hooks are slower |
| BPF load per cell | Startup regresses |
| `bpf()` in the jail | Breaks the isolation story |
| MicroVM per agent | Wrong latency class |
| “Faster CPU vendor” | Bind/clone dominate startup |

---

## 9. Migration from today’s AgentCell

Nothing in this document requires throwing away `sand`:

1. Keep **unprivileged** `sand` / `sand serve` / streaming exec protocol.
2. Run **one** `agentlsm serve` on the box (optional).
3. Swap host `/usr` binds for **erofs cell-root** when the image exists.
4. Teach `agentcelld` to **pool** serve-mode jails (new, small).
5. Ship a kernel + initramfs with the LSM list and cgroup layout above.

The GitHub tree (`sand`, `agentlsm`, `examples/client.py`, web gateway) is
the userspace; this OS is the **environment** that makes that userspace cheap.

## Related

- Runtime: `README.md` (usage, `sand serve`, `--net veth`, `--overlay`, `io.max`)
- Python client: `examples/client.py`
- HTTP gateway sketch: `examples/webui/server.py`
