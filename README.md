# AgentCell

**A ~1000-line AI-agent sandbox built directly on Linux kernel primitives.**
No Docker, no container runtime, no daemon — and it runs **fully unprivileged**.

```
┌─────────────────────────────────────────────────────────────────┐
│  your agent payload (bash / python / claude / codex / ...)      │
├─────────────────────────────────────────────────────────────────┤
│  5. seccomp-BPF   hand-built sock_filter, binary-search tree    │
│                    (modules, ptrace, bpf, mount-API, io_uring…) │
│  4. Landlock LSM  path allowlist: where R / W / X is allowed    │
│  3. mount ns      tmpfs root + pivot_root; /usr /etc ro binds;  │
│                    fresh /proc /dev /sys; rw tmpfs /tmp /run    │
│  2. namespaces    user+pid+net+ipc+uts+cgroup via clone(2)      │
│                    uid 0 inside == your uid outside             │
│  1. cgroup v2     cpu.max / memory.max / pids.max / io.max      │
├─────────────────────────────────────────────────────────────────┤
│  eBPF monitor    tracepoint probes filtered by cgroup id +      │
│  (agentmon)      kernel-audit tail — every exec, open, connect  │
│                  and escape attempt is streamed to you          │
└─────────────────────────────────────────────────────────────────┘
```

## Why

An AI agent with shell access will eventually run something you didn't
expect. Containers help, but they're heavy and their defaults are loose.
AgentCell is the opposite bet: a tiny, readable, unprivileged sandbox
that stacks every relevant kernel isolation mechanism — and an eBPF
audit trail the agent cannot see or disable.

| Primitive | Kernel mechanism | What it stops |
|---|---|---|
| user namespace | `clone(CLONE_NEWUSER)` + uid_map | privilege escalation — in-ns root is your uid outside |
| mount namespace + `pivot_root(2)` | new root on tmpfs, host unmounted | seeing or touching host files |
| PID namespace | `clone(CLONE_NEWPID)` | seeing/killing host processes |
| network namespace (default) | `clone(CLONE_NEWNET)` | network access entirely (loopback only) |
| Landlock | `landlock(2)` rulesets | writes/exec outside allowlisted paths |
| seccomp-BPF | `seccomp(2)` + raw `sock_filter` | kernel attack surface (module ops, bpf, ptrace, new mount API, io_uring, keyring, …) |
| cgroup v2 | `cpu.max`/`memory.max`/`pids.max`/`io.max` | resource exhaustion, fork bombs, disk flooding |
| eBPF tracepoints + audit | `bpf()` with cgroup-id filter | invisibility — every exec/open/connect is audited |

## Build

Requires: `clang` (for eBPF), `libbpf`, `libelf`, `zlib`, `xxd` (vim-common).

```bash
make          # -> sand (launcher, unprivileged) + agentmon (eBPF monitor, root)
```

## Usage

```bash
# interactive shell inside the sandbox
# (default: no network, 60% of RAM, all CPUs, 256 pids)
./sand

# a specific agent with tighter limits
./sand --mem 1G --cpu 1 --pids 64 --timeout 600 -- \
    python3 -c "print('hello from jail')"

# agent that needs network / API access
./sand --net host -- claude

# give it extra views (host paths appear under /mnt/<name>)
./sand --ro ~/Dev/myrepo --rw ~/.cache -- some-agent

# custom mounts at exact in-sandbox paths
./sand --bind-ro ~/.local/share/mise:/mise \
       --bind    ~/.pi:/home/agent/.pi \
       -- /mise/installs/pi/latest/pi/pi
```

Inside the sandbox: workspace is `/home/agent` (rw, `~/agent-work` on the
host), scratch is `/tmp` (tmpfs — RAM speed), full toolchain read-only at
`/usr`, host files don't exist at all.

## Real networking (`--net veth`)

`--net none` gives loopback only; `--net host` shares the host's stack
entirely.  `--net veth` is the middle ground: the cell gets its own
stack with a veth pair and NAT — real outbound networking, no shared
interfaces.

veth pairs and NAT need host root, so this mode is provisioned by the
**agentlsm daemon** (`sudo agentlsm serve`, same one as `--secure`):

```bash
./sand --net veth -- curl -sI https://example.com
# cell side: vethc<i> 10.200.x.2/30, default via 10.200.x.1 (host end)
# host side: vethh<i>, MASQUERADE for 10.200.0.0/16, ip_forward
```

The daemon allocates a /30 per cell out of 10.200.0.0/16, pushes one
end into the cell's netns, and adds the NAT/FORWARD rules once; the
cell configures its own end with plain ioctls (no iproute2 inside).
Everything is reversed when the cell exits (veth deleted, /30 freed)
and when the daemon exits (rules removed, ip_forward restored).
DNS works: `/etc/resolv.conf`'s loopback stub is unreachable from a
netns, so the cell gets systemd-resolved's upstream list instead.

Notes: needs `iproute2` + `iptables` on the host; the cell can reach
the host at the gateway IP (same model as a Docker bridge); without
the daemon, `--net veth` warns and falls back to `--net none`.

## Disposable views (`--overlay`) and disk limits (`--io-*`)

```bash
# copy-on-write view of a directory: the agent reads the real content
# and can "modify" anything its DAC permissions allow — but every
# write lands in a throwaway tmpfs layer; the host dir is never touched
./sand --overlay ~/Dev/myrepo -- risky-agent     # jail sees /mnt/myrepo

# throttle real disk I/O on the workspace device (cgroup v2 io.max)
./sand --io-wbps 8M -- dd if=/dev/zero of=/home/agent/blob bs=1M count=32
```

`--overlay` (repeatable) uses userns overlayfs (kernel >= 5.11):
lower = the host dir, upper/work on the scratch tmpfs.  There is no
whole-root variant on purpose: a filesystem root can be neither bound
nor used as a lowerdir from inside a user namespace (measured: EINVAL
and ENOENT respectively), and DAC would still gate root-owned files —
scoped overlays are the honest version.  They shine for dirs you own:
let the agent edit your repo freely, watch `git status` stay clean.

`--io-rbps`/`--io-wbps` write `io.max` for the block device backing
the workdir (the /tmp tmpfs scratch has no backing device and is never
throttled — only what actually hits the disk).  Needs the `io`
controller delegated to your user slice; most distros delegate only
cpu/memory/pids.  Enable it live (reverts on reboot):

```bash
for f in /sys/fs/cgroup/cgroup.subtree_control \
         /sys/fs/cgroup/user.slice/cgroup.subtree_control \
         /sys/fs/cgroup/user.slice/user-$UID.slice/cgroup.subtree_control; do
    echo +io | sudo tee "$f"
done
```

## Long-running mode (cell server)

Each one-shot sandbox costs ~5 ms to build — negligible for one agent,
 but not for a harness firing dozens of commands per second. Serve mode
sets up all isolation layers **once**, then executes commands on demand:

```bash
# terminal 1: start the cell (prints its socket)
./sand serve --net host
#   sand: serving /run/user/1000/agentcell-1120702.sock ...

# any number of commands, ~2 ms each (vs ~6 ms one-shot; measured 2.7x)
./sand exec /run/user/1000/agentcell-1120702.sock -- bash -c 'ls /usr | wc -l'
echo data | ./sand exec /run/user/1000/agentcell-1120702.sock -- cat
./sand exec /run/user/1000/agentcell-1120702.sock -- python3 script.py
```

Architecture: the supervisor accepts client connections on the host and
**passes the connection fd into the jail with `SCM_RIGHTS`** — data flows
directly between the client and the jailed command, nothing is proxied
through the supervisor. Inside the jail a tiny exec server `fork`s per
command (stdin via memfd, stdout/stderr = the client socket, exit status
trailing the stream). Every layer — seccomp, Landlock, cgroup limits,
PID/net namespaces — applies to each exec'd command. Ctrl-C (or SIGTERM)
cleans up the socket and kills the jail; the socket lives in
`$XDG_RUNTIME_DIR` with mode 0600.

## Ask mode (human-in-the-loop)

`--ask` turns the seccomp deny-list into a question instead of an
EPERM. When the agent calls a blocked syscall (`mount`, `ptrace`,
`bpf`, `unshare`, ...), the syscall parks in the kernel and the
supervisor asks you on `/dev/tty` (the payload's stdio is untouched):

```
[sand-ask] pid 7 requests unshare(0x20000000, 0, 0, ...)
[sand-ask] y=allow once  n=deny (EPERM)  a=always  k=kill payload >
```

- `y` — the kernel executes this one call, still inside the jail's
  namespaces (a tmpfs mount is contained; the other layers still
  apply — e.g. Landlock independently refuses `move_mount`)
- `n` — EPERM, the classic behavior
- `a` — always allow this syscall number for the rest of the run
- `k` — kill the payload

Note that one logical operation can prompt several times: util-linux
`mount` walks the whole new mount API (`fsopen` → `fsconfig` ×2 →
`fsmount` → `move_mount`), one prompt per syscall.

One-shot mode only (not `sand serve`); needs kernel >= 5.0. The
clone-flag mask (`CLONE_NEWUSER`/`CLONE_NEWNET`) stays hard-denied —
approval is by syscall number, not by argument.  Without a
controlling terminal, prompts fall back to deny.

## eBPF audit monitor (root)

> Registered cells are already covered by the **agentlsm daemon's
> unified stream** (`sand lsm -f`) — same probes, no extra process.
> `agentmon` remains for ad-hoc use: watching a cgroup that isn't
> registered with the daemon, and `--audit` (the kernel-audit tail).

```bash
# terminal 1: start a sandbox — note the cgroup it prints
./sand -- claude

# terminal 2: what the agent DOES (exec / open / connect)
sudo ./agentmon --cgroup /sys/fs/cgroup/.../agentcell-<PID>

# terminal 3: what the agent TRIES (seccomp-denied escape attempts)
sudo ./agentmon --audit
```

Sample output:

```
19:02:45 EXEC  bash[1010603]  /usr/bin/unshare
19:02:45 TRIP  unshare[1010603] cgid=15098 blocked syscall: unshare (272)
19:03:13 OPEN  node[920173]    /home/agent/.config/config.json
19:03:15 NET   node[920180]    connect 104.18.7.85:443
```

**Why two sources?** The kernel runs seccomp **before** the sys_enter
tracepoints (verified empirically): a denied syscall never reaches the
eBPF probes. But the filter is installed with `SECCOMP_FILTER_FLAG_LOG`,
so every denial lands in the kernel audit log (`type=1326` records) —
`--audit` tails that stream. Bonus detail it reveals: util-linux `mount`
tries the new mount API (`fsopen`) before `mount(2)`.

## Kernel LSM enforcement (agentlsm, root daemon)

Below seccomp and Landlock there is one more layer: a **BPF LSM program
on `lsm/file_open`** that denies opens in-kernel, per sandbox cgroup,
by path prefix. Unlike Landlock (self-imposed, per-process), it is
imposed from outside and centrally managed — the sandboxed process
cannot see or turn it off.

```bash
# terminal 1: the daemon (once per boot; root)
sudo ./agentlsm serve

# terminal 2: launch a sandbox registered with the daemon.
# --secure denies /etc/shadow + /etc/gshadow by default;
# --deny adds prefixes (as seen INSIDE the sandbox) and implies --secure
./sand --secure -- claude
./sand --deny /mnt/secrets -- claude

# terminal 3: policies + live events, no root needed
./sand lsm        # table of armed policies, resolved to cell names
./sand lsm -f     # unified live stream — the daemon also carries
                  # agentmon's tracepoint probes (registered cells):
                  #   cell-x.sock  EXEC node[123] /usr/bin/node
                  #   cell-x.sock  OPEN node[123] /home/agent/.config
                  #   cell-x.sock  NET  node[123] connect 104.18.7.85:443
                  #   cell-x.sock  TRIP mount[123] blocked syscall mount (165)
                  #   cell-x.sock  DENY node[123] /etc/shadow
./sand lsm -f deny,trip   # only the high-signal classes
                  # (classes: deny,exec,open,net,trip; default all)
                  # TRIP = seccomp-denied escape attempts, seen on
                  # raw_syscalls/sys_exit — seccomp runs before the
                  # entry tracepoints, but its -EPERM return value is
                  # visible on the exit path

# hot policy updates on RUNNING cells — works even on cells that
# were started WITHOUT --secure; effective on the very next open:
./sand lsm deny  agentcell-16514 /mnt/secrets   # unique name prefix ok
./sand lsm allow agentcell-16514 /etc/hostname
./sand lsm reset agentcell-16514                # drop all its rules
```

Cells register on start and unregister on exit; if the daemon is down,
`sand` prints a warning and runs without the LSM layer (fail-open for
availability — mount RO + Landlock still apply).

One-shot debug modes (verified end-to-end):

```bash
sudo ./agentlsm --cgroup /sys/fs/cgroup/.../agentcell-<PID> --deny /etc/shadow
sudo ./agentlsm --any-cgroup --deny /etc/hostname   # no cgroup filter
# decisive test: deny EVERY open in one cell for 1s, kernel-side deadline
sudo ./agentlsm --block-all 1 --cgroup /sys/fs/cgroup/.../agentcell-<PID>
# system-wide variant (--block-all 3 without --cgroup) denies EVERY open
# on the machine for 3s — including your shell, desktop and any agent
# harness. Manual debugging only; `make check` skips it unless
# AGENTCELL_TEST_BLOCK_ALL_GLOBAL=1 is set.
```

`--block-all` denied 121,190 opens in 3s and self-expired within ~1 ms
of schedule — the mechanism used to prove the attach path works when
filtered policies mysteriously "didn't" (they did; the test was wrong).

Trust model: the control socket is 0666 — any local user can register
policy for any cgroup id. Fine on a single-user workstation; needs peer
credentials + an allowlist before multi-user use.

## Testing

```bash
make check
```

Runs `tests/run.sh`: unprivileged launcher / serve / exec tests always
run; the agentmon and agentlsm tiers run when sudo works and skip
cleanly otherwise (agentlsm also needs `bpf` in
`/sys/kernel/security/lsm`). The suite isolates itself in a mktemp
runtime dir and leaves nothing behind. CI runs it on every push
(Ubuntu runner: agentmon tier runs, agentlsm tier skips).

## Measured performance

On an old i5-4210U (2C/4T), Arch kernel 7.1.9:

| workload | bare | sandboxed | overhead |
|---|---|---|---|
| sandbox startup | — | **~5 ms** | — |
| 10M syscalls | 5196 ms | 5343 ms | +2.8% (fixed seccomp cost) |
| static gcc build | 157 ms | 159 ms | +1.3% |
| writes to /tmp (tmpfs) | — | 2.1 GB/s | (SSD: 509 MB/s) |

Memory defaults are chosen for speed: 60% of RAM as `memory.max`
(avoids reclaim storms; measured 11% slowdown when running at the edge)
and a 1G tmpfs scratch.

## Notes & limits

- x86_64 only — Intel and AMD alike (the syscall ABI is per-architecture,
  not per-vendor; numbers are hardcoded in the seccomp filter & probes).
  ARM64 would need its own syscall table + `AUDIT_ARCH_AARCH64`.
- `/etc` is bound read-only and therefore readable (incl. `/etc/shadow` —
  host root can read it anyway; swap to a curated copy if that matters).
- seccomp returns **EPERM** (agent-visible). Switch the deny tail to
  `SECCOMP_RET_KILL_PROCESS` for kill-on-first-trip hardening.
- The monitor needs root (CAP_BPF + CAP_PERFMON). The sandbox never does.
- `clone3` returns ENOSYS (not EPERM) so glibc falls back to `clone(2)`,
  where the `CLONE_NEWUSER`/`CLONE_NEWNET` flag mask applies.

## Ideas to extend

- `--ask` in serve mode (approval flow for long-lived cells)
- per-cell egress policy: netfilter rules on the `vethh*` host ends
- idmapped binds, if the unprivileged idmap story ever settles

## License

MIT — except `src/agentmon.bpf.c` which is GPL-2.0 (kernel-side BPF).
