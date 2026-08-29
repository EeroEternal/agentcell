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
│  1. cgroup v2     cpu.max / memory.max / pids.max               │
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
| cgroup v2 | `cpu.max`/`memory.max`/`pids.max` | resource exhaustion, fork bombs |
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

## eBPF audit monitor (root)

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

- x86_64 only (syscall numbers hardcoded in the seccomp filter & probes).
- `/etc` is bound read-only and therefore readable (incl. `/etc/shadow` —
  host root can read it anyway; swap to a curated copy if that matters).
- seccomp returns **EPERM** (agent-visible). Switch the deny tail to
  `SECCOMP_RET_KILL_PROCESS` for kill-on-first-trip hardening.
- The monitor needs root (CAP_BPF + CAP_PERFMON). The sandbox never does.
- `clone3` returns ENOSYS (not EPERM) so glibc falls back to `clone(2)`,
  where the `CLONE_NEWUSER`/`CLONE_NEWNET` flag mask applies.

## Ideas to extend

- **seccomp user-notify** (`SECCOMP_FILTER_FLAG_USER_LISTENER`): a
  supervisor approves syscalls per-call — "ask permission" flows.
- **BPF LSM hooks** (needs `bpf` in the LSM list): enforce policy
  in-kernel on `file_open` / `bprm_check_security` instead of auditing.
- **veth + NAT** for real (non-host-shared) network access.
- **long-lived cell**: keep one sandbox alive, stream commands over a
  unix socket, amortize all setup cost to zero.
- `io.max` for disk rate limiting; overlayfs upperdir for disposable roots.

## License

MIT — except `src/agentmon.bpf.c` which is GPL-2.0 (kernel-side BPF).
