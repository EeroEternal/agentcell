# agentcell

[![crates.io](https://img.shields.io/crates/v/agentcell.svg)](https://crates.io/crates/agentcell)
[![docs.rs](https://docs.rs/agentcell/badge.svg)](https://docs.rs/agentcell)

Rust bindings for [AgentCell](https://github.com/EeroEternal/agentcell) — an
unprivileged Linux sandbox built on kernel primitives (user/mount/pid/net
namespaces, Landlock, seccomp-BPF, cgroup v2). No Docker, no daemon for the
common path.

**Linux only** (`x86_64` and `aarch64`). The crate compiles on other OSes so
workspaces can depend on it; `spawn` returns `Error::Unsupported` there.

## Install

```toml
[dependencies]
agentcell = "0.1"
```

## Usage

```rust
use agentcell::{Config, Stdio};

fn main() -> agentcell::Result<()> {
    let output = Config::new()
        .mem_bytes(512 * 1024 * 1024)
        .cpu_cores(1.0)
        .pids(32)
        .stdout(Stdio::Piped)
        .stderr(Stdio::Piped)
        .spawn(["sh", "-c", "echo hi-from-rust; id -u; exit 7"])?
        .wait_with_output()?;

    assert_eq!(output.status.code(), Some(7));
    Ok(())
}
```

`Config` maps 1:1 onto the C ABI in `agentcell.h`:

| method | C field | default |
|---|---|---|
| `workdir` | `workdir` | `~/agent-work` |
| `rootfs` | `rootfs` | live `/usr` `/etc` `/opt` |
| `mem_bytes` | `mem_bytes` | 60% of RAM |
| `cpu_cores` | `cpu_cores` | host default quota |
| `pids` | `pids` | 256 |
| `net` | `net` | loopback only |
| `egress` | `egress` | off (`HOST:PORT` allowlist) |
| `secure` | `secure` | off (`agentlsm` extra denies) |

Raw FFI is under `agentcell::ffi` (Linux) if you want to drive `libagentcell`
yourself.

## Limits

- Spawns are **not thread-safe** in the C library. This crate serializes
  `spawn` / `release` with a process-wide mutex.
- At most **16** live cells per process; wait or drop one before spawning more.
- Needs unprivileged user namespaces (`kernel.unprivileged_userns_clone=1`).
  On Ubuntu 24.04 also `kernel.apparmor_restrict_unprivileged_userns=0` or the
  packaged AppArmor profile.
- `agentlsm` (root, eBPF LSM) is optional and only required for `--secure` /
  `--egress` / `Net::Veth`.

## License

MIT. The in-tree eBPF monitors (`agentmon` / `agentlsm`) are GPL-2.0 and are
**not** linked by this crate.
