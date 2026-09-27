# Changelog

All notable changes to the `agentcell` crate and the `sand` / `agentlsm`
binaries. This project adheres to [Semantic Versioning](https://semver.org/).

## 0.2.0 — 2026-09-27

### Added

- `--egress HOST[:PORT]` is **repeatable** (port defaults to 443, up to 16
  entries). `agentlsm` resolves **every A record** of each host and installs
  one ACCEPT per address, so CDN registries with rotating IPs
  (`static.crates.io`, `files.pythonhosted.org`, `registry.npmjs.org`) stay
  reachable. Daemon protocol is now
  `NETUP <pid> EGRESS H1 P1 [EGRESS H2 P2 …]`.
- `--env K=V` (repeatable) and `--env-file PATH` set the cell environment.
  Use the file form (0600) for secrets: argv is visible to other host users.
- `--secret DST=SRC` copies a 0600 host file into the cell's tmpfs; `DST`
  must be under `/tmp`, `/run` or `/var/tmp`.
- `--workdir-size SIZE` backs the workspace (`/home/agent`) with a size-capped
  tmpfs instead of a host bind. A runaway build gets `ENOSPC` instead of
  filling the node disk. Counts against `--mem`.
- C ABI: `agentcell_config.egress_list` (NULL-terminated) for multiple
  destinations; the existing `egress` field still works.
- Rust: `Config::egress` is repeatable (`Vec<String>`) and feeds
  `egress_list`.

### Changed

- `--egress HOST` (no port) is accepted and defaults to 443; the cell's
  `http_proxy`/`https_proxy` are only set when exactly one entry is given.
- `agentlsm` control line buffer grew 256 → 2048 and the `sand` command
  buffer 320 → 1024 to fit multi-host `NETUP` lines.

### Fixed

- `agentlsm` no longer leaks per-cell egress rules when the daemon exits and
  now frees the `/30` bit during cleanup.

### Known limitations

- The egress allowlist is resolved once, at cell start, on the **host's**
  resolver. A cell whose own resolvers return a different CDN anycast set can
  dial an address the firewall does not allow (intermittent `network_denied`).
  Align the resolvers or use a host-side CONNECT proxy.
- `--net veth` without any `--egress` entry still has full NAT (default-deny
  applies only when at least one entry is given).

## 0.1.0 — 2025

- First public crate: unprivileged cell built on user/mount/pid/net/ipc/uts/
  cgroup namespaces, Landlock, seccomp-BPF and cgroup v2, with a Rust wrapper
  over the C ABI.
