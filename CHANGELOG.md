# Changelog

All notable changes to the `agentcell` crate and the `sand` / `agentlsm`
binaries. This project adheres to [Semantic Versioning](https://semver.org/).

## 0.2.2 — 2026-09-28

### Fixed

- `sand` now requires the egress counts in the `NETUP` reply. When egress
  was requested it demands all five fields, `n_hosts == the requested host
  count` and `n_ips > 0`; a pre-0.2.1 daemon — which ignores the `RESOLV`
  token, installs *no* accept rules and still answers `OK <if> <cell>
  <gw>` — no longer reads as success. Mismatches take the existing
  `egress unavailable` path (exit 127, no silent `--net none` fallback).
  The three-field reply is still accepted when no egress was requested.

### Added

- `agentlsm` logs a warning when a veth is built with **no** egress
  allowlist (`WARNING: vethN (pid P) has no egress allowlist — unrestricted
  NAT`). Plain `--net veth` remains real networking with NAT; this only
  makes the situation visible in the journal.
- `AGENTCELL_LSM_SOCK` overrides the daemon control socket path, and
  `tests/stub-agentlsm.c` drives the `NETUP` reply branches without root; the
  new `tests/run.sh` cases cover the old/short/zero-address replies and show
  the 0.2.1 reply is still accepted.

## 0.2.1 — 2026-09-27

### Fixed

- Egress now resolves against the **cell's** nameservers. `sand` sends them
  in `NETUP … RESOLV <addr>[:port] …` (parsed from systemd-resolved's
  upstream list that it bind-mounts into the cell), and `agentlsm` resolves
  each host with `res_nquery` against those servers instead of the host
  stub. This removes the resolver skew that made the allowlist miss the
  address the cell dials.
- Egress addresses are **refreshed on the record TTL** (capped at 60 s)
  while the cell lives, so CDNs that rotate addresses within one resolver
  stay reachable. A transient refresh failure keeps the last good set.
- Egress failures are loud: the daemon replies `ERR egress_unresolved
  <host>` / `egress_too_many_ips` / `egress_too_many_hosts` (rolls back the
  veth), and `sand` exits nonzero with `egress unavailable: <reason>`
  instead of silently falling back to `--net none` when egress was
  requested. The success reply now carries host/address counts.
- `ERR line_too_long` is returned instead of silently discarding an
  over-long control line; the `NETUP` builder no longer truncates (and
  fails instead), and the control buffers were enlarged.

### Added

- `sand --capabilities` prints the feature flags (`egress_multi`,
  `egress_refresh`, `egress_resolv`, `env`, `env_file`, `secret`,
  `workdir_size`) for hosts to gate on.
- `--egress` validation rejects empty/whitespace hosts, IPv6 literals
  (unsupported by the AF_INET rules) and duplicates.

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
