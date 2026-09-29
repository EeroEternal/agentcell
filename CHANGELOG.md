# Changelog

All notable changes to the `agentcell` crate and the `sand` / `agentlsm`
binaries. This project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Fixed

- Every iptables rule that mentions a veth interface failed to install:
  `egress_base` and `egress_accept` interpolated their op string
  ("-I FORWARD 1" / "-D FORWARD") into a format that already contained the
  chain name, producing `iptables -I FORWARD 1 FORWARD ...` — shell error,
  swallowed by `2>/dev/null`. Egress allowlists were therefore always empty
  (and teardown never removed anything). Found by the v0.2.3 certification
  run on a real node (#7); only the contract-stub tests ran before.
- `net_recover_startup`'s stale-link scrub was a shell syntax error (missing
  `;` before `done`), so leftover `vethh*` links from a crashed daemon were
  never removed and the "removed stale" journal line never appeared.
- Literal-IP egress hosts (`--egress 1.1.1.1:443`) are no longer sent to
  DNS. On nodes behind a fake-ip TUN proxy every A query — including for a
  numeric name — answers with a 198.18.0.0/15 address, so the allowlist was
  built for an address the cell never dials; literals are now used as-is
  and never age into the refresh loop.
- A literal-IP-only allowlist no longer needs the cell to send `RESOLV`:
  `egress_no_resolv` now only fires when a *hostname* would have to be
  resolved, so `--egress 1.1.1.1:443` from a cell with no nameservers is
  accepted instead of refused.
- A NETUP whose `iptables -I` fails for any requested address now replies
  `ERR egress_install_failed` and rolls back (base rules and any installed
  ACCEPTs), instead of `OK` with a partially-installed, silently
  under-blocking allowlist.
- `tests/run.sh` (privileged tier) asserts the per-cell `DROP` and the
  allowlist `ACCEPT` are actually present in `iptables -S FORWARD` while an
  allowlisted cell is alive, and removed on teardown — the reachability
  assertions alone passed while no rule was installed (the historical bug).

## 0.2.3 — 2026-09-29

### Fixed

- `agentlsm serve` now honors its own NETUP error contract: a failed NETUP
  no longer overwrites the specific `ERR egress_unresolved <host>` /
  `ERR egress_too_many_ips` replies with a generic `ERR netup`, so clients
  finally see *why* egress provisioning failed.
- A crashed/restarted daemon no longer leaks state into new cells. On
  startup (and when a NETUP recycles a veth index whose stale link survived
  a crash) it removes leftover `vethh*` pairs and every iptables rule that
  mentions them — previously the previous cell's per-IP ACCEPT rules
  survived the crash and silently grafted its allowlist onto the next cell
  using that index. Leftover global NAT rules are cleaned up too.
- `egress_apply` no longer counts a rule that `iptables -I` failed to
  install; the NETUP reply's address count is now the truth, and failures
  are logged per rule.
- Egress resolution is bounded (1 s per nameserver attempt) instead of the
  resolver defaults; NETUP and the TTL refresh run inline in the serve
  loop, and the old defaults could stall every control client for minutes
  when a nameserver was unreachable.
- An over-long control line no longer desynchronizes the protocol: after
  `ERR line_too_long`, the daemon drains the rest of the offending line
  instead of parsing its tail as new commands.
- `agentlsm serve` takes an exclusive lock (`/run/agentcell/agentlsm.lock`)
  and refuses to start a second instance. Startup recovery deletes every
  `vethh*` rule it finds, which would otherwise destroy a live daemon's
  cells; the lock is released on process death, so a crash does not lock
  out the next start.
- `net.ipv4.ip_forward` is restored even after a crash: the pre-daemon
  value is persisted to `/run/agentcell/ip_forward.saved` when NAT is
  enabled and consumed by startup recovery when a previous run died before
  `nat_teardown()`.
- Egress no longer falls back to `getaddrinfo()` on the host stub.  A
  NETUP that asks for egress but carries no `RESOLV` is refused with
  `ERR egress_no_resolv`, and a nameserver that answers nothing yields
  `egress_unresolved` — so an old `sand` (or a cell with no resolvers)
  fails loudly instead of silently resolving with the host's view.
- `egress_no_resolv` is covered by `tests/contract_test`.

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
