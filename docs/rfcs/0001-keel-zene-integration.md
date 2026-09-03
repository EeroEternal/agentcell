# RFC 0001: Harmonizing AgentCell for Agent Host Integrations (Keel & Zene)

- **Status**: Proposed
- **Author**: EeroEternal / Zene & Keel Development Team
- **Created**: 2026-09-03
- **Targets**: `agentcell` core (`src/sand.c`, `src/agentmon.bpf.c`, `src/agentlsm.bpf.c`), Keel (`keel-enforce`), and Zene (`crates/sandbox`).

---

## 1. Context & Motivation

[AgentCell](https://github.com/EeroEternal/agentcell) provides an unprivileged, raw Linux primitive sandbox (namespaces, Landlock, Seccomp-BPF, cgroup v2, and eBPF LSM/tracepoints) with sub-5ms cold startup and kernel-level non-bypassable guarantees.

[Keel](https://github.com/EeroEternal/keel) (`eero-keel-core`) provides the execution gate and policy lifecycle under AI coding agents (such as [Zene](https://github.com/ParaTensor/zene)).

During live integration testing on production cloud nodes (GCP Ubuntu 24.04 LTS x86_64) and architectural review with Zene's runtime engine, **AgentCell proved extraordinarily effective at kernel containment (PID hiding, mount tree isolation, seccomp trip interception, and eBPF audit recording)**. However, several friction points and interface gaps currently hinder seamless, production-grade adoption as a drop-in execution backend for Keel and Zene.

This RFC outlines the requirements, architectural adjustments, and proposed changes to `agentcell` to facilitate first-class integration into Keel and Zene.

---

## 2. Friction Points & Gap Analysis

### Gap 1: Architecture Limitation (x86_64 only)
- **Current State**: `src/sand.c` and `src/agentmon.bpf.c` hardcode x86_64 syscall numbers (e.g. `__NR_mount 165`, `__NR_unshare 272`, `__NR_clone 56`, `AUDIT_ARCH_X86_64`).
- **Impact**: AI Agent developers heavily utilize Apple Silicon (M-series, ARM64) for local development, and modern cloud providers deploy cost-effective AArch64 instances (AWS Graviton, GCP Tau T2A). Currently, AgentCell cannot build or run on ARM64.
- **Requirement**: Abstract syscall definitions into architecture-specific header tables (`arch/x86_64.h` and `arch/aarch64.h`), parameterizing the BPF seccomp filter and tracepoint probes by architecture.

### Gap 2: Interactive Process & Duplex Stdio Streaming (MCP Servers)
- **Current State**: AgentCell is designed primarily around a batch, run-to-completion model (`sand -- <cmd>` or `POST /api/cells/<id>/exec`).
- **Impact**:
  - Coding agents require **long-running interactive processes** (e.g., persistent test servers, REPLs, or processes requiring interactive stdin confirmation).
  - Crucially, AI agent runtimes host **Model Context Protocol (MCP)** servers, which communicate continuously over standard I/O pipes (`stdin`/`stdout`) via JSON-RPC. A batch-oriented execution API cannot sustain persistent duplex streams without process exit.
- **Requirement**: Provide a continuous duplex streaming protocol over Unix domain sockets for `sand serve` (or an interactive mode in `sand` exposing separate unbuffered stdin/stdout/stderr pipes with PID management).

### Gap 3: Fine-Grained Domain-Level Network Egress Filtering
- **Current State**: Network policy is binary: either `--net none` (only isolated loopback) or `--net host` (full host network access).
- **Impact**: Real-world agents require selective outbound network access (e.g., allow `https://api.openai.com` and `https://github.com`, but deny access to cloud metadata services `169.254.169.254` and VPC internal ranges `10.0.0.0/8`).
- **Requirement**:
  - Support an integrated HTTP/TLS transparent egress proxy bridge (or `--net veth` with preconfigured host-side iptables/nftables egress allowlists).
  - Allow passing an optional `--egress-proxy <HOST:PORT>` that configures internal `http_proxy`/`https_proxy` or redirects port 80/443 traffic to Keel's local proxy.

### Gap 4: Ubuntu 24.04 AppArmor User Namespace Restrictions
- **Current State**: On modern distributions like Ubuntu 24.04 LTS, `kernel.apparmor_restrict_unprivileged_userns = 1` blocks unprivileged `clone(CLONE_NEWUSER)` mount operations unless an AppArmor profile permits it.
- **Impact**: Running `./sand` out-of-the-box on Ubuntu 24.04 fails with `sand: make mounts private: Permission denied`.
- **Requirement**:
  - Provide an official, installable AppArmor profile (`packaging/apparmor/sand`) allowing the unprivileged userns mount permissions.
  - Document the operational setup and graceful detection in `sand` diagnostics.

### Gap 5: Clean C ABI / FFI Library Target for Direct Rust Linking
- **Current State**: AgentCell is strictly a CLI binary (`sand`). Integrating with Keel currently requires spawning `sand` as a subprocess (`tokio::process::Command::new("sand")`), incurring fork-exec parsing overhead and complex signal translation.
- **Requirement**: Refactor `src/sand.c` into a reusable shared/static library (`libagentcell.a` / `agentcell.h`), enabling `keel-enforce` to link directly via Rust FFI (`agentcell-sys`).

---

## 3. Detailed Technical Proposals

### Proposal A: Syscall Architecture Abstraction
Structure syscall tables by target architecture:

```text
src/
├── arch/
│   ├── x86_64.h   # __NR_*, AUDIT_ARCH_X86_64, arg register offsets
│   └── aarch64.h  # __NR_*, AUDIT_ARCH_AARCH64, arg register offsets
├── sand.c
└── ...
```

In `src/sand.c`:
```c
#if defined(__x86_64__)
#include "arch/x86_64.h"
#elif defined(__aarch64__)
#include "arch/aarch64.h"
#else
#error "Unsupported architecture: AgentCell currently supports x86_64 and aarch64"
#endif
```

### Proposal B: Duplex Stream Protocol for `sand serve`
Extend the Unix domain socket protocol to support persistent sessions:

1. `POST /api/cells/<id>/spawn_interactive`
   - Spawns process within namespace.
   - Upgrades socket or returns a dedicated framing channel (stdin stream / stdout stream / stderr stream).
   - Keeps process running until explicit termination or EOF.
2. Supports signal delivery (`POST /api/cells/<id>/signal { "signal": 15 }`).

### Proposal C: AppArmor Profile for Modern Ubuntu
Add `packaging/apparmor/usr.bin.sand`:
```apparmor
abi <abi/4.0>,
include <tunables/global>

profile sand /usr/bin/sand flags=(unconfined) {
  userns,
  mount,
  pivot_root,
  include if exists <local/sand>
}
```
Add `make install-apparmor` target to automatically stage and load the profile.

### Proposal D: Zero-Overhead FFI Surface for Keel
Expose a core C API:
```c
struct agentcell_config {
    const char *workdir;
    const char *rootfs;
    const char *deny_paths[64];
    size_t deny_count;
    uint64_t memory_limit_bytes;
    uint32_t cpu_limit_pct;
    uint32_t pids_limit;
    int net_mode; // 0 = none, 1 = host, 2 = proxy
    const char *proxy_addr;
};

int agentcell_spawn(const struct agentcell_config *cfg, 
                    const char *argv[], 
                    const char *envp[],
                    int stdin_fd, 
                    int stdout_fd, 
                    int stderr_fd, 
                    pid_t *out_pid);
```

---

## 4. Integration Roadmap with Keel & Zene

1. **Phase 1 (Immediate)**:
   - Provide Ubuntu 24.04 AppArmor profile and documentation.
   - Keel implements `AgentCellBackend` utilizing `sand` CLI in subprocess mode.
2. **Phase 2 (Cross-Platform / ARM64)**:
   - Add AArch64 syscall definitions to Seccomp-BPF and eBPF probes.
   - Enable CI verification on ARM64 Linux runners.
3. **Phase 3 (Interactive & Library Embedding)**:
   - Expose `libagentcell` C ABI.
   - Create `crates/keel-enforce/src/agentcell.rs` linking directly via FFI.
   - Support bidirectional stdio streaming for MCP and interactive commands.

---

## 5. Conclusion

Addressing these requirements transforms AgentCell from an independent, standalone CLI experiment into the **gold-standard execution runtime for next-generation AI agent architectures (Keel and Zene)**.
