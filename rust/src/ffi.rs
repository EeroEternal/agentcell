//! Raw C ABI (`agentcell.h`). Linux only.
//!
//! Prefer the safe wrappers on [`crate::Config`]. These bindings exist for
//! hosts that want to drive `libagentcell` themselves (e.g. Keel).
//!
//! # Safety
//!
//! `agentcell_spawn` is **not thread-safe**. Serialize it (and
//! `agentcell_release`) across the process. `argv` / `envp` strings must
//! remain valid until the jailed process has `execve`'d — keep them alive
//! until after `waitpid`.

#![allow(non_camel_case_types)]

use libc::{c_char, c_int, pid_t};

pub const AGENTCELL_NET_NONE: c_int = 0;
pub const AGENTCELL_NET_HOST: c_int = 1;
pub const AGENTCELL_NET_VETH: c_int = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct agentcell_config {
    pub workdir: *const c_char,
    pub rootfs: *const c_char,
    pub mem_bytes: u64,
    pub cpu_cores: f64,
    pub pids: u32,
    pub net: c_int,
    pub egress: *const c_char,
    pub secure: c_int,
    pub no_landlock: c_int,
    pub no_seccomp: c_int,
}

impl Default for agentcell_config {
    fn default() -> Self {
        Self {
            workdir: std::ptr::null(),
            rootfs: std::ptr::null(),
            mem_bytes: 0,
            cpu_cores: 0.0,
            pids: 0,
            net: AGENTCELL_NET_NONE,
            egress: std::ptr::null(),
            secure: 0,
            no_landlock: 0,
            no_seccomp: 0,
        }
    }
}

extern "C" {
    pub fn agentcell_spawn(
        cfg: *const agentcell_config,
        argv: *const *const c_char,
        envp: *const *const c_char,
        stdin_fd: c_int,
        stdout_fd: c_int,
        stderr_fd: c_int,
        out_pid: *mut pid_t,
    ) -> c_int;

    pub fn agentcell_release(pid: pid_t) -> c_int;

    pub fn agentcell_version() -> *const c_char;
}
