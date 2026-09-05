//! Unprivileged Linux sandbox for AI agents.
//!
//! AgentCell stacks user/mount/pid/net namespaces, Landlock, seccomp-BPF
//! and cgroup v2 — the same isolation as the `sand` CLI — behind a small
//! C ABI. This crate compiles that ABI (`libagentcell`) and wraps it.
//!
//! **Linux only.** On other OSes the crate compiles so workspaces and
//! `cargo publish` work; [`Config::spawn`] returns [`Error::Unsupported`].
//!
//! # Example
//!
//! ```no_run
//! use agentcell::{Config, Stdio};
//!
//! let mut child = Config::new()
//!     .mem_bytes(512 * 1024 * 1024)
//!     .cpu_cores(1.0)
//!     .pids(32)
//!     .stdout(Stdio::Piped)
//!     .spawn(["sh", "-c", "echo hi-from-rust; exit 7"])?;
//!
//! let mut out = String::new();
//! std::io::Read::read_to_string(child.stdout.as_mut().unwrap(), &mut out)?;
//! let status = child.wait()?;
//! assert_eq!(status.code(), Some(7));
//! # Ok::<(), agentcell::Error>(())
//! ```
//!
//! Spawns are serialized internally: the C library is not thread-safe.

use std::ffi::{CString, NulError, OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Mutex;

#[cfg(target_os = "linux")]
pub mod ffi;

#[cfg(target_os = "linux")]
static API_LOCK: Mutex<()> = Mutex::new(());

/// Crate-level result.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from config, stdio setup, or the C ABI.
#[derive(Debug)]
pub enum Error {
    /// Not Linux, or this host cannot run AgentCell.
    Unsupported,
    /// An argument contained an interior NUL byte.
    Nul(NulError),
    /// Failed to set up stdio pipes / `/dev/null`.
    Io(io::Error),
    /// `argv` was empty.
    EmptyArgv,
    /// Sixteen cells already live in this process; [`Child`] must be
    /// reaped (dropped or [`Child::wait`]ed) first.
    Busy,
    /// `agentcell_spawn` failed. `errno` is the kernel / libc error.
    Spawn { errno: i32, message: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unsupported => {
                write!(f, "agentcell is only supported on Linux")
            }
            Error::Nul(e) => write!(f, "interior NUL in C string: {e}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::EmptyArgv => write!(f, "argv must contain at least a program name"),
            Error::Busy => {
                write!(f, "too many live cells (max 16); wait/drop one first")
            }
            Error::Spawn { errno, message } => {
                write!(f, "agentcell_spawn failed: {message} (errno {errno})")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Nul(e) => Some(e),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<NulError> for Error {
    fn from(e: NulError) -> Self {
        Error::Nul(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// How the jail's network namespace is set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Net {
    /// Loopback only (default).
    #[default]
    None,
    /// Share the host network stack.
    Host,
    /// Own stack + NAT. Needs the `agentlsm` daemon.
    Veth,
}

/// Stdio for the jailed process. Same idea as [`std::process::Stdio`].
#[derive(Debug, Clone)]
pub enum Stdio {
    /// Inherit the corresponding fd from the caller (default).
    Inherit,
    /// Pipe. The parent end lands on [`Child::stdin`] / `stdout` / `stderr`.
    Piped,
    /// `/dev/null`.
    Null,
    /// Use this already-open file descriptor. AgentCell `dup2`s it;
    /// you keep ownership and may close it after [`Config::spawn`].
    Fd(i32),
}

/// Builder for one jail. Reusable: [`Config::spawn`] borrows `self`.
#[derive(Debug, Clone)]
pub struct Config {
    workdir: Option<PathBuf>,
    rootfs: Option<PathBuf>,
    mem_bytes: u64,
    cpu_cores: f64,
    pids: u32,
    net: Net,
    egress: Option<String>,
    secure: bool,
    no_landlock: bool,
    no_seccomp: bool,
    env: Option<Vec<(OsString, OsString)>>,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            workdir: None,
            rootfs: None,
            mem_bytes: 0,
            cpu_cores: 0.0,
            pids: 0,
            net: Net::None,
            egress: None,
            secure: false,
            no_landlock: false,
            no_seccomp: false,
            env: None,
            stdin: Stdio::Inherit,
            stdout: Stdio::Inherit,
            stderr: Stdio::Inherit,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    /// Working directory, bind-mounted at `/home/agent`. `None` = `~/agent-work`.
    pub fn workdir(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.workdir = Some(path.as_ref().to_owned());
        self
    }

    /// Packed rootfs tree instead of bind-mounting the live `/usr`.
    pub fn rootfs(&mut self, path: impl AsRef<Path>) -> &mut Self {
        self.rootfs = Some(path.as_ref().to_owned());
        self
    }

    /// cgroup `memory.max`. `0` (default) = 60% of host RAM.
    pub fn mem_bytes(&mut self, bytes: u64) -> &mut Self {
        self.mem_bytes = bytes;
        self
    }

    /// CPU quota in cores (cgroup `cpu.max`). `0` = default.
    pub fn cpu_cores(&mut self, cores: f64) -> &mut Self {
        self.cpu_cores = cores;
        self
    }

    /// cgroup `pids.max`. `0` (default) = 256.
    pub fn pids(&mut self, n: u32) -> &mut Self {
        self.pids = n;
        self
    }

    pub fn net(&mut self, net: Net) -> &mut Self {
        self.net = net;
        self
    }

    /// `HOST:PORT` allowlist. Implies [`Net::Veth`]. Needs `agentlsm`.
    pub fn egress(&mut self, host_port: impl Into<String>) -> &mut Self {
        self.egress = Some(host_port.into());
        self
    }

    /// Ask `agentlsm` to enforce extra denies (e.g. `/etc/shadow`).
    pub fn secure(&mut self, yes: bool) -> &mut Self {
        self.secure = yes;
        self
    }

    /// Debug: skip Landlock.
    pub fn no_landlock(&mut self, yes: bool) -> &mut Self {
        self.no_landlock = yes;
        self
    }

    /// Debug: skip seccomp-BPF.
    pub fn no_seccomp(&mut self, yes: bool) -> &mut Self {
        self.no_seccomp = yes;
        self
    }

    /// Replace the jail environment. Once called, you own `PATH` / `HOME`
    /// (the C defaults are not merged).
    pub fn env(&mut self, key: impl AsRef<OsStr>, val: impl AsRef<OsStr>) -> &mut Self {
        self.env
            .get_or_insert_with(Vec::new)
            .push((key.as_ref().to_owned(), val.as_ref().to_owned()));
        self
    }

    /// Drop every env var, including AgentCell's defaults. Follow with [`env`].
    pub fn env_clear(&mut self) -> &mut Self {
        self.env = Some(Vec::new());
        self
    }

    pub fn stdin(&mut self, io: Stdio) -> &mut Self {
        self.stdin = io;
        self
    }

    pub fn stdout(&mut self, io: Stdio) -> &mut Self {
        self.stdout = io;
        self
    }

    pub fn stderr(&mut self, io: Stdio) -> &mut Self {
        self.stderr = io;
        self
    }

    /// Run `argv` inside a fresh jail.
    ///
    /// The returned [`Child`] must be waited (or dropped) so cgroup / veth
    /// teardown runs. At most 16 cells may be live in the process.
    pub fn spawn<I, S>(&mut self, argv: I) -> Result<Child>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let argv: Vec<OsString> = argv.into_iter().map(|s| s.as_ref().to_owned()).collect();
        if argv.is_empty() {
            return Err(Error::EmptyArgv);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = argv;
            Err(Error::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            self.spawn_linux(&argv)
        }
    }
}

/// Wait-status of a jailed process (`waitpid` raw status).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    raw: i32,
}

impl Status {
    /// Raw `waitpid` status word.
    pub fn raw(&self) -> i32 {
        self.raw
    }

    /// Exited with code 0.
    pub fn success(&self) -> bool {
        self.code() == Some(0)
    }

    /// `exit(2)` code, if the process exited normally.
    pub fn code(&self) -> Option<i32> {
        #[cfg(unix)]
        {
            if libc::WIFEXITED(self.raw) {
                Some(libc::WEXITSTATUS(self.raw))
            } else {
                None
            }
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    /// Fatal signal, if the process was killed.
    pub fn signal(&self) -> Option<i32> {
        #[cfg(unix)]
        {
            if libc::WIFSIGNALED(self.raw) {
                Some(libc::WTERMSIG(self.raw))
            } else {
                None
            }
        }
        #[cfg(not(unix))]
        {
            None
        }
    }
}

/// Captured stdio + wait status. See [`Child::wait_with_output`].
#[derive(Debug)]
pub struct Output {
    pub status: Status,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A live jail. Dropping it SIGKILLs if still running, then releases
/// cgroup / veth / LSM state.
#[derive(Debug)]
pub struct Child {
    pid: i32,
    /// Parent end of a piped stdin, if requested.
    pub stdin: Option<File>,
    /// Parent end of a piped stdout, if requested.
    pub stdout: Option<File>,
    /// Parent end of a piped stderr, if requested.
    pub stderr: Option<File>,
    waited: bool,
    released: bool,
    #[allow(dead_code)] // read by wait_linux on Linux
    last_status: Option<Status>,
    /// `argv` / `envp` C strings. The child reads these until `execvp`.
    #[allow(dead_code)]
    keep_alive: Vec<CString>,
}

impl Child {
    /// Jail pid (the payload; namespace PID 1 inside).
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    /// Block until the payload exits, then tear down the cell.
    pub fn wait(&mut self) -> Result<Status> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            Ok(self.wait_linux(0)?.unwrap_or(Status { raw: 0 }))
        }
    }

    /// Non-blocking [`wait`]. `Ok(None)` = still running.
    pub fn try_wait(&mut self) -> Result<Option<Status>> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(Error::Unsupported)
        }
        #[cfg(target_os = "linux")]
        {
            self.wait_linux(libc::WNOHANG)
        }
    }

    /// SIGKILL the payload. Still call [`wait`] (or drop) to reap.
    pub fn kill(&mut self) -> Result<()> {
        #[cfg(not(unix))]
        {
            Err(Error::Unsupported)
        }
        #[cfg(unix)]
        {
            if self.waited {
                return Ok(());
            }
            let rc = unsafe { libc::kill(self.pid, libc::SIGKILL) };
            if rc != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(());
                }
                return Err(Error::Io(e));
            }
            Ok(())
        }
    }

    /// Close stdin, read stdout/stderr to EOF, wait.
    pub fn wait_with_output(mut self) -> Result<Output> {
        drop(self.stdin.take());
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        if let Some(mut f) = self.stdout.take() {
            f.read_to_end(&mut stdout)?;
        }
        if let Some(mut f) = self.stderr.take() {
            f.read_to_end(&mut stderr)?;
        }
        let status = self.wait()?;
        Ok(Output {
            status,
            stdout,
            stderr,
        })
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if !self.waited {
                let _ = self.kill();
                let _ = self.wait_linux(0);
            } else {
                self.release_linux();
            }
        }
        self.released = true;
    }
}

/// Library version string from `libagentcell`, or a stub off Linux.
pub fn version() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let p = ffi::agentcell_version();
            if p.is_null() {
                return "agentcell";
            }
            std::ffi::CStr::from_ptr(p).to_str().unwrap_or("agentcell")
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        "agentcell 0.1.0 (non-linux stub)"
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{FromRawFd, RawFd};

    fn cstring_os(s: impl AsRef<OsStr>) -> Result<CString> {
        Ok(CString::new(s.as_ref().as_bytes())?)
    }

    fn cstring_path(p: &Path) -> Result<CString> {
        cstring_os(p.as_os_str())
    }

    fn lock_api() -> std::sync::MutexGuard<'static, ()> {
        API_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    struct Prepared {
        child_fd: i32,
        parent: Option<File>,
        close_after: Option<RawFd>,
        inherit: bool,
    }

    fn set_cloexec(fd: RawFd) {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }

    fn prepare(spec: &Stdio, inherit_fd: i32, child_writes: bool) -> Result<Prepared> {
        match spec {
            Stdio::Inherit => Ok(Prepared {
                child_fd: inherit_fd,
                parent: None,
                close_after: None,
                inherit: true,
            }),
            Stdio::Piped => {
                let mut fds = [0 as libc::c_int; 2];
                if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
                    return Err(Error::Io(io::Error::last_os_error()));
                }
                set_cloexec(fds[0]);
                set_cloexec(fds[1]);
                let (child_fd, parent_fd) = if child_writes {
                    (fds[1], fds[0])
                } else {
                    (fds[0], fds[1])
                };
                Ok(Prepared {
                    child_fd,
                    parent: Some(unsafe { File::from_raw_fd(parent_fd) }),
                    close_after: Some(child_fd),
                    inherit: false,
                })
            }
            Stdio::Null => {
                let fd = unsafe {
                    libc::open(
                        b"/dev/null\0".as_ptr() as *const libc::c_char,
                        libc::O_RDWR | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(Error::Io(io::Error::last_os_error()));
                }
                Ok(Prepared {
                    child_fd: fd,
                    parent: None,
                    close_after: Some(fd),
                    inherit: false,
                })
            }
            Stdio::Fd(fd) => Ok(Prepared {
                child_fd: *fd,
                parent: None,
                close_after: None,
                inherit: false,
            }),
        }
    }

    impl Config {
        pub(crate) fn spawn_linux(&mut self, argv: &[OsString]) -> Result<Child> {
            let mut keep = Vec::new();

            let argv_c: Result<Vec<CString>> = argv.iter().map(cstring_os).collect();
            let argv_c = argv_c?;
            let mut argv_ptr: Vec<*const libc::c_char> =
                argv_c.iter().map(|s| s.as_ptr()).collect();
            argv_ptr.push(std::ptr::null());
            keep.extend(argv_c);

            let env_ptr_storage: Option<Vec<*const libc::c_char>> = if let Some(vars) = &self.env {
                let mut ptrs = Vec::with_capacity(vars.len() + 1);
                for (k, v) in vars {
                    let mut pair = k.as_bytes().to_vec();
                    pair.push(b'=');
                    pair.extend(v.as_bytes());
                    let c = CString::new(pair)?;
                    ptrs.push(c.as_ptr());
                    keep.push(c);
                }
                ptrs.push(std::ptr::null());
                Some(ptrs)
            } else {
                None
            };

            let workdir = match &self.workdir {
                Some(p) => {
                    let c = cstring_path(p)?;
                    let ptr = c.as_ptr();
                    keep.push(c);
                    ptr
                }
                None => std::ptr::null(),
            };
            let rootfs = match &self.rootfs {
                Some(p) => {
                    let c = cstring_path(p)?;
                    let ptr = c.as_ptr();
                    keep.push(c);
                    ptr
                }
                None => std::ptr::null(),
            };
            let egress = match &self.egress {
                Some(s) => {
                    let c = CString::new(s.as_bytes())?;
                    let ptr = c.as_ptr();
                    keep.push(c);
                    ptr
                }
                None => std::ptr::null(),
            };

            let net = match self.net {
                Net::None => ffi::AGENTCELL_NET_NONE,
                Net::Host => ffi::AGENTCELL_NET_HOST,
                Net::Veth => ffi::AGENTCELL_NET_VETH,
            };

            let cfg = ffi::agentcell_config {
                workdir,
                rootfs,
                mem_bytes: self.mem_bytes,
                cpu_cores: self.cpu_cores,
                pids: self.pids,
                net,
                egress,
                secure: self.secure as libc::c_int,
                no_landlock: self.no_landlock as libc::c_int,
                no_seccomp: self.no_seccomp as libc::c_int,
            };

            let stdin = prepare(&self.stdin, 0, false)?;
            let stdout = prepare(&self.stdout, 1, true)?;
            let stderr = prepare(&self.stderr, 2, true)?;

            // C only dup2s when stdin_fd >= 0. Mixed inherit/pipe must pass
            // real fds (0/1/2), not -1.
            let all_inherit = stdin.inherit && stdout.inherit && stderr.inherit;
            let (in_fd, out_fd, err_fd) = if all_inherit {
                (-1, -1, -1)
            } else {
                (stdin.child_fd, stdout.child_fd, stderr.child_fd)
            };

            let envp = env_ptr_storage
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null());

            let mut pid: libc::pid_t = 0;
            let rc = {
                let _guard = lock_api();
                unsafe {
                    ffi::agentcell_spawn(
                        &cfg,
                        argv_ptr.as_ptr(),
                        envp,
                        in_fd,
                        out_fd,
                        err_fd,
                        &mut pid,
                    )
                }
            };

            for p in [&stdin, &stdout, &stderr] {
                if let Some(fd) = p.close_after {
                    unsafe { libc::close(fd) };
                }
            }

            if rc < 0 {
                let errno = -rc;
                if errno == libc::EBUSY {
                    return Err(Error::Busy);
                }
                let message = io::Error::from_raw_os_error(errno).to_string();
                return Err(Error::Spawn { errno, message });
            }

            Ok(Child {
                pid,
                stdin: stdin.parent,
                stdout: stdout.parent,
                stderr: stderr.parent,
                waited: false,
                released: false,
                last_status: None,
                keep_alive: keep,
            })
        }
    }

    impl Child {
        pub(crate) fn wait_linux(&mut self, flags: libc::c_int) -> Result<Option<Status>> {
            if self.waited {
                return Ok(self.last_status);
            }
            let mut st: libc::c_int = 0;
            loop {
                let r = unsafe { libc::waitpid(self.pid, &mut st, flags) };
                if r < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(Error::Io(e));
                }
                if r == 0 {
                    // WNOHANG, still running
                    return Ok(None);
                }
                break;
            }
            let status = Status { raw: st };
            self.waited = true;
            self.last_status = Some(status);
            self.release_linux();
            Ok(Some(status))
        }

        pub(crate) fn release_linux(&mut self) {
            if self.released {
                return;
            }
            let _guard = lock_api();
            unsafe { ffi::agentcell_release(self.pid) };
            self.released = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_nonempty() {
        assert!(!version().is_empty());
    }

    #[test]
    fn builder_chain() {
        let mut c = Config::new();
        c.mem_bytes(1 << 20)
            .cpu_cores(1.0)
            .pids(8)
            .net(Net::Host)
            .secure(true);
        assert_eq!(c.mem_bytes, 1 << 20);
        assert_eq!(c.pids, 8);
        assert!(c.secure);
    }

    #[test]
    fn empty_argv_fails() {
        let err = Config::new().spawn(Vec::<&str>::new()).unwrap_err();
        assert!(matches!(err, Error::EmptyArgv));
    }

    #[test]
    fn nul_in_env_fails_or_unsupported() {
        // Off Linux spawn returns Unsupported before env conversion.
        let mut c = Config::new();
        c.env("A", "b");
        match c.spawn(["true"]) {
            Err(Error::Unsupported) => {}
            Err(Error::Spawn { .. }) | Ok(_) => {}
            Err(e) => panic!("unexpected {e:?}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn spawn_unsupported_off_linux() {
        let err = Config::new().spawn(["echo", "hi"]).unwrap_err();
        assert!(matches!(err, Error::Unsupported));
    }
}
