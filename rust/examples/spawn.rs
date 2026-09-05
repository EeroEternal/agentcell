//! Mirror of `examples/ffi_demo.c`: jail `sh -c 'echo …; exit 7'` and
//! check the exit code.
//!
//!   cargo run --example spawn

use std::io::Read;

use agentcell::{Config, Stdio};

fn main() {
    let mut child = match Config::new()
        .mem_bytes(512 * 1024 * 1024)
        .cpu_cores(1.0)
        .pids(32)
        .env("HOME", "/home/agent")
        .env("PATH", "/usr/bin:/bin")
        .stdout(Stdio::Piped)
        .stderr(Stdio::Piped)
        .spawn(["sh", "-c", "echo hi-from-rust; id -u; exit 7"])
    {
        Ok(c) => c,
        Err(agentcell::Error::Unsupported) => {
            eprintln!("agentcell: Linux only (this host cannot spawn a jail)");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("spawn failed: {e}");
            std::process::exit(1);
        }
    };

    println!("jailed pid {}", child.id());
    let mut out = String::new();
    if let Some(ref mut stdout) = child.stdout {
        let _ = stdout.read_to_string(&mut out);
    }
    print!("output:\n{out}");

    match child.wait() {
        Ok(st) => {
            println!("exit code: {:?} (want 7)", st.code());
            std::process::exit(if st.code() == Some(7) { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("wait failed: {e}");
            std::process::exit(1);
        }
    }
}
