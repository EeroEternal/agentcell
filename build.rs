use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/libagentcell.c");
    println!("cargo:rerun-if-changed=src/sand.c");
    println!("cargo:rerun-if-changed=src/agentcell.h");
    println!("cargo:rerun-if-changed=src/arch/syscalls.h");
    println!("cargo:rerun-if-changed=src/arch/x86_64.h");
    println!("cargo:rerun-if-changed=src/arch/aarch64.h");

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    // `links = "agentcell"` requires at least one `cargo:` metadata key.
    println!("cargo:os={os}");

    if os != "linux" {
        return;
    }

    cc::Build::new()
        .file("src/libagentcell.c")
        .include("src")
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-variable")
        .flag_if_supported("-Wno-unused-but-set-variable")
        .flag_if_supported("-Wno-unused-parameter")
        .compile("agentcell");
}
