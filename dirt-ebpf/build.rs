use std::process::Command;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies

fn main() {
    // let output = Command::new("aya-tool")
    //     .args(["generate", "task_struct", "dentry"])
    //     .output()
    //     .expect("failed to run aya-tool");

    // if !output.status.success() {
    //     println!("aya-tool stdout: {}", String::from_utf8_lossy(&output.stdout));
    //     eprintln!("aya-tool stderr: {}", String::from_utf8_lossy(&output.stderr));
    //     panic!("aya-tool failed");
    // }

    // std::fs::write("src/vmlinux.rs", output.stdout).expect("failed to write vmlinux.rs");

    // Ensure the vmlinux.rs file exists, even if we don't regenerate it.
    // This is mostly to satisfy cargo if the file was somehow deleted.
    // In a normal scenario, it should exist as it's checked into the repo.
    if std::fs::metadata("src/vmlinux.rs").is_err() {
        // Attempt to create an empty file if it doesn't exist,
        // though this will likely cause compilation errors later if it's truly needed
        // and not just a build script artifact.
        std::fs::File::create("src/vmlinux.rs").expect("failed to create empty vmlinux.rs");
        println!("cargo:warning=src/vmlinux.rs was missing, created an empty one. This might lead to compile errors.");
    }

    println!("cargo:rerun-if-changed=build.rs");
    // Also tell cargo to rerun if the checked-in vmlinux.rs changes,
    // though this is less relevant if we are not generating it.
    println!("cargo:rerun-if-changed=src/vmlinux.rs");
}
