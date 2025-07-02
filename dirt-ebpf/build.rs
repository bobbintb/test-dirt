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
    let output = Command::new("aya-tool")
        .args(["generate", "task_struct", "dentry"])
        .output()
        .expect("failed to run aya-tool");

    if !output.status.success() {
        panic!("aya-tool failed");
    }

    std::fs::write("src/vmlinux.rs", output.stdout).expect("failed to write vmlinux.rs");

    println!("cargo:rerun-if-changed=build.rs");
}
