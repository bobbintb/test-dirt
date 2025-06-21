// dirt/dirt-ebpf/build.rs
fn main() {
    println!("cargo:rerun-if-changed=src/main.rs");
    // Aya's build process, when the 'btf' feature is enabled for aya-ebpf,
    // should handle necessary BTF processing for CO-RE helpers.
}
