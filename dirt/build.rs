use anyhow::{anyhow, Context as _};
use cargo_metadata::{Artifact, CompilerMessage, Message, Package}; // Replaced aya_build::cargo_metadata, removed Target
use std::{
    env, fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

// Copied from aya-build/src/lib.rs
/// The toolchain to use for building eBPF programs.
#[derive(Default)]
pub enum Toolchain<'a> {
    /// The latest nightly toolchain i.e. `nightly`.
    #[default]
    Nightly,
    /// A custom toolchain e.g. `nightly-2021-01-01`.
    ///
    /// The toolchain specifier is passed to `rustup run` and therefore should _
    /// not_ have a preceding `+`.
    Custom(&'a str),
}

impl<'a> Toolchain<'a> {
    fn as_str(&self) -> &'a str {
        match self {
            Toolchain::Nightly => "nightly",
            Toolchain::Custom(toolchain) => toolchain,
        }
    }
}

// Adapted build_ebpf function
fn build_ebpf_custom(packages: impl IntoIterator<Item = Package>, toolchain: Toolchain) -> Result<(), anyhow::Error> {
    // cargo_metadata::Target was unused, removed from imports if this was the only use.
    // If it was used by cargo_metadata::Package, it's implicitly handled.
    let out_dir = env::var_os("OUT_DIR").ok_or_else(|| anyhow!("OUT_DIR not set"))?;
    let out_dir = PathBuf::from(out_dir);

    let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN")
        .ok_or_else(|| anyhow!("CARGO_CFG_TARGET_ENDIAN not set"))?;
    let target_suffix = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        return Err(anyhow!("unsupported endian={:?}", endian));
    };

    let arch = env::var_os("CARGO_CFG_TARGET_ARCH")
        .ok_or_else(|| anyhow!("CARGO_CFG_TARGET_ARCH not set"))?;

    let target_triple = format!("{}-unknown-none", target_suffix);

    for package_meta in packages {
        let package_name = &package_meta.name;
        let manifest_path = &package_meta.manifest_path;
        let dir = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {}", manifest_path))?;

        println!("cargo:rerun-if-changed={}", dir.as_str());

        let mut cmd = Command::new("rustup");
        cmd.args([
            "run",
            toolchain.as_str(),
            "cargo",
            "build",
            "--package",
            package_name,
            "-Z",
            "build-std=core", // Should be core only if not using alloc
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target_triple,
        ]);

        cmd.env("CARGO_CFG_BPF_TARGET_ARCH", &arch);
        cmd.env(
            "CARGO_ENCODED_RUSTFLAGS",
            ["debuginfo=2", "link-arg=--btf"]
                .into_iter()
                .flat_map(|flag| ["-C", flag])
                .fold(String::new(), |mut acc, flag| {
                    if !acc.is_empty() {
                        acc.push('\x1f');
                    }
                    acc.push_str(flag);
                    acc
                }),
        );

        for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
            cmd.env_remove(key);
        }

        let target_dir = out_dir.join(package_name.as_str());
        cmd.arg("--target-dir").arg(&target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn {:?}", cmd))?;
        let Child { stdout, stderr, .. } = &mut child;

        let stderr_thread = {
            let stderr = stderr.take().expect("stderr");
            let reader = BufReader::new(stderr);
            std::thread::spawn(move || {
                for line in reader.lines() {
                    println!("cargo:warning={}", line.expect("read line"));
                }
            })
        };

        let stdout_reader = BufReader::new(stdout.take().expect("stdout"));
        let mut executables = Vec::new();
        for message in Message::parse_stream(stdout_reader) {
            match message.expect("valid JSON") {
                Message::CompilerArtifact(Artifact {
                    executable,
                    target: package_target, // Renamed to avoid conflict with target_triple
                    ..
                }) => {
                    if let Some(executable_path) = executable {
                        executables.push((package_target.name, executable_path.into_std_path_buf()));
                    }
                }
                Message::CompilerMessage(CompilerMessage { message, .. }) => {
                    for line in message.rendered.unwrap_or_default().split('\n') {
                        println!("cargo:warning={}", line);
                    }
                }
                Message::TextLine(line) => {
                    println!("cargo:warning={}", line);
                }
                _ => {}
            }
        }

        let status = child
            .wait()
            .with_context(|| format!("failed to wait for {:?}", cmd))?;
        if !status.success() {
            return Err(anyhow!("{:?} failed: {:?}", cmd, status));
        }

        stderr_thread.join().map_err(|e| anyhow!("stderr thread panicked: {:?}", e))?;


        for (name, binary) in executables {
            let dst = out_dir.join(name);
            fs::copy(&binary, &dst)
                .with_context(|| format!("failed to copy {:?} to {:?}", binary, dst))?;
        }
    }
    Ok(())
}


fn main() -> anyhow::Result<()> {
    // aya_build::build_ebpf needs a valid OUT_DIR from the calling build script
    // We set it here for our custom function, assuming it's being run by cargo
    // for the `dirt` crate.
    println!("cargo:rerun-if-env-changed=OUT_DIR");


    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps() // We are interested in the specific eBPF package, not its deps for this step
        .exec()
        .context("MetadataCommand::exec for eBPF package discovery")?;

    let ebpf_package = packages
        .into_iter()
        .find(|pkg| pkg.name == "dirt-ebpf")
        .ok_or_else(|| anyhow!("dirt-ebpf package not found in metadata"))?;

    // Call the custom build function
    build_ebpf_custom(std::iter::once(ebpf_package), Toolchain::default())?;

    Ok(())
}
