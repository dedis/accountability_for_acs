//! Drives the external Circom / Groth16 toolchain: `circom`, `make`, the
//! `snarkjs` CLI and `rapidsnark`. Every path handed to a tool is absolute, so
//! nothing depends on the working directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use regex::Regex;

use crate::paths;

/// Iteration counts shared by the prove/verify benchmarks.
#[derive(clap::Args, Debug)]
pub struct IterArgs {
    /// Measured iterations.
    #[arg(long, env = "BENCH_N", default_value_t = 10)]
    pub n: usize,
    /// Discarded iterations before the measured ones.
    #[arg(long, env = "BENCH_WARMUP", default_value_t = 1)]
    pub warmup: usize,
    /// Extra verify calls during the warm-up iteration.
    #[arg(long, env = "BENCH_VERIFY_WARMUP", default_value_t = 0)]
    pub verify_warmup: usize,
}

impl IterArgs {
    /// `Iterations: N (+W warmup discarded)`.
    pub fn describe(&self) -> String {
        if self.warmup > 0 {
            format!("{} (+{} warmup discarded)", self.n, self.warmup)
        } else {
            self.n.to_string()
        }
    }
}

/// Where each external tool lives, and how loud to be about using it.
pub struct Toolchain {
    pub circom: String,
    pub rapidsnark: String,
    pub snarkjs: String,
    /// `-l` include roots: the downloads (holding `circomlib/`) and `circuits/`.
    pub include_dirs: Vec<PathBuf>,
    pub verbose: bool,
}

impl Toolchain {
    /// Reads `CIRCOM_BIN`/`CIRCOM`, `RAPIDSNARK_BIN`, `SNARKJS_BIN` and
    /// `CIRCOM_LIB_PATH`, falling back to the names on `PATH`.
    pub fn from_env(verbose: bool) -> Self {
        Self {
            circom: env_or("CIRCOM_BIN", || env_or("CIRCOM", || "circom".into())),
            rapidsnark: env_or("RAPIDSNARK_BIN", || "prover".into()),
            snarkjs: env_or("SNARKJS_BIN", || "snarkjs".into()),
            include_dirs: vec![paths::circom_lib(), paths::circuits()],
            verbose,
        }
    }

    fn progress(&self, message: &str) {
        if std::env::var("BENCH_SILENT_SETUP").as_deref() != Ok("1") {
            println!("{message}");
        }
    }

    pub fn section(&self, title: &str) {
        if !self.verbose {
            return;
        }
        println!("\n{}", "━".repeat(51));
        println!("  {title}");
        println!("{}", "━".repeat(51));
    }

    /// Runs a command and captures its output.
    pub fn exec(&self, program: &str, args: &[&str]) -> Result<Output> {
        let output = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("spawn {program}"))?;
        Ok(Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    /// `circom <source> <flags> -o <out> -l <include>...`.
    fn circom(&self, spec: &Groth16Spec, flags: &[&str]) -> Result<Output> {
        let mut args = vec![spec.circom_file.display().to_string()];
        args.extend(flags.iter().map(|f| f.to_string()));
        args.extend(["-o".to_string(), spec.out_dir.display().to_string()]);
        for dir in &self.include_dirs {
            args.extend(["-l".to_string(), dir.display().to_string()]);
        }
        self.exec(
            &self.circom,
            &args.iter().map(String::as_str).collect::<Vec<_>>(),
        )
    }
}

/// What a spawned tool produced.
pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    /// The tool's own diagnostics, preferring stderr.
    pub fn message(&self) -> &str {
        if self.stderr.trim().is_empty() {
            &self.stdout
        } else {
            &self.stderr
        }
    }
}

fn env_or(name: &str, fallback: impl FnOnce() -> String) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(fallback)
}

fn modified(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// True when every output exists and is at least as new as the source.
fn up_to_date(source: &Path, outputs: &[&Path]) -> bool {
    let Some(source_time) = modified(source) else {
        return false;
    };
    outputs
        .iter()
        .all(|out| modified(out).is_some_and(|t| t >= source_time))
}

fn assert_non_empty(path: &Path, label: &str) -> Result<()> {
    let size = fs::metadata(path)
        .with_context(|| format!("missing {label} at {}", path.display()))?
        .len();
    if size == 0 {
        bail!("empty {label} at {}", path.display());
    }
    Ok(())
}

/// One circuit and the files its setup produces, all under
/// `.work/zk-friendly/generated/<circuit>/`.
pub struct Groth16Spec {
    pub circom_file: PathBuf,
    pub out_dir: PathBuf,
    pub r1cs_file: PathBuf,
    pub zkey_file: PathBuf,
    pub vkey_file: PathBuf,
    pub ptau_file: PathBuf,
}

impl Groth16Spec {
    pub fn new(circom_file: PathBuf) -> Self {
        let name = circom_file
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("circuit file has a UTF-8 name")
            .to_string();
        let out_dir = paths::generated(&name);
        Self {
            r1cs_file: out_dir.join(format!("{name}.r1cs")),
            zkey_file: out_dir.join(format!("{name}.zkey")),
            vkey_file: out_dir.join("vkey.json"),
            ptau_file: paths::ptau(),
            circom_file,
            out_dir,
        }
    }

    fn sym_file(&self) -> PathBuf {
        self.r1cs_file.with_extension("sym")
    }

    fn circuit_name(&self) -> &str {
        self.circom_file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
    }
}

/// The prover-side artifacts a benchmark iteration needs.
pub struct Artifacts {
    pub witness_bin: PathBuf,
    pub zkey: PathBuf,
    pub vkey: PathBuf,
}

impl Toolchain {
    /// Compiles the circuit to R1CS unless the cached output is still fresh.
    fn ensure_circuit_compiled(&self, spec: &Groth16Spec) -> Result<()> {
        if up_to_date(&spec.circom_file, &[&spec.r1cs_file, &spec.sym_file()]) {
            self.progress("  [setup] Using cached R1CS/sym (skipped circom compile).");
            return Ok(());
        }

        self.section("Setup (Compiling circuit)");
        self.progress("  [setup] Compiling circuit (circom)...");
        fs::create_dir_all(&spec.out_dir)?;
        let result = self.circom(spec, &["--r1cs", "--sym"])?;
        if !result.ok {
            bail!("circom failed:\n{}", result.message());
        }
        Ok(())
    }

    /// Builds circom's C++ witness calculator unless it is still fresh.
    fn ensure_witness_generator(&self, spec: &Groth16Spec) -> Result<PathBuf> {
        let name = spec.circuit_name();
        let cpp_dir = spec.out_dir.join(format!("{name}_cpp"));
        let bin = cpp_dir.join(name);
        let dat = cpp_dir.join(format!("{name}.dat"));

        if up_to_date(&spec.circom_file, &[&bin, &dat]) {
            self.progress("  [setup] Using cached C++ witness binary (skipped make).");
            return Ok(bin);
        }

        self.section("Setup (Building C++ witness generator)");
        self.progress("  [setup] Building C++ witness generator (circom --c + make)...");
        let generated = self.circom(spec, &["--c", "--no_asm"])?;
        if !generated.ok {
            bail!("circom --c failed:\n{}", generated.message());
        }

        // Best effort: circom's generated Makefile does not know about
        // Homebrew's prefix, and its `--no_asm` backend passes `uint64_t*` to
        // GMP's `mpn_*`, which Clang rejects on macOS.
        if cfg!(target_os = "macos") {
            let _ = self.patch_makefile_for_brew(&cpp_dir.join("Makefile"));
            let _ = patch_fr_backend_for_darwin(&cpp_dir);
        }

        let made = self.exec("make", &["-C", &cpp_dir.display().to_string()])?;
        if !made.ok {
            bail!(
                "{}\n\nIf this is a missing dependency on macOS, try:\n  brew install gmp nlohmann-json",
                made.message()
            );
        }

        if !bin.is_file() {
            bail!("C++ witness binary not found at {}", bin.display());
        }
        Ok(bin)
    }

    /// Adds Homebrew's include and library paths to a generated Makefile.
    fn patch_makefile_for_brew(&self, makefile: &Path) -> Result<()> {
        if !makefile.is_file() {
            return Ok(());
        }
        let brew = self.exec("brew", &["--prefix"])?;
        if !brew.ok || brew.stdout.trim().is_empty() {
            return Ok(());
        }

        static CFLAGS: OnceLock<Regex> = OnceLock::new();
        let cflags = CFLAGS.get_or_init(|| Regex::new(r"(?m)^(CFLAGS=.*)$").expect("valid regex"));

        let mut text = fs::read_to_string(makefile)?;
        if !text.contains("BREW_PREFIX") && text.contains("CFLAGS=") {
            text = cflags
                .replace(
                    &text,
                    "$1\nBREW_PREFIX ?= $(shell brew --prefix 2>/dev/null)\n\
                     CFLAGS += -I$(BREW_PREFIX)/include\n\
                     LDFLAGS += -L$(BREW_PREFIX)/lib",
                )
                .into_owned();
        }

        // Link steps that pull in -lgmp must also honour LDFLAGS.
        text = text
            .lines()
            .map(|line| {
                if line.contains("-lgmp") && line.contains("$(CC)") && !line.contains("$(LDFLAGS)")
                {
                    line.replacen("$(CC) ", "$(CC) $(LDFLAGS) ", 1)
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        fs::write(makefile, text)?;
        Ok(())
    }
}

/// Retypes the generated field backend so Clang accepts GMP's `mpn_*` calls.
fn patch_fr_backend_for_darwin(cpp_dir: &Path) -> Result<()> {
    static RAW_ELEMENT: OnceLock<Regex> = OnceLock::new();
    static P_RAW_B: OnceLock<Regex> = OnceLock::new();
    static UINT64: OnceLock<Regex> = OnceLock::new();
    static FIRST_INCLUDE: OnceLock<Regex> = OnceLock::new();

    let raw_element = RAW_ELEMENT.get_or_init(|| {
        Regex::new(r"typedef\s+uint64_t\s+FrRawElement\[Fr_N64\];").expect("valid regex")
    });
    let p_raw_b = P_RAW_B.get_or_init(|| Regex::new(r"\buint64_t\s+pRawB\b").expect("valid regex"));
    let uint64 = UINT64.get_or_init(|| Regex::new(r"\buint64_t\b").expect("valid regex"));
    let first_include =
        FIRST_INCLUDE.get_or_init(|| Regex::new(r"(?m)^(#include[^\n]*\n)").expect("valid regex"));

    let header = cpp_dir.join("fr.hpp");
    if header.is_file() {
        let original = fs::read_to_string(&header)?;
        let mut text = raw_element
            .replace_all(&original, "typedef mp_limb_t FrRawElement[Fr_N64];")
            .into_owned();
        text = p_raw_b.replace_all(&text, "mp_limb_t pRawB").into_owned();

        // Some generated headers use the non-standard `uint` without a typedef.
        if text.contains("uint base") && !text.contains("<sys/types.h>") {
            const APPLE_BLOCK: &str =
                "\n#ifdef __APPLE__\n#include <sys/types.h> // typedef unsigned int uint;\n#endif // __APPLE__\n";
            text = if text.contains("#include <gmp.h>") {
                text.replace(
                    "#include <gmp.h>",
                    &format!("#include <gmp.h>{APPLE_BLOCK}"),
                )
            } else {
                first_include
                    .replace(&text, format!("${{1}}{APPLE_BLOCK}\n").as_str())
                    .into_owned()
            };
        }

        if text != original {
            fs::write(&header, text)?;
        }
    }

    let source = cpp_dir.join("fr.cpp");
    if source.is_file() {
        let text = fs::read_to_string(&source)?;
        let uses_gmp_backend = text.contains("mpn_add_n") || text.contains("mpn_mul_1");
        if uses_gmp_backend && text.contains("uint64_t") {
            fs::write(&source, uint64.replace_all(&text, "mp_limb_t").as_ref())?;
        }
    }

    Ok(())
}

impl Toolchain {
    /// Generates (or reuses) the proving and verification keys.
    fn ensure_keys(&self, spec: &Groth16Spec) -> Result<()> {
        self.ensure_circuit_compiled(spec)?;

        let zkey_fresh = up_to_date(&spec.r1cs_file, &[&spec.zkey_file])
            && fs::metadata(&spec.zkey_file).is_ok_and(|m| m.len() > 0);
        let vkey_fresh = up_to_date(&spec.r1cs_file, &[&spec.vkey_file])
            && fs::metadata(&spec.vkey_file).is_ok_and(|m| m.len() > 0);

        if zkey_fresh && vkey_fresh {
            self.progress("  [setup] Using cached zkey/vkey (skipped snarkjs setup).");
            return Ok(());
        }

        if zkey_fresh {
            self.progress("  [setup] Exporting vkey from cached zkey...");
            return self.export_verification_key(spec);
        }

        self.section("Setup (Generating Groth16 zkey/vkey)");
        self.progress(
            "  [setup] Generating Groth16 zkey (snarkjs groth16 setup — may take a few minutes)...",
        );
        if !spec.ptau_file.is_file() {
            bail!(
                "Missing ptau file {}. Fetch it with: python3 tools/fetch.py",
                spec.ptau_file.display()
            );
        }

        let setup = self.exec(
            &self.snarkjs,
            &[
                "groth16",
                "setup",
                &spec.r1cs_file.display().to_string(),
                &spec.ptau_file.display().to_string(),
                &spec.zkey_file.display().to_string(),
            ],
        )?;
        if !setup.ok {
            bail!("snarkjs groth16 setup failed:\n{}", setup.message());
        }
        assert_non_empty(&spec.zkey_file, "proving key (zkey)")?;

        self.progress("  [setup] Exporting verification key...");
        self.export_verification_key(spec)
    }

    fn export_verification_key(&self, spec: &Groth16Spec) -> Result<()> {
        let exported = self.exec(
            &self.snarkjs,
            &[
                "zkey",
                "export",
                "verificationkey",
                &spec.zkey_file.display().to_string(),
                &spec.vkey_file.display().to_string(),
            ],
        )?;
        if !exported.ok {
            bail!("snarkjs vkey export failed:\n{}", exported.message());
        }
        assert_non_empty(&spec.vkey_file, "verification key")
    }

    /// Checks that `rapidsnark` is reachable before a long setup starts.
    pub fn ensure_rapidsnark(&self) -> Result<()> {
        if self.rapidsnark.contains('/') {
            if !Path::new(&self.rapidsnark).is_file() {
                bail!("rapidsnark binary not found at path: {}", self.rapidsnark);
            }
            return Ok(());
        }

        if which(&self.rapidsnark).is_some() {
            return Ok(());
        }
        bail!(
            "rapidsnark not found in PATH (looked for {:?}).\n\
             Install rapidsnark, or point to it via RAPIDSNARK_BIN.",
            self.rapidsnark
        );
    }

    /// Compiles the circuit, generates the keys and builds the witness binary.
    pub fn prepare_groth16(&self, spec: &Groth16Spec) -> Result<Artifacts> {
        self.ensure_rapidsnark()?;
        self.ensure_keys(spec)?;
        let witness_bin = self.ensure_witness_generator(spec)?;

        assert_non_empty(&spec.zkey_file, "proving key (zkey)")?;
        assert_non_empty(&spec.vkey_file, "verification key")?;
        assert_non_empty(&witness_bin, "C++ witness binary")?;

        Ok(Artifacts {
            witness_bin,
            zkey: spec.zkey_file.clone(),
            vkey: spec.vkey_file.clone(),
        })
    }

    /// Runs the witness calculator.
    pub fn run_witness(&self, witness_bin: &Path, input: &Path, witness: &Path) -> Result<Output> {
        self.exec(
            &witness_bin.display().to_string(),
            &[&input.display().to_string(), &witness.display().to_string()],
        )
    }

    /// Runs rapidsnark over a witness.
    pub fn run_prover(
        &self,
        zkey: &Path,
        witness: &Path,
        proof: &Path,
        public: &Path,
    ) -> Result<Output> {
        self.exec(
            &self.rapidsnark,
            &[
                &zkey.display().to_string(),
                &witness.display().to_string(),
                &proof.display().to_string(),
                &public.display().to_string(),
            ],
        )
    }
}

/// Minimal `PATH` lookup, so a missing tool is reported before a long setup.
fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|candidate| candidate.is_file())
    })
}

/// Deletes a benchmark's per-iteration files unless they are to be kept.
pub fn clean_artifacts(dir: &Path, keep: bool) {
    if !keep {
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_prefers_stderr_for_diagnostics() {
        let out = Output {
            ok: false,
            stdout: "some stdout".into(),
            stderr: "  ".into(),
        };
        assert_eq!(out.message(), "some stdout");

        let err = Output {
            ok: false,
            stdout: "some stdout".into(),
            stderr: "the real error".into(),
        };
        assert_eq!(err.message(), "the real error");
    }

    #[test]
    fn spec_derives_every_path_from_the_circuit() {
        let spec = Groth16Spec::new(paths::circuits().join("prove_verify.circom"));
        assert_eq!(spec.circuit_name(), "prove_verify");
        assert_eq!(spec.out_dir, paths::generated("prove_verify"));
        assert_eq!(spec.r1cs_file, spec.out_dir.join("prove_verify.r1cs"));
        assert_eq!(spec.sym_file(), spec.out_dir.join("prove_verify.sym"));
        assert_eq!(spec.zkey_file, spec.out_dir.join("prove_verify.zkey"));
        assert_eq!(spec.ptau_file, paths::ptau());
    }
}
