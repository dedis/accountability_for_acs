//! Locating and running the Longfellow benchmark binaries.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

use crate::gbench::{self, Row};
use crate::paths;

/// One benchmark binary plus the flags shared by its warm-up and measured runs.
pub struct Gbench {
    pub bin: PathBuf,
    base_args: Vec<String>,
}

impl Gbench {
    /// `bin` must exist; `filter`, `repetitions` and `min_time` are the flags
    /// every benchmark passes, and `iterations` is omitted for the adaptive
    /// inner loop.
    pub fn new(
        bin: PathBuf,
        filter: &str,
        repetitions: usize,
        min_time: &str,
        iterations: Option<usize>,
    ) -> Result<Self> {
        let mut base_args = vec![
            format!("--benchmark_filter={filter}"),
            format!("--benchmark_repetitions={repetitions}"),
            "--benchmark_report_aggregates_only=false".to_string(),
            "--benchmark_display_aggregates_only=false".to_string(),
            format!(
                "--benchmark_min_time={}",
                gbench::format_min_time_for_gbench(min_time, &bin)?
            ),
        ];
        if let Some(iterations) = iterations {
            base_args.push(format!("--benchmark_iterations={iterations}"));
        }
        Ok(Self { bin, base_args })
    }

    fn args_with(&self, out: &Path, repetitions: Option<usize>) -> Vec<String> {
        let mut args: Vec<String> = self
            .base_args
            .iter()
            .map(|arg| match repetitions {
                Some(n) if arg.starts_with("--benchmark_repetitions=") => {
                    format!("--benchmark_repetitions={n}")
                }
                _ => arg.clone(),
            })
            .collect();
        args.push("--benchmark_format=console".to_string());
        args.push(format!("--benchmark_out={}", out.display()));
        args.push("--benchmark_out_format=json".to_string());
        args
    }

    /// One discarded repetition with the same filter and min_time.
    pub fn warmup(&self, quiet: bool) -> Result<()> {
        let out = temp_report("longfellow-warm");
        if !quiet {
            println!(
                "[warmup] 1x Google Benchmark repetition (same filter/min_time). \
                 Live console; JSON is written to a temp file and discarded.\n"
            );
        }
        Command::new(&self.bin)
            .args(self.args_with(&out, Some(1)))
            .status()
            .with_context(|| format!("run {}", self.bin.display()))?;
        let _ = std::fs::remove_file(&out);
        if !quiet {
            println!("[warmup] Done.\n");
        }
        Ok(())
    }

    /// The measured run; the console output streams, the JSON is parsed after.
    pub fn measured(&self) -> Result<(Vec<Row>, Option<i32>)> {
        let out = temp_report("longfellow-gbench");
        let status = Command::new(&self.bin)
            .args(self.args_with(&out, None))
            .status()
            .with_context(|| format!("run {}", self.bin.display()))?;

        let rows = gbench::read_report(&out);
        let _ = std::fs::remove_file(&out);
        Ok((rows?, status.code()))
    }
}

fn temp_report(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.json", std::process::id()))
}

/// Resolves the benchmark binary: an explicit path, an environment override, or
/// the default Longfellow build tree.
pub fn resolve_bin(
    explicit: Option<PathBuf>,
    env_names: &[&str],
    test_name: &str,
) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    for name in env_names {
        if let Some(value) = std::env::var_os(name).filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(value));
        }
    }

    let default = paths::default_bin_path(test_name);
    if default.is_file() {
        return Ok(default);
    }
    bail!(
        "Benchmark binary not found at {}.\n\
         Build it first (see crates/standard/README.md): cmake -S {} -B {} && \
         cmake --build {} -j, or set {} / pass --bin PATH",
        default.display(),
        paths::longfellow().join("lib").display(),
        paths::build_dir().display(),
        paths::build_dir().display(),
        env_names.join(" / ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warmup_forces_a_single_repetition() {
        let bench = Gbench {
            bin: PathBuf::from("/bin/true"),
            base_args: vec![
                "--benchmark_filter=BM_X".into(),
                "--benchmark_repetitions=10".into(),
            ],
        };
        let args = bench.args_with(Path::new("/tmp/out.json"), Some(1));
        assert!(args.contains(&"--benchmark_repetitions=1".to_string()));
        assert!(args.contains(&"--benchmark_filter=BM_X".to_string()));
        assert!(args.contains(&"--benchmark_out=/tmp/out.json".to_string()));
    }

    #[test]
    fn measured_keeps_the_configured_repetitions() {
        let bench = Gbench {
            bin: PathBuf::from("/bin/true"),
            base_args: vec!["--benchmark_repetitions=10".into()],
        };
        let args = bench.args_with(Path::new("/tmp/out.json"), None);
        assert!(args.contains(&"--benchmark_repetitions=10".to_string()));
    }
}
