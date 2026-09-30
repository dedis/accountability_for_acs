//! Flags shared by the Longfellow benchmark drivers.
//!
//! The JavaScript drivers each carried their own copy of this parser and of the
//! usage text; `clap` generates both from one declaration.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use bench_core::cli::Out;
use clap::{Args, ValueEnum};

/// Which Google Benchmark timing column `--verbose` prints.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
#[value(rename_all = "snake_case")]
pub enum Metric {
    RealTime,
    CpuTime,
    Both,
}

impl Metric {
    pub const fn wants_cpu(self) -> bool {
        matches!(self, Self::CpuTime | Self::Both)
    }

    pub const fn wants_real(self) -> bool {
        matches!(self, Self::RealTime | Self::Both)
    }
}

/// Google Benchmark's `--benchmark_iterations`, or its adaptive inner loop.
///
/// A dedicated type rather than a bare `Option<usize>`: clap reads
/// `Option<T>` as "the flag may be absent", which is not what `auto` means.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Iterations(pub Option<usize>);

impl FromStr for Iterations {
    type Err = String;

    /// `auto` and `0` select the adaptive loop; anything else is a count.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let t = raw.trim().to_ascii_lowercase();
        if t == "auto" || t == "0" {
            return Ok(Self(None));
        }
        t.parse::<usize>()
            .ok()
            .filter(|n| *n >= 1)
            .map(|n| Self(Some(n)))
            .ok_or_else(|| {
                "must be a positive integer, or 0/auto for the adaptive inner loop".to_string()
            })
    }
}

#[derive(Args, Debug)]
pub struct Common {
    /// Benchmark binary; falls back to the environment and the default build path.
    #[arg(long)]
    pub bin: Option<PathBuf>,

    /// Outer repetitions, i.e. statistical samples.
    #[arg(
        long = "repetitions",
        visible_alias = "n",
        env = if std::env::var_os("BENCH_N").is_some() { "BENCH_N" } else { "BENCH_REPETITIONS" },
        default_value_t = 10
    )]
    pub repetitions: usize,

    /// Inner iterations per repetition; `auto` or `0` lets min_time decide.
    #[arg(long, env = "BENCH_ITERATIONS", default_value = "1")]
    pub iterations: Iterations,

    /// Google Benchmark `--benchmark_min_time`, e.g. `0.05s`.
    #[arg(long = "min_time", env = "BENCH_MIN_TIME", default_value = "0.05s")]
    pub min_time: String,

    /// Timing column printed by `--verbose`.
    #[arg(long, env = "BENCH_METRIC", value_enum, default_value_t = Metric::Both)]
    pub metric: Metric,

    /// Per-benchmark sample statistics after the run.
    #[arg(long)]
    pub verbose: bool,

    /// Minimal header.
    #[arg(long)]
    pub compact: bool,

    /// Compatibility flag; quiet output is already the default.
    #[arg(long)]
    pub quiet: bool,

    /// Remove the output directory before the run.
    #[arg(long, env = "CLEAN", value_parser = clap::builder::BoolishValueParser::new())]
    pub clean: bool,

    #[command(flatten)]
    pub out: Out,
}

impl Common {
    /// Whether to run one discarded repetition before the measured pass.
    pub fn warmup_enabled() -> bool {
        match std::env::var("BENCH_WARMUP") {
            Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"),
            Err(_) => true,
        }
    }

    pub fn describe_iterations(&self) -> String {
        self.iterations.0.map_or_else(
            || "adaptive (BENCH_ITERATIONS=auto or 0)".to_string(),
            |n| n.to_string(),
        )
    }

    pub fn describe_warmup() -> &'static str {
        if Self::warmup_enabled() {
            "1x Google Benchmark repetition discarded before measured run (BENCH_WARMUP=0 to skip)"
        } else {
            "disabled (BENCH_WARMUP)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterations_accept_auto_and_zero() {
        assert_eq!("auto".parse::<Iterations>(), Ok(Iterations(None)));
        assert_eq!("AUTO".parse::<Iterations>(), Ok(Iterations(None)));
        assert_eq!("0".parse::<Iterations>(), Ok(Iterations(None)));
        assert_eq!("4".parse::<Iterations>(), Ok(Iterations(Some(4))));
        assert!("-1".parse::<Iterations>().is_err());
        assert!("many".parse::<Iterations>().is_err());
    }

    /// Every flag must round-trip through clap; a value parser whose output
    /// type disagrees with the field type only fails at parse time.
    #[test]
    fn common_flags_parse() {
        use clap::Parser;

        #[derive(Parser)]
        struct Probe {
            #[command(flatten)]
            common: Common,
        }

        let probe = Probe::try_parse_from(["probe"]).expect("defaults parse");
        assert_eq!(probe.common.repetitions, 10);
        assert_eq!(probe.common.iterations, Iterations(Some(1)));
        assert_eq!(probe.common.metric, Metric::Both);

        let probe = Probe::try_parse_from([
            "probe",
            "--repetitions",
            "3",
            "--iterations",
            "auto",
            "--min_time",
            "0.2s",
            "--metric",
            "cpu_time",
            "--verbose",
        ])
        .expect("explicit flags parse");
        assert_eq!(probe.common.repetitions, 3);
        assert_eq!(probe.common.iterations, Iterations(None));
        assert_eq!(probe.common.min_time, "0.2s");
        assert_eq!(probe.common.metric, Metric::CpuTime);
        assert!(probe.common.verbose);
    }

    #[test]
    fn metric_selects_columns() {
        assert!(Metric::Both.wants_cpu() && Metric::Both.wants_real());
        assert!(Metric::CpuTime.wants_cpu() && !Metric::CpuTime.wants_real());
        assert!(!Metric::RealTime.wants_cpu() && Metric::RealTime.wants_real());
    }
}
