//! The grid experiment driver: `set_size × recurring_pct × runs`.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{anyhow, bail, Context as _, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::cft::{self, Batch, Keys, Timing};
use crate::csv;
use crate::env;
use crate::paths::with_suffix;
use crate::stats::{self, Sample};
use babyjub::poseidon::Poseidon;

const DEFAULT_SIZES: [usize; 9] = [10, 20, 50, 100, 500, 1000, 2000, 4000, 8000];
/// Direct decrypt opens every CFT, so the recurring mix cannot affect timing.
const DIRECT_RECURRING_PCTS: [f64; 1] = [0.1];
/// Link decrypt only opens recurring pseudonyms, so the rate is swept.
const LINK_RECURRING_PCTS: [f64; 2] = [0.1, 0.5];
const DEFAULT_RUNS: usize = 10;

/// Columns of `*_runs.csv`.
pub const RUN_HEADERS: [&str; 14] = [
    "benchmark",
    "set_size",
    "recurring_pct",
    "run",
    "pid_threshold",
    "n_recurring_expected",
    "n_after_filter",
    "t_total_ms",
    "t_link_ms",
    "t_decrypt_ms",
    "t_per_input_cft_ms",
    "t_ngo_ms",
    "t_judge_ms",
    "t_police_ms",
];

/// Columns of `*_summary.csv`.
pub const SUMMARY_HEADERS: [&str; 11] = [
    "benchmark",
    "set_size",
    "recurring_pct",
    "runs",
    "pid_threshold",
    "n_after_filter_mean",
    "t_total_mean_ms",
    "t_total_std_ms",
    "t_link_mean_ms",
    "t_decrypt_mean_ms",
    "t_per_input_cft_mean_ms",
];

/// Columns of `*_fit.csv`.
pub const FIT_HEADERS: [&str; 5] = [
    "benchmark",
    "t1_ms_per_input_cft",
    "t2_ms_per_after_filter_cft",
    "formula",
    "n_samples",
];

/// Which revocation strategy to measure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Benchmark {
    DirectDecrypt,
    LinkDecrypt,
}

impl Benchmark {
    pub const ALL: [Self; 2] = [Self::DirectDecrypt, Self::LinkDecrypt];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectDecrypt => "direct-decrypt",
            Self::LinkDecrypt => "link-decrypt",
        }
    }

    fn default_recurring_pcts(self) -> Vec<f64> {
        match self {
            Self::DirectDecrypt => DIRECT_RECURRING_PCTS.to_vec(),
            Self::LinkDecrypt => LINK_RECURRING_PCTS.to_vec(),
        }
    }
}

impl fmt::Display for Benchmark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Benchmark {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "direct-decrypt" => Ok(Self::DirectDecrypt),
            "link-decrypt" => Ok(Self::LinkDecrypt),
            other => Err(anyhow!(
                "unknown benchmark {other:?}, expected direct-decrypt or link-decrypt"
            )),
        }
    }
}

/// Crypto material and randomness shared by every scenario.
///
/// Building it is the expensive part of a run, so `run_experiments` reuses one
/// context across both benchmarks, as the JS `initBenchContext()` did.
pub struct Context {
    pub poseidon: Poseidon,
    pub keys: Keys,
    pub rng: StdRng,
}

impl Context {
    pub fn new() -> Self {
        let mut rng = StdRng::from_entropy();
        let keys = Keys::generate(&mut rng);
        Self {
            poseidon: Poseidon::new(),
            keys,
            rng,
        }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Grid dimensions, taken from the environment unless overridden.
pub struct Options {
    pub sizes: Vec<usize>,
    pub recurring_pcts: Vec<f64>,
    pub runs: usize,
    pub results_dir: PathBuf,
}

impl Options {
    /// Reads `EXPERIMENT_SIZES`, `EXPERIMENT_RECURRING_PCTS` and
    /// `EXPERIMENT_RUNS`, falling back to the benchmark's defaults. The CSVs
    /// go to `results_dir`.
    pub fn from_env(benchmark: Benchmark, results_dir: PathBuf) -> Result<Self> {
        Ok(Self {
            sizes: parse_usize_list("EXPERIMENT_SIZES")?.unwrap_or_else(|| DEFAULT_SIZES.to_vec()),
            recurring_pcts: parse_percent_list("EXPERIMENT_RECURRING_PCTS")?
                .unwrap_or_else(|| benchmark.default_recurring_pcts()),
            runs: env::usize_or("EXPERIMENT_RUNS", DEFAULT_RUNS)?,
            results_dir,
        })
    }
}

fn parse_usize_list(name: &str) -> Result<Option<Vec<usize>>> {
    let Some(raw) = env::var(name) else {
        return Ok(None);
    };
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<usize>()
                .with_context(|| format!("{name} entry {s:?} is not an integer"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((!values.is_empty()).then_some(values))
}

/// Percentages on the wire (`10,50`) become fractions (`0.1`, `0.5`).
fn parse_percent_list(name: &str) -> Result<Option<Vec<f64>>> {
    let Some(raw) = env::var(name) else {
        return Ok(None);
    };
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<f64>()
                .map(|p| p / 100.0)
                .with_context(|| format!("{name} entry {s:?} is not a number"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((!values.is_empty()).then_some(values))
}

/// One measured `(set_size, recurring_pct, run)` cell.
struct Row {
    set_size: usize,
    recurring_pct: i64,
    run: usize,
    pid_threshold: usize,
    n_recurring_expected: usize,
    timing: Timing,
}

impl Row {
    fn total_ms(&self) -> f64 {
        ms(self.timing.total())
    }

    fn per_input_cft_ms(&self) -> f64 {
        self.total_ms() / self.set_size as f64
    }

    fn fields(&self, benchmark: Benchmark) -> Vec<String> {
        vec![
            benchmark.to_string(),
            self.set_size.to_string(),
            self.recurring_pct.to_string(),
            self.run.to_string(),
            self.pid_threshold.to_string(),
            self.n_recurring_expected.to_string(),
            self.timing.n_after_filter.to_string(),
            self.total_ms().to_string(),
            ms(self.timing.link).to_string(),
            ms(self.timing.decrypt).to_string(),
            self.per_input_cft_ms().to_string(),
            ms(self.timing.ngo).to_string(),
            ms(self.timing.judge).to_string(),
            ms(self.timing.police).to_string(),
        ]
    }
}

#[inline]
fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

/// Where the CSVs landed, plus the fitted model.
pub struct Outcome {
    pub benchmark: Benchmark,
    pub prefix: PathBuf,
    pub formula: String,
}

fn run_scenario(
    benchmark: Benchmark,
    ctx: &mut Context,
    set_size: usize,
    recurring_pct: f64,
    run: usize,
) -> Result<Row> {
    let batch: Batch = cft::build_batch(
        &ctx.poseidon,
        ctx.keys.pk_ag,
        set_size,
        recurring_pct,
        &mut ctx.rng,
    )?;

    let timing = match benchmark {
        Benchmark::DirectDecrypt => cft::bench_direct_decrypt(&ctx.poseidon, &batch, &ctx.keys)?,
        Benchmark::LinkDecrypt => {
            cft::bench_link_decrypt(&ctx.poseidon, &batch, &ctx.keys, &mut ctx.rng)?
        }
    };

    if benchmark == Benchmark::LinkDecrypt && timing.n_after_filter != batch.n_recurring {
        bail!(
            "{benchmark} n={set_size} pct={recurring_pct} run={run}: expected {} after filter, got {}",
            batch.n_recurring,
            timing.n_after_filter
        );
    }

    Ok(Row {
        set_size,
        recurring_pct: (recurring_pct * 100.0).round() as i64,
        run,
        pid_threshold: batch.pid_threshold,
        n_recurring_expected: batch.n_recurring,
        timing,
    })
}

/// Runs the whole grid and writes `*_runs.csv`, `*_summary.csv`, `*_fit.csv`.
pub fn run(benchmark: Benchmark, ctx: &mut Context, options: &Options) -> Result<Outcome> {
    let prefix = options.results_dir.join(benchmark.as_str());

    println!("CFT experiment: {benchmark}");
    println!(
        "  sizes={} recurring%={} runs={}",
        options
            .sizes
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(","),
        options
            .recurring_pcts
            .iter()
            .map(|p| ((p * 100.0).round() as i64).to_string())
            .collect::<Vec<_>>()
            .join(","),
        options.runs
    );
    if benchmark == Benchmark::DirectDecrypt {
        println!("  (direct-decrypt: recurring% is not swept — one batch per set_size)");
    }
    println!("  model: t_total_ms ≈ t1·set_size + t2·set_size_after_filter");
    if benchmark == Benchmark::LinkDecrypt {
        println!("  PID threshold = 10% of set_size");
    }
    println!();

    let total_scenarios = options.sizes.len() * options.recurring_pcts.len() * options.runs;
    let mut all_runs: Vec<Row> = Vec::with_capacity(total_scenarios);
    let mut done = 0usize;

    for &set_size in &options.sizes {
        for &recurring_pct in &options.recurring_pcts {
            for run in 1..=options.runs {
                done += 1;
                print!(
                    "[{done}/{total_scenarios}] n={set_size} recurring={}% run={run} ... ",
                    (recurring_pct * 100.0).round() as i64
                );
                io::stdout().flush()?;

                let row = run_scenario(benchmark, ctx, set_size, recurring_pct, run)?;
                println!("{:.1} ms", row.total_ms());
                all_runs.push(row);
            }
        }
    }

    let runs_path = with_suffix(&prefix, "_runs.csv");
    csv::write(
        &runs_path,
        &RUN_HEADERS,
        &all_runs
            .iter()
            .map(|r| r.fields(benchmark))
            .collect::<Vec<_>>(),
    )?;

    let summary_rows = summarise(benchmark, &all_runs, options);
    let summary_path = with_suffix(&prefix, "_summary.csv");
    csv::write(&summary_path, &SUMMARY_HEADERS, &summary_rows)?;

    let samples: Vec<Sample> = all_runs
        .iter()
        .map(|r| Sample {
            x: r.set_size as f64,
            z: r.timing.n_after_filter as f64,
            y: r.total_ms(),
        })
        .collect();
    let model = stats::fit_time_model(&samples);
    let formula = model.formula();

    let fit_path = with_suffix(&prefix, "_fit.csv");
    csv::write(
        &fit_path,
        &FIT_HEADERS,
        &[vec![
            benchmark.to_string(),
            model.t1.map_or_else(String::new, |v| format!("{v:.6}")),
            model.t2.map_or_else(String::new, |v| format!("{v:.6}")),
            formula.clone(),
            samples.len().to_string(),
        ]],
    )?;

    println!("\nWrote:");
    println!("  {}", runs_path.display());
    println!(
        "  {}  (x=set_size, y=recurring_pct)",
        summary_path.display()
    );
    println!("  {}", fit_path.display());
    println!("  {formula}");

    Ok(Outcome {
        benchmark,
        prefix,
        formula,
    })
}

fn summarise(benchmark: Benchmark, all_runs: &[Row], options: &Options) -> Vec<Vec<String>> {
    let mut rows = Vec::with_capacity(options.sizes.len() * options.recurring_pcts.len());

    for &set_size in &options.sizes {
        for &recurring_pct in &options.recurring_pcts {
            let pct = (recurring_pct * 100.0).round() as i64;
            let subset: Vec<&Row> = all_runs
                .iter()
                .filter(|r| r.set_size == set_size && r.recurring_pct == pct)
                .collect();

            let total = stats::mean_std(&subset.iter().map(|r| r.total_ms()).collect::<Vec<_>>());
            let link =
                stats::mean_std(&subset.iter().map(|r| ms(r.timing.link)).collect::<Vec<_>>());
            let decrypt = stats::mean_std(
                &subset
                    .iter()
                    .map(|r| ms(r.timing.decrypt))
                    .collect::<Vec<_>>(),
            );
            let per_cft = stats::mean_std(
                &subset
                    .iter()
                    .map(|r| r.per_input_cft_ms())
                    .collect::<Vec<_>>(),
            );
            let n_after = stats::mean_std(
                &subset
                    .iter()
                    .map(|r| r.timing.n_after_filter as f64)
                    .collect::<Vec<_>>(),
            );

            rows.push(vec![
                benchmark.to_string(),
                set_size.to_string(),
                pct.to_string(),
                options.runs.to_string(),
                subset
                    .first()
                    .map_or_else(String::new, |r| r.pid_threshold.to_string()),
                n_after.mean.to_string(),
                format!("{:.3}", total.mean),
                format!("{:.3}", total.std),
                format!("{:.3}", link.mean),
                format!("{:.3}", decrypt.mean),
                format!("{:.4}", per_cft.mean),
            ]);
        }
    }

    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_names_roundtrip() {
        for b in Benchmark::ALL {
            assert_eq!(b.as_str().parse::<Benchmark>().unwrap(), b);
        }
        assert!("mpc-decrypt".parse::<Benchmark>().is_err());
    }

    #[test]
    fn percent_lists_become_fractions() {
        std::env::set_var("REVOCATION_TEST_PCTS", "10, 50");
        let parsed = parse_percent_list("REVOCATION_TEST_PCTS").unwrap().unwrap();
        std::env::remove_var("REVOCATION_TEST_PCTS");
        assert_eq!(parsed, vec![0.1, 0.5]);
    }
}
