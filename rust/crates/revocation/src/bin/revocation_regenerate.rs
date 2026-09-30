//! Rebuilds `*_summary.csv` and `*_fit.csv` from an existing `*_runs.csv`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{bail, Context as _, Result};
use clap::Parser;
use revocation::csv::{self, Table};
use revocation::experiment::{FIT_HEADERS, RUN_HEADERS, SUMMARY_HEADERS};
use revocation::paths::{self, with_suffix};
use revocation::stats::{self, Sample};

const MPC_SUMMARY_HEADERS: [&str; 9] = [
    "benchmark",
    "set_size",
    "runs",
    "n_after_filter_mean",
    "t_total_mean_ms",
    "t_total_std_ms",
    "t_link_mean_ms",
    "t_decrypt_mean_ms",
    "t_per_input_cft_mean_ms",
];

const MPC_FIT_HEADERS: [&str; 5] = ["benchmark", "k_ms_per_pair", "formula", "r2", "n_samples"];

const VALID: [&str; 3] = ["direct-decrypt", "link-decrypt", "mpc-decrypt"];

/// One row of a `*_runs.csv`, with the columns every regeneration path needs.
struct Run {
    set_size: u64,
    /// Empty for the MPC sweep, which does not vary the recurring rate.
    recurring_pct: Option<i64>,
    run: u64,
    /// Passed through verbatim; empty for the MPC sweep.
    pid_threshold: String,
    n_after_filter: f64,
    t_total_ms: f64,
    t_link_ms: f64,
    t_decrypt_ms: f64,
    t_per_input_cft_ms: f64,
}

fn load(path: &Path) -> Result<Vec<Run>> {
    let table = Table::read(path)?;
    let col = |name: &str| table.column(name);
    let (set_size, recurring_pct, run, pid_threshold) = (
        col("set_size")?,
        col("recurring_pct")?,
        col("run")?,
        col("pid_threshold")?,
    );
    let (n_after_filter, t_total_ms, t_link_ms, t_decrypt_ms, t_per_input_cft_ms) = (
        col("n_after_filter")?,
        col("t_total_ms")?,
        col("t_link_ms")?,
        col("t_decrypt_ms")?,
        col("t_per_input_cft_ms")?,
    );

    table
        .rows()
        .enumerate()
        .map(|(i, row)| {
            (|| -> Result<Run> {
                Ok(Run {
                    set_size: row.parse(set_size, "set_size")?,
                    recurring_pct: row
                        .parse_opt::<f64>(recurring_pct, "recurring_pct")?
                        .map(|p| p.round() as i64),
                    run: row.parse(run, "run")?,
                    pid_threshold: row.text(pid_threshold).to_string(),
                    n_after_filter: row.parse(n_after_filter, "n_after_filter")?,
                    t_total_ms: row.parse(t_total_ms, "t_total_ms")?,
                    t_link_ms: row.parse(t_link_ms, "t_link_ms")?,
                    t_decrypt_ms: row.parse(t_decrypt_ms, "t_decrypt_ms")?,
                    t_per_input_cft_ms: row.parse(t_per_input_cft_ms, "t_per_input_cft_ms")?,
                })
            })()
            .with_context(|| format!("row {}", i + 2))
        })
        .collect()
}

/// What the tool reports once it has rewritten the CSVs.
struct Report {
    sizes: Vec<u64>,
    summary_rows: usize,
    formula: String,
    n_samples: usize,
}

fn regenerate_grid(benchmark: &str, runs: &[Run], prefix: &Path) -> Result<Report> {
    let sizes: Vec<u64> = runs
        .iter()
        .map(|r| r.set_size)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let pcts: Vec<i64> = runs
        .iter()
        .filter_map(|r| r.recurring_pct)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut summary_rows = Vec::new();
    for &set_size in &sizes {
        for &pct in &pcts {
            let subset: Vec<&Run> = runs
                .iter()
                .filter(|r| r.set_size == set_size && r.recurring_pct == Some(pct))
                .collect();
            if subset.is_empty() {
                continue;
            }

            let total = stats::mean_std(&subset.iter().map(|r| r.t_total_ms).collect::<Vec<_>>());
            let link = stats::mean_std(&subset.iter().map(|r| r.t_link_ms).collect::<Vec<_>>());
            let decrypt =
                stats::mean_std(&subset.iter().map(|r| r.t_decrypt_ms).collect::<Vec<_>>());
            let per_cft = stats::mean_std(
                &subset
                    .iter()
                    .map(|r| r.t_per_input_cft_ms)
                    .collect::<Vec<_>>(),
            );
            let n_after =
                stats::mean_std(&subset.iter().map(|r| r.n_after_filter).collect::<Vec<_>>());

            summary_rows.push(vec![
                benchmark.to_string(),
                set_size.to_string(),
                pct.to_string(),
                subset.len().to_string(),
                subset[0].pid_threshold.clone(),
                n_after.mean.to_string(),
                format!("{:.3}", total.mean),
                format!("{:.3}", total.std),
                format!("{:.3}", link.mean),
                format!("{:.3}", decrypt.mean),
                format!("{:.4}", per_cft.mean),
            ]);
        }
    }

    csv::write(
        &with_suffix(prefix, "_summary.csv"),
        &SUMMARY_HEADERS,
        &summary_rows,
    )?;

    let samples: Vec<Sample> = runs
        .iter()
        .map(|r| Sample {
            x: r.set_size as f64,
            z: r.n_after_filter,
            y: r.t_total_ms,
        })
        .collect();
    let model = stats::fit_time_model(&samples);
    let formula = model.formula();

    csv::write(
        &with_suffix(prefix, "_fit.csv"),
        &FIT_HEADERS,
        &[vec![
            benchmark.to_string(),
            model.t1.map_or_else(String::new, |v| format!("{v:.6}")),
            model.t2.map_or_else(String::new, |v| format!("{v:.6}")),
            formula.clone(),
            samples.len().to_string(),
        ]],
    )?;

    Ok(Report {
        sizes,
        summary_rows: summary_rows.len(),
        formula,
        n_samples: samples.len(),
    })
}

fn regenerate_mpc(runs: &[Run], prefix: &Path) -> Result<Report> {
    const BENCHMARK: &str = "mpc-decrypt";

    let mut sorted: Vec<&Run> = runs.iter().collect();
    sorted.sort_by_key(|r| (r.set_size, r.run));

    // The MPC sweep measures a single undivided phase, so the grid columns that
    // do not apply are written empty, as the JS did.
    let run_rows: Vec<Vec<String>> = sorted
        .iter()
        .map(|r| {
            vec![
                BENCHMARK.to_string(),
                r.set_size.to_string(),
                String::new(),
                r.run.to_string(),
                String::new(),
                String::new(),
                r.set_size.to_string(),
                r.t_total_ms.to_string(),
                "0".to_string(),
                r.t_total_ms.to_string(),
                round_to(r.t_total_ms / r.set_size as f64, 7),
                String::new(),
                String::new(),
                String::new(),
            ]
        })
        .collect();
    csv::write(&with_suffix(prefix, "_runs.csv"), &RUN_HEADERS, &run_rows)?;

    let sizes: Vec<u64> = sorted
        .iter()
        .map(|r| r.set_size)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let summary_rows: Vec<Vec<String>> = sizes
        .iter()
        .map(|&set_size| {
            let subset: Vec<&&Run> = sorted.iter().filter(|r| r.set_size == set_size).collect();
            let total = stats::mean_std(&subset.iter().map(|r| r.t_total_ms).collect::<Vec<_>>());
            let per_cft = stats::mean_std(
                &subset
                    .iter()
                    .map(|r| r.t_per_input_cft_ms)
                    .collect::<Vec<_>>(),
            );
            vec![
                BENCHMARK.to_string(),
                set_size.to_string(),
                subset.len().to_string(),
                set_size.to_string(),
                format!("{:.3}", total.mean),
                format!("{:.3}", total.std),
                "0.000".to_string(),
                format!("{:.3}", total.mean),
                format!("{:.4}", per_cft.mean),
            ]
        })
        .collect();
    csv::write(
        &with_suffix(prefix, "_summary.csv"),
        &MPC_SUMMARY_HEADERS,
        &summary_rows,
    )?;

    let model = stats::fit_pairwise_model(
        &sorted.iter().map(|r| r.set_size).collect::<Vec<_>>(),
        &sorted.iter().map(|r| r.t_total_ms).collect::<Vec<_>>(),
    );
    let formula = format!(
        "t_total_ms ≈ {}·set_size·(set_size - 1)/2",
        model
            .k
            .map_or_else(|| "?".to_string(), |k| format!("{k:.4}"))
    );
    csv::write(
        &with_suffix(prefix, "_fit.csv"),
        &MPC_FIT_HEADERS,
        &[vec![
            BENCHMARK.to_string(),
            model.k.map_or_else(String::new, |k| format!("{k:.6}")),
            formula.clone(),
            format!("{:.6}", model.r2),
            sorted.len().to_string(),
        ]],
    )?;

    Ok(Report {
        sizes,
        summary_rows: summary_rows.len(),
        formula,
        n_samples: sorted.len(),
    })
}

/// Rounds to `decimals` places and drops the trailing zeros, which is what
/// `Number(x.toFixed(7))` produced in the JS.
fn round_to(value: f64, decimals: usize) -> String {
    format!("{value:.decimals$}")
        .parse::<f64>()
        .unwrap_or(value)
        .to_string()
}

#[derive(Parser)]
#[command(about = "Rebuild *_summary.csv and *_fit.csv from an existing *_runs.csv")]
struct Args {
    /// direct-decrypt, link-decrypt or mpc-decrypt.
    benchmark: String,
    /// Folder holding the CSVs (default `.work/revocation/out/experiments`).
    #[arg(long)]
    dir: Option<std::path::PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let benchmark = args.benchmark;
    if !VALID.contains(&benchmark.as_str()) {
        bail!("benchmark must be one of {}", VALID.join(", "));
    }

    let prefix = args.dir.unwrap_or_else(paths::experiments).join(&benchmark);
    let runs_path = with_suffix(&prefix, "_runs.csv");
    let runs = load(&runs_path).with_context(|| format!("load {}", runs_path.display()))?;

    let report = if benchmark == "mpc-decrypt" {
        regenerate_mpc(&runs, &prefix)?
    } else {
        regenerate_grid(&benchmark, &runs, &prefix)?
    };

    println!(
        "sizes: {}",
        report
            .sizes
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("summary rows: {}", report.summary_rows);
    println!("{}", report.formula);
    println!("n_samples: {}", report.n_samples);
    if benchmark == "mpc-decrypt" {
        println!(
            "Wrote {} (sorted)",
            with_suffix(&prefix, "_runs.csv").display()
        );
    }
    println!("Wrote {}", with_suffix(&prefix, "_summary.csv").display());
    println!("Wrote {}", with_suffix(&prefix, "_fit.csv").display());
    Ok(())
}
