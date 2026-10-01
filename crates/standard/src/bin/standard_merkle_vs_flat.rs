//! Longfellow: flat SHA versus Merkle attribute commitment, swept over
//! credential size `n` and disclosure count `k`.
//!
//! The binary reports `prove_ns` / `verify_ns` counters on `Combined` rows.
//! Older builds only register separate `Prover` / `Verifier` benchmarks, so the
//! harness falls back to their `real_time` / `cpu_time` columns.

use bench_core::stats::{self, P95};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::OnceLock;

use anyhow::{bail, Result};
use clap::Parser;
use regex::Regex;
use serde::Serialize;

use bench_core::report;
use bench_core::time;
use standard::cli::{Common, Metric};
use standard::gbench::{self, Row};
use standard::paths;
use standard::runner::{self, Gbench};

const TEST_NAME: &str = "circuits/tests/ec/attr_commitment_experiment_test";

#[derive(Parser)]
#[command(about = "Longfellow Merkle versus flat attribute commitment sweep")]
struct Args {
    /// Credential sizes n.
    #[arg(long = "total-attrs", visible_alias = "attr", env = "TOTAL_ATTRS", value_delimiter = ',', default_values_t = [8usize, 16, 32, 64])]
    totals: Vec<usize>,
    /// Disclosed counts k; points with k > n are skipped.
    #[arg(long = "used-attrs", visible_alias = "used-attr", env = "USED_ATTRS", value_delimiter = ',', default_values_t = [1usize, 2, 4, 8, 16])]
    used: Vec<usize>,
    /// Google Benchmark filter regex.
    #[arg(long, env = "BENCH_FILTER")]
    filter: Option<String>,
    #[command(flatten)]
    common: Common,
}

/// Which commitment scheme a benchmark row measures.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Mode {
    Merkle,
    Flat,
}

impl Mode {
    const fn label(self) -> &'static str {
        match self {
            Self::Merkle => "Merkle",
            Self::Flat => "Flat",
        }
    }
}

/// What a benchmark name says about the point it measures.
#[derive(Clone, Copy, Debug)]
struct BenchName {
    kind: Kind,
    mode: Mode,
    n: usize,
    k: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Combined,
    Prover,
    Verifier,
}

fn parse_bench_name(name: &str) -> Option<BenchName> {
    static COMBINED: OnceLock<Regex> = OnceLock::new();
    static SPLIT: OnceLock<Regex> = OnceLock::new();

    let combined = COMBINED.get_or_init(|| {
        Regex::new(r"^BM_AttrSigCombined_(Flat|Merkle)/(\d+)/(\d+)$").expect("valid regex")
    });
    let split = SPLIT.get_or_init(|| {
        Regex::new(r"^BM_AttrSig(Prover|Verifier)_(Flat|Merkle)/(\d+)/(\d+)$").expect("valid regex")
    });

    let mode = |s: &str| {
        if s == "Merkle" {
            Mode::Merkle
        } else {
            Mode::Flat
        }
    };

    if let Some(caps) = combined.captures(name) {
        return Some(BenchName {
            kind: Kind::Combined,
            mode: mode(&caps[1]),
            n: caps[2].parse().ok()?,
            k: caps[3].parse().ok()?,
        });
    }

    let caps = split.captures(name)?;
    Some(BenchName {
        kind: if &caps[1] == "Prover" {
            Kind::Prover
        } else {
            Kind::Verifier
        },
        mode: mode(&caps[2]),
        n: caps[3].parse().ok()?,
        k: caps[4].parse().ok()?,
    })
}

#[derive(Serialize, Clone, Copy, Default)]
struct Cell {
    #[serde(rename = "avgProverMs")]
    avg_prover_ms: Option<f64>,
    #[serde(rename = "avgVerifyMs")]
    avg_verify_ms: Option<f64>,
    #[serde(rename = "successfulIters")]
    successful_iters: Option<usize>,
}

type Grid = BTreeMap<usize, BTreeMap<usize, Cell>>;

#[derive(Serialize)]
struct Meta {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "N")]
    n: usize,
    totals: Vec<usize>,
    used: Vec<usize>,
    #[serde(rename = "timestampIso")]
    timestamp_iso: String,
}

#[derive(Serialize)]
struct SweepSummary {
    meta: Meta,
    merkle: Grid,
    flat: Grid,
}

/// Samples for one `(mode, n, k)` point.
#[derive(Default)]
struct Samples {
    prove_ms: Vec<f64>,
    verify_ms: Vec<f64>,
}

type Key = (Mode, usize, usize);

/// Collects `prove_ns` / `verify_ns` from the `Combined` rows.
fn collect_combined(
    rows: &[Row],
    totals: &BTreeSet<usize>,
    used: &BTreeSet<usize>,
) -> BTreeMap<Key, Samples> {
    let mut by_key: BTreeMap<Key, Samples> = BTreeMap::new();
    for row in rows {
        if row.is_aggregate() {
            continue;
        }
        let Some(meta) = parse_bench_name(gbench::base_name(row.name())) else {
            continue;
        };
        if meta.kind != Kind::Combined || !totals.contains(&meta.n) || !used.contains(&meta.k) {
            continue;
        }
        let (Some(prove_ns), Some(verify_ns)) = (row.number("prove_ns"), row.number("verify_ns"))
        else {
            continue;
        };
        let entry = by_key.entry((meta.mode, meta.n, meta.k)).or_default();
        entry.prove_ms.push(prove_ns / 1e6);
        entry.verify_ms.push(verify_ns / 1e6);
    }
    by_key
}

/// Fallback for builds without `Combined` rows: read the chosen timing column
/// off the separate `Prover` / `Verifier` benchmarks.
fn collect_split(
    rows: &[Row],
    totals: &BTreeSet<usize>,
    used: &BTreeSet<usize>,
    metric: Metric,
) -> BTreeMap<Key, Samples> {
    let column = if metric == Metric::CpuTime {
        "cpu_time"
    } else {
        "real_time"
    };

    let mut by_key: BTreeMap<Key, Samples> = BTreeMap::new();
    for row in rows {
        if row.is_aggregate() {
            continue;
        }
        let Some(meta) = parse_bench_name(gbench::base_name(row.name())) else {
            continue;
        };
        if meta.kind == Kind::Combined || !totals.contains(&meta.n) || !used.contains(&meta.k) {
            continue;
        }
        let Some(ms) = row
            .number(column)
            .and_then(|v| gbench::to_ms(v, row.time_unit()))
        else {
            continue;
        };
        let entry = by_key.entry((meta.mode, meta.n, meta.k)).or_default();
        match meta.kind {
            Kind::Prover => entry.prove_ms.push(ms),
            Kind::Verifier => entry.verify_ms.push(ms),
            Kind::Combined => unreachable!("filtered above"),
        }
    }
    by_key
}

fn to_grids(samples: &BTreeMap<Key, Samples>, totals: &[usize], used: &[usize]) -> (Grid, Grid) {
    let mut merkle = Grid::new();
    let mut flat = Grid::new();

    for &n in totals {
        for &k in used {
            if k > n {
                continue;
            }
            for mode in [Mode::Merkle, Mode::Flat] {
                let cell = samples
                    .get(&(mode, n, k))
                    .map_or_else(Cell::default, |s| Cell {
                        avg_prover_ms: stats::mean(&s.prove_ms),
                        avg_verify_ms: stats::mean(&s.verify_ms),
                        successful_iters: (!s.prove_ms.is_empty()).then_some(s.prove_ms.len()),
                    });
                let grid = if mode == Mode::Merkle {
                    &mut merkle
                } else {
                    &mut flat
                };
                grid.entry(n).or_default().insert(k, cell);
            }
        }
    }

    (merkle, flat)
}

fn print_recap(title: &str, grid: &Grid, totals: &[usize], used: &[usize], metric_label: &str) {
    println!("\n{}", "=".repeat(51));
    println!("  {title}");
    println!("  cell = avgProverMs/avgVerifyMs ({metric_label})");
    println!("{}", "=".repeat(51));

    const COL: usize = 12;
    let header = std::iter::once(format!("{:<COL$}", "total\\used"))
        .chain(used.iter().map(|u| format!("{u:>COL$}")))
        .collect::<String>();
    println!("{header}");
    println!("{}", "-".repeat(header.len()));

    for n in totals {
        let mut row = format!("{n:<COL$}");
        for k in used {
            let text = grid
                .get(n)
                .and_then(|r| r.get(k))
                .and_then(|cell| {
                    cell.avg_prover_ms
                        .zip(cell.avg_verify_ms)
                        .map(|(p, v)| format!("{p:.0}/{v:.0}"))
                })
                .unwrap_or_default();
            let _ = write!(row, "{text:>COL$}");
        }
        println!("{row}");
    }
}

/// Longest literals first, so `16` is not shadowed by `1` in the alternation.
fn regex_alternation(values: &[usize]) -> String {
    let mut sorted: Vec<String> = values.iter().map(usize::to_string).collect();
    sorted.sort_by(|a, b| b.len().cmp(&a.len()).then(b.cmp(a)));
    sorted.join("|")
}

fn sorted_unique(values: &[usize]) -> Vec<usize> {
    values
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn main() -> Result<()> {
    let args = Args::parse();
    let common = args.common;

    let totals = sorted_unique(&args.totals);
    let used = sorted_unique(&args.used);
    let total_set: BTreeSet<usize> = totals.iter().copied().collect();
    let used_set: BTreeSet<usize> = used.iter().copied().collect();

    let bin = runner::resolve_bin(
        common.bin.clone(),
        &["LONGFELLOW_ATTR_BENCH_BIN"],
        TEST_NAME,
    )?;
    let out_dir = common.out.dir(paths::STACK, "merkle_vs_flat");
    if common.clean {
        let _ = std::fs::remove_dir_all(&out_dir);
    }

    let filter = args.filter.unwrap_or_else(|| {
        format!(
            "BM_AttrSigCombined_(Flat|Merkle)/({})/({})$",
            regex_alternation(&totals),
            regex_alternation(&used)
        )
    });

    if !common.compact {
        println!("Backend: Longfellow (P-256 + SHA) - {TEST_NAME}");
        println!(
            "Repetitions (outer samples): {}  (BENCH_N; --repetitions / --n)",
            common.repetitions
        );
        println!(
            "Inner iterations per rep: {}  (BENCH_ITERATIONS; --iterations; default 1)",
            common.describe_iterations()
        );
        println!(
            "Totals: {}  (env TOTAL_ATTRS; CLI --total-attrs / --attr)",
            join(&totals)
        );
        println!(
            "Used:   {}  (env USED_ATTRS; CLI --used-attrs / --used-attr)",
            join(&used)
        );
        println!("Filter: {filter}  (env BENCH_FILTER)");
        println!(
            "Metric: {:?}   min_time: {}  (env BENCH_METRIC, BENCH_MIN_TIME)",
            common.metric, common.min_time
        );
        println!("Output: {}  (--out / BENCH_OUT)", out_dir.display());
        println!("Warm-up: {}", Common::describe_warmup());
        println!();
    }

    let gb = Gbench::new(
        bin,
        &filter,
        common.repetitions,
        &common.min_time,
        common.iterations.0,
    )?;
    if Common::warmup_enabled() {
        gb.warmup(common.compact)?;
    }
    if !common.compact {
        println!(
            "[measured] Live Google Benchmark console follows; JSON for summaries is written \
             to a temp file (--benchmark_out), then parsed when the binary exits.\n"
        );
    }
    let (rows, exit_code) = gb.measured()?;

    let mut samples = collect_combined(&rows, &total_set, &used_set);
    let metric_label = if samples.is_empty() {
        samples = collect_split(&rows, &total_set, &used_set, common.metric);
        match common.metric {
            Metric::CpuTime => "cpu_time",
            _ => "real_time",
        }
    } else {
        "prove_ns / verify_ns counters (wall clock)"
    };

    if common.verbose {
        println!("\n-- Per-benchmark sample stats (all matching runs) --");
        for ((mode, n, k), s) in &samples {
            let label = format!("{}/{n}/{k}", mode.label());
            stats::print_stats(&format!("{label} prover"), &s.prove_ms, P95::FloorNMinus1);
            stats::print_stats(&format!("{label} verify"), &s.verify_ms, P95::FloorNMinus1);
        }
        println!();
    }

    let (merkle, flat) = to_grids(&samples, &totals, &used);
    print_recap("Recap - Flat hash", &flat, &totals, &used, metric_label);
    print_recap("Recap - Merkle", &merkle, &totals, &used, metric_label);

    let report = SweepSummary {
        meta: Meta {
            kind: "longfellow",
            n: common.repetitions,
            totals: totals.clone(),
            used: used.clone(),
            timestamp_iso: time::iso8601_now(),
        },
        merkle,
        flat,
    };
    let written = report::write(&out_dir, &report)?;
    if !common.compact {
        println!("Summary written: {}", written.display());
    }

    if samples.is_empty() {
        bail!(
            "No benchmark data parsed (check the filter against the n/k registered in the binary)."
        );
    }
    if let Some(code) = exit_code.filter(|c| *c != 0) {
        eprintln!(
            "Note: benchmark process exited with code {code} (JSON parsed; summary written)."
        );
    }
    Ok(())
}

fn join(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_and_split_names() {
        let combined = parse_bench_name("BM_AttrSigCombined_Merkle/32/8").unwrap();
        assert_eq!(combined.kind, Kind::Combined);
        assert_eq!(combined.mode, Mode::Merkle);
        assert_eq!((combined.n, combined.k), (32, 8));

        let prover = parse_bench_name("BM_AttrSigProver_Flat/16/4").unwrap();
        assert_eq!(prover.kind, Kind::Prover);
        assert_eq!(prover.mode, Mode::Flat);

        let verifier = parse_bench_name("BM_AttrSigVerifier_Merkle/8/1").unwrap();
        assert_eq!(verifier.kind, Kind::Verifier);

        assert!(parse_bench_name("BM_Something_Else/1/2").is_none());
    }

    #[test]
    fn alternation_puts_longer_literals_first() {
        assert_eq!(regex_alternation(&[1, 2, 4, 8, 16]), "16|8|4|2|1");
        assert_eq!(regex_alternation(&[8, 16, 32, 64]), "64|32|16|8");
    }

    #[test]
    fn grids_skip_points_where_k_exceeds_n() {
        let samples = BTreeMap::new();
        let (merkle, _) = to_grids(&samples, &[8], &[1, 16]);
        assert!(merkle[&8].contains_key(&1));
        assert!(!merkle[&8].contains_key(&16));
    }
}
