//! The shared driver for the benchmarks that report one Combined
//! prove/verify pass per repetition.
//!
//! `standard_prove_verify`, `standard_prove_verify_no_cft` and
//! `standard_ml_dsa65` differ only in which binary they run, which filter they
//! default to and how they label themselves.

use bench_core::stats::{self, P95};
use std::collections::BTreeMap;

use anyhow::{bail, Result};

use crate::cli::Common;
use crate::gbench::{self, Meta};
use crate::paths;
use crate::runner::{self, Gbench};
use bench_core::report;
use bench_core::time;

/// What distinguishes one Combined benchmark from another.
pub struct Bench {
    /// One line describing the circuit under test.
    pub backend: &'static str,
    /// `variant` field of the summary metadata, and the output folder name.
    pub variant: &'static str,
    pub default_filter: &'static str,
    /// Binary path relative to the Longfellow build tree.
    pub test_name: &'static str,
    /// Environment variables that may point at the binary, most specific first.
    pub bin_env: &'static [&'static str],
}

pub fn run(bench: &Bench, common: Common, filter: Option<String>) -> Result<()> {
    let filter = filter
        .or_else(|| std::env::var("BENCH_FILTER").ok().filter(|v| !v.is_empty()))
        .unwrap_or_else(|| bench.default_filter.to_string());

    let bin = runner::resolve_bin(common.bin.clone(), bench.bin_env, bench.test_name)?;
    let out_dir = common.out.dir(paths::STACK, bench.variant);

    if common.clean {
        let _ = std::fs::remove_dir_all(&out_dir);
    }

    if !common.compact {
        println!("Backend: {}", bench.backend);
        println!(
            "Repetitions (outer samples): {}  (BENCH_N; --repetitions / --n)",
            common.repetitions
        );
        println!(
            "Inner iterations per rep: {}  (BENCH_ITERATIONS; --iterations; default 1)",
            common.describe_iterations()
        );
        println!("Filter: {filter}  (env BENCH_FILTER)");
        println!("min_time: {}  (env BENCH_MIN_TIME)", common.min_time);
        println!(
            "Metric (verbose only): {:?}  (env BENCH_METRIC)",
            common.metric
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
            "[measured] Live Google Benchmark console follows; JSON for summaries is read \
             from a temp file (--benchmark_out) when the binary exits.\n"
        );
    }

    let (rows, exit_code) = gb.measured()?;
    if rows.is_empty() {
        bail!("No benchmark samples found (check --filter).");
    }

    if common.verbose {
        print_per_run_stats(&rows, &common);
    }

    let Some(report) = gbench::build_timing_summary(
        &rows,
        Meta {
            kind: "longfellow",
            variant: bench.variant,
            n: common.repetitions,
            credential_mode: "init_once_per_show_refresh",
            timestamp_iso: time::iso8601_now(),
        },
    ) else {
        bail!("No Combined prove_ns/verify_ns counters found (check --filter).");
    };

    let written = report::write(&out_dir, &report)?;
    println!("Summary written: {}", written.display());

    if let Some(code) = exit_code.filter(|c| *c != 0) {
        eprintln!(
            "Note: benchmark process exited with code {code} (JSON parsed; summary written)."
        );
    }
    Ok(())
}

/// Per-benchmark `min/avg/median/p95/max` over every matching run.
fn print_per_run_stats(rows: &[gbench::Row], common: &Common) {
    #[derive(Default)]
    struct Series {
        cpu: Vec<f64>,
        real: Vec<f64>,
    }

    let mut by_name: BTreeMap<String, Series> = BTreeMap::new();
    for row in rows {
        if row.is_aggregate() {
            continue;
        }
        let name = gbench::base_name(row.name());
        if name.is_empty() {
            continue;
        }
        let unit = row.time_unit();
        let (Some(cpu), Some(real)) = (row.number("cpu_time"), row.number("real_time")) else {
            continue;
        };
        let entry = by_name.entry(name.to_string()).or_default();
        if let Some(ms) = gbench::to_ms(cpu, unit) {
            entry.cpu.push(ms);
        }
        if let Some(ms) = gbench::to_ms(real, unit) {
            entry.real.push(ms);
        }
    }

    println!("-- Results (printStats) --");
    for (name, series) in &by_name {
        if common.metric.wants_cpu() {
            stats::print_stats(&format!("{name} cpu"), &series.cpu, P95::FloorNMinus1);
        }
        if common.metric.wants_real() {
            stats::print_stats(&format!("{name} real"), &series.real, P95::FloorNMinus1);
        }
    }
    println!();
}
