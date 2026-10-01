//! Longfellow: age-check + CFT + packed status-list revocation (SHA-256
//! Merkle), swept over population scales.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use bench_core::cli::Out;
use bench_core::report;
use bench_core::stats::{self, Summary};
use bench_core::time;
use standard::cli::Common;
use standard::paths;
use standard::runner::{self, Gbench};

const TEST_NAME: &str = "circuits/tests/ec/prove_verify_revocation_test";
const BITS_PER_LEAF: u32 = 253;

#[derive(Parser)]
#[command(about = "Longfellow prove/verify benchmark for CFT + packed status-list revocation")]
struct Args {
    /// Population scales as log2.
    #[arg(long, env = if std::env::var_os("REVOC_LOG2_LIST").is_some() { "REVOC_LOG2_LIST" } else { "REVOC_LOG2" }, value_delimiter = ',', default_values_t = [12u32, 16, 20, 24])]
    revoc_log2: Vec<u32>,
    /// Google Benchmark filter regex.
    #[arg(long, env = "BENCH_FILTER")]
    filter: Option<String>,
    /// Benchmark binary.
    #[arg(long)]
    bin: Option<PathBuf>,
    #[arg(
        long = "repetitions",
        visible_alias = "n",
        env = if std::env::var_os("BENCH_N").is_some() { "BENCH_N" } else { "BENCH_REPETITIONS" },
        default_value_t = 10
    )]
    repetitions: usize,
    #[arg(long = "min_time", env = "BENCH_MIN_TIME", default_value = "0.05s")]
    min_time: String,
    #[command(flatten)]
    out: Out,
}

#[derive(Serialize)]
struct ScaleResult {
    #[serde(rename = "revocLog2")]
    revoc_log2: Option<u32>,
    population: Option<u64>,
    #[serde(rename = "merkleDepth")]
    merkle_depth: Option<u32>,
    verify: Option<Summary>,
    #[serde(rename = "proverTotal")]
    prover_total: Option<Summary>,
}

#[derive(Serialize)]
struct Meta {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "revocLog2List")]
    revoc_log2_list: Vec<u32>,
    #[serde(rename = "bitsPerLeaf")]
    bits_per_leaf: u32,
    #[serde(rename = "benchN")]
    bench_n: usize,
    warmup: u8,
    #[serde(rename = "timestampIso")]
    timestamp_iso: String,
}

#[derive(Serialize)]
struct RevocationSummary {
    meta: Meta,
    #[serde(rename = "byScale")]
    by_scale: Vec<ScaleResult>,
}

/// Packed SHA-256 status-list Merkle depth for a population of `2^revoc_log2`.
fn packed_merkle_depth(revoc_log2: u32) -> u32 {
    (1u64 << revoc_log2)
        .div_ceil(u64::from(BITS_PER_LEAF))
        .next_power_of_two()
        .trailing_zeros()
}

/// Google Benchmark appends the scale as a trailing `/<log2>` argument.
fn scale_from_bench_name(name: &str) -> Option<u32> {
    name.rsplit_once('/')
        .and_then(|(_, tail)| tail.parse().ok())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let bin = runner::resolve_bin(args.bin, &["LONGFELLOW_REVOC_BENCH_BIN"], TEST_NAME)?;
    let out_dir = args.out.dir(paths::STACK, "prove_verify_revocation");

    let filter = args.filter.unwrap_or_else(|| {
        format!(
            "BM_ProveVerifyRevocationCombined_Packed_P256/({})",
            args.revoc_log2
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join("|")
        )
    });

    println!("Longfellow ProveVerify+CFT+packed revocation (SHA-256 Merkle)");
    println!(
        "  scales: {}",
        args.revoc_log2
            .iter()
            .map(|x| format!("2^{x}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  filter = {filter}");
    println!("  repetitions = {}", args.repetitions);
    println!("  warm-up: {}\n", Common::describe_warmup());

    // Every scale is a separate benchmark, so the inner loop stays at one
    // iteration and the repetitions carry the statistics.
    let gb = Gbench::new(bin, &filter, args.repetitions, &args.min_time, Some(1))?;
    let warmup = Common::warmup_enabled();
    if warmup {
        gb.warmup(false)?;
    }
    let (rows, exit_code) = gb.measured()?;

    // One entry per benchmark name; each name is one population scale.
    let mut by_name: BTreeMap<String, (Vec<f64>, Vec<f64>)> = BTreeMap::new();
    for row in &rows {
        if row.is_aggregate() {
            continue;
        }
        let name = row.name();
        if name.is_empty() {
            continue;
        }
        let entry = by_name.entry(name.to_string()).or_default();
        if let Some(prove_ns) = row.number("prove_ns") {
            entry.0.push(prove_ns / 1e6);
        }
        if let Some(verify_ns) = row.number("verify_ns") {
            entry.1.push(verify_ns / 1e6);
        }
    }

    println!("\n-- Summary (avg ms) --");
    let mut by_scale = Vec::with_capacity(by_name.len());
    for (name, (prove_ms, verify_ms)) in &by_name {
        let revoc_log2 = scale_from_bench_name(name);
        let row = ScaleResult {
            revoc_log2,
            population: revoc_log2.map(|l| 1u64 << l),
            merkle_depth: revoc_log2.map(packed_merkle_depth),
            verify: stats::summary(verify_ms),
            // Longfellow has no witness/prove split: prove_ns is the prover.
            prover_total: stats::summary(prove_ms),
        };
        println!(
            "  2^{} (depth {})  prover={}  verify={}",
            show(row.revoc_log2),
            show(row.merkle_depth),
            avg(row.prover_total),
            avg(row.verify)
        );
        by_scale.push(row);
    }

    let empty = by_scale.is_empty();
    let report = RevocationSummary {
        meta: Meta {
            kind: "longfellow",
            revoc_log2_list: args.revoc_log2,
            bits_per_leaf: BITS_PER_LEAF,
            bench_n: args.repetitions,
            warmup: u8::from(warmup),
            timestamp_iso: time::iso8601_now(),
        },
        by_scale,
    };
    let written = report::write(&out_dir, &report)?;
    println!("\nSummary: {}", written.display());

    if empty {
        std::process::exit(exit_code.unwrap_or(1));
    }
    Ok(())
}

fn show(value: Option<u32>) -> String {
    value.map_or_else(|| "?".to_string(), |v| v.to_string())
}

fn avg(value: Option<Summary>) -> String {
    value.map_or_else(|| "?".to_string(), |s| format!("{:.1}", s.avg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_matches_the_recorded_scales() {
        assert_eq!(packed_merkle_depth(12), 5);
        assert_eq!(packed_merkle_depth(16), 9);
        assert_eq!(packed_merkle_depth(20), 13);
        assert_eq!(packed_merkle_depth(24), 17);
    }

    #[test]
    fn scale_is_read_from_the_benchmark_name() {
        assert_eq!(
            scale_from_bench_name("BM_ProveVerifyRevocationCombined_Packed_P256/16"),
            Some(16)
        );
        assert_eq!(scale_from_bench_name("BM_NoScale"), None);
    }
}
