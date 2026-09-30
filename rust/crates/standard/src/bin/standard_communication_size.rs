//! Wire-size report for the Longfellow stack.
//!
//! The two `build_measure_longfellow_*.sh` scripts compile and run the C++
//! measurement programs; this driver runs them, reads their JSON and fits the
//! proof size against the packed Merkle depth.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use bench_core::cli::Out;
use bench_core::report;
use standard::paths;

/// Packed depth for a population of 2^29 at 253 bits per leaf.
const DEPTH_AT_2_29: f64 = 22.0;

#[derive(Parser)]
#[command(about = "Communication-cost report for the Longfellow stack")]
struct Args {
    /// Revocation population scales as log2, passed through to the measure script.
    #[arg(long, env = if std::env::var_os("REVOC_LOG2_LIST").is_some() { "REVOC_LOG2_LIST" } else { "REVOC_LOG2" }, value_delimiter = ',', default_values_t = [12u32, 16, 20, 24])]
    revoc_log2: Vec<u32>,
    #[command(flatten)]
    out: Out,
}

/// What `measure_longfellow_prove_verify_proof_size` reports.
#[derive(Deserialize, Serialize)]
struct CftOnly {
    circuit: Value,
    proof: Value,
    #[serde(rename = "publicInputs")]
    public_inputs: Value,
    #[serde(rename = "showMessageIfProofPlusAllPublic")]
    show_message_if_proof_plus_all_public: Value,
    #[serde(rename = "showMessageIfProofPlusCftOnlyCachedKeys")]
    show_message_if_proof_plus_cft_only_cached_keys: Value,
}

#[derive(Deserialize, Serialize, Clone)]
struct ScaleRow {
    #[serde(rename = "merkleDepth")]
    merkle_depth: f64,
    #[serde(rename = "serializedProofBytes")]
    serialized_proof_bytes: f64,
    #[serde(flatten)]
    rest: Value,
}

/// What `measure_longfellow_prove_verify_revocation_proof_size` reports.
#[derive(Deserialize, Serialize)]
struct Revocation {
    circuit: Value,
    #[serde(rename = "cftBytes")]
    cft_bytes: Value,
    #[serde(rename = "publicInputsBytes")]
    public_inputs_bytes: Value,
    #[serde(rename = "byScale")]
    by_scale: Vec<ScaleRow>,
}

#[derive(Serialize)]
struct DepthFit {
    formula: String,
    r2: f64,
    #[serde(rename = "maxAbsRelErrorPct")]
    max_abs_rel_error_pct: f64,
    #[serde(rename = "extrapolated_2_29_d22_bytes")]
    extrapolated_2_29_d22_bytes: i64,
}

#[derive(Serialize)]
struct WithRevocation {
    #[serde(flatten)]
    revocation: Revocation,
    #[serde(rename = "fitVsDepth")]
    fit_vs_depth: Option<DepthFit>,
}

#[derive(Serialize)]
struct Meta {
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
struct Report {
    meta: Meta,
    #[serde(rename = "cftOnly")]
    cft_only: CftOnly,
    #[serde(rename = "withRevocation")]
    with_revocation: WithRevocation,
}

/// Linear fit `|π| ≈ a·d + b` over packed Merkle depth `d`.
fn fit_vs_depth(rows: &[ScaleRow]) -> Option<DepthFit> {
    let n = rows.len();
    if n < 2 {
        return None;
    }

    let sum_x: f64 = rows.iter().map(|r| r.merkle_depth).sum();
    let sum_y: f64 = rows.iter().map(|r| r.serialized_proof_bytes).sum();
    let sum_xx: f64 = rows.iter().map(|r| r.merkle_depth * r.merkle_depth).sum();
    let sum_xy: f64 = rows
        .iter()
        .map(|r| r.merkle_depth * r.serialized_proof_bytes)
        .sum();

    let n_f = n as f64;
    let denom = n_f * sum_xx - sum_x * sum_x;
    if denom == 0.0 {
        return None;
    }
    let a = (n_f * sum_xy - sum_x * sum_y) / denom;
    let b = (sum_y - a * sum_x) / n_f;

    let mean_y = sum_y / n_f;
    let mut ss_res = 0.0;
    let mut ss_tot = 0.0;
    let mut max_abs_rel = 0.0f64;
    for row in rows {
        let err = row.serialized_proof_bytes - (a * row.merkle_depth + b);
        ss_res += err * err;
        ss_tot += (row.serialized_proof_bytes - mean_y).powi(2);
        max_abs_rel = max_abs_rel.max(err.abs() / row.serialized_proof_bytes);
    }

    Some(DepthFit {
        formula: format!(
            "|pi| ≈ {}*d + {} bytes  (~{:.1} KB*d + {:.0} KB)",
            a.round(),
            b.round(),
            a / 1024.0,
            b / 1024.0
        ),
        r2: round_to(
            if ss_tot == 0.0 {
                1.0
            } else {
                1.0 - ss_res / ss_tot
            },
            4,
        ),
        max_abs_rel_error_pct: round_to(max_abs_rel * 100.0, 2),
        extrapolated_2_29_d22_bytes: (a * DEPTH_AT_2_29 + b).round() as i64,
    })
}

fn round_to(value: f64, decimals: i32) -> f64 {
    let scale = 10f64.powi(decimals);
    (value * scale).round() / scale
}

/// Runs one measure script and reads the JSON it writes.
fn run_measure<T: for<'de> Deserialize<'de>>(
    script: &str,
    json_out: &Path,
    scales: &str,
) -> Result<T> {
    let script_path = paths::measure().join(script);
    println!("\n=== {script} ===");

    // The scripts take every Longfellow path from here, so it is set once.
    let status = Command::new("bash")
        .arg(&script_path)
        .env("LONGFELLOW_LIB", paths::longfellow().join("lib"))
        .env("LONGFELLOW_BUILD_DIR", paths::build_dir())
        .env("MEASURE_JSON_OUT", json_out)
        .env("REVOC_LOG2_LIST", scales)
        .status()
        .with_context(|| format!("run {}", script_path.display()))?;
    if !status.success() {
        bail!("{script} failed ({status})");
    }

    let text = std::fs::read_to_string(json_out)
        .with_context(|| format!("missing {}", json_out.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", json_out.display()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out_dir = args.out.dir(paths::STACK, "communication_size");
    std::fs::create_dir_all(&out_dir)?;

    let scales = args
        .revoc_log2
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let cft_json = out_dir.join("cft_only.json");
    let revoc_json = out_dir.join("revocation.json");

    let cft_only: CftOnly = run_measure(
        "build_measure_longfellow_prove_verify_proof_size.sh",
        &cft_json,
        &scales,
    )?;
    let revocation: Revocation = run_measure(
        "build_measure_longfellow_prove_verify_revocation_proof_size.sh",
        &revoc_json,
        &scales,
    )?;

    let report = Report {
        meta: Meta { kind: "longfellow" },
        cft_only,
        with_revocation: WithRevocation {
            fit_vs_depth: fit_vs_depth(&revocation.by_scale),
            revocation,
        },
    };
    let written = report::write(&out_dir, &report)?;

    println!("\n=== communication-size summary ===");
    println!("{}", serde_json::to_string_pretty(&report)?);
    println!("\nWrote {}", written.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(depth: f64, bytes: f64) -> ScaleRow {
        ScaleRow {
            merkle_depth: depth,
            serialized_proof_bytes: bytes,
            rest: Value::Null,
        }
    }

    #[test]
    fn fit_needs_at_least_two_points() {
        assert!(fit_vs_depth(&[]).is_none());
        assert!(fit_vs_depth(&[row(5.0, 1000.0)]).is_none());
    }

    #[test]
    fn fit_recovers_an_exact_line() {
        let rows = [
            row(5.0, 1000.0 * 5.0 + 2000.0),
            row(9.0, 1000.0 * 9.0 + 2000.0),
            row(13.0, 1000.0 * 13.0 + 2000.0),
        ];
        let fit = fit_vs_depth(&rows).unwrap();
        assert_eq!(fit.r2, 1.0);
        assert_eq!(fit.max_abs_rel_error_pct, 0.0);
        assert_eq!(fit.extrapolated_2_29_d22_bytes, 24_000);
        assert!(fit.formula.starts_with("|pi| ≈ 1000*d + 2000 bytes"));
    }
}
