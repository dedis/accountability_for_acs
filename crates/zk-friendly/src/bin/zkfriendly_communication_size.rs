//! Wire-size report for the zk-friendly stack.
//!
//! A Groth16 proof is circuit-independent (128 B compressed) and the public IO
//! is fixed across revocation scales, because the Merkle path and the leaf are
//! private witnesses. The benchmark still runs both provers once so the report
//! is measured rather than asserted.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Serialize;

use bench_core::cli::Out;
use bench_core::report;
use zk_friendly::paths;

/// Compressed BN254 Groth16 proof: `G1 || G2 || G1`.
const GROTH16_COMPRESSED: usize = 32 + 64 + 32;
/// A CFT is nine field elements on the wire.
const CFT_FIELD_ELEMENTS: usize = 9;
const CFT_BYTES: usize = CFT_FIELD_ELEMENTS * 32;
const FIELD_BYTES: usize = 32;
const BITS_PER_LEAF: u32 = 253;
/// Packed depth for a population of 2^29 at 253 bits per leaf.
const DEPTH_AT_2_29: f64 = 22.0;

#[derive(Parser)]
#[command(about = "Communication-cost report for the Circom / Groth16 stack")]
struct Args {
    #[arg(long, env = if std::env::var_os("REVOC_LOG2_LIST").is_some() { "REVOC_LOG2_LIST" } else { "REVOC_LOG2" }, value_delimiter = ',', default_values_t = [12u32, 16, 20, 24])]
    revoc_log2: Vec<u32>,
    #[command(flatten)]
    out: Out,
}

#[derive(Serialize)]
struct ProofSize {
    #[serde(rename = "serializedProofBytes")]
    serialized_proof_bytes: usize,
    note: &'static str,
}

#[derive(Serialize)]
struct PublicInputs {
    count: usize,
    #[serde(rename = "binaryBytes")]
    binary_bytes: usize,
    #[serde(rename = "cftBytes")]
    cft_bytes: usize,
}

#[derive(Serialize)]
struct CftOnly {
    circuit: &'static str,
    proof: ProofSize,
    #[serde(rename = "publicInputs")]
    public_inputs: PublicInputs,
    #[serde(rename = "showMessageIfProofPlusAllPublic")]
    show_message_if_proof_plus_all_public: usize,
    #[serde(rename = "showMessageIfProofPlusCftOnlyCachedKeys")]
    show_message_if_proof_plus_cft_only_cached_keys: usize,
}

#[derive(Serialize, Clone, Copy)]
struct ScaleRow {
    #[serde(rename = "revocLog2")]
    revoc_log2: u32,
    #[serde(rename = "merkleDepth")]
    merkle_depth: u32,
    #[serde(rename = "serializedProofBytes")]
    serialized_proof_bytes: usize,
}

#[derive(Serialize)]
struct Revocation {
    circuit: &'static str,
    #[serde(rename = "cftBytes")]
    cft_bytes: usize,
    #[serde(rename = "publicInputsBytes")]
    public_inputs_bytes: Option<usize>,
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

/// Packed Merkle depth for `2^revoc_log2` credentials.
fn packed_depth(revoc_log2: u32) -> u32 {
    (1u64 << revoc_log2)
        .div_ceil(u64::from(BITS_PER_LEAF))
        .next_power_of_two()
        .trailing_zeros()
}

/// Linear fit `|π| ≈ a·d + b` over packed Merkle depth `d`.
fn fit_vs_depth(rows: &[ScaleRow]) -> Option<DepthFit> {
    let n = rows.len();
    if n < 2 {
        return None;
    }

    let xs: Vec<f64> = rows.iter().map(|r| f64::from(r.merkle_depth)).collect();
    let ys: Vec<f64> = rows
        .iter()
        .map(|r| r.serialized_proof_bytes as f64)
        .collect();

    let sum_x: f64 = xs.iter().sum();
    let sum_y: f64 = ys.iter().sum();
    let sum_xx: f64 = xs.iter().map(|x| x * x).sum();
    let sum_xy: f64 = xs.iter().zip(&ys).map(|(x, y)| x * y).sum();

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
    for (x, y) in xs.iter().zip(&ys) {
        let err = y - (a * x + b);
        ss_res += err * err;
        ss_tot += (y - mean_y).powi(2);
        max_abs_rel = max_abs_rel.max(err.abs() / y);
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

/// Runs a sibling benchmark binary from the same build directory.
fn run_sibling(name: &str, envs: &[(&str, String)]) -> Result<()> {
    let exe = std::env::current_exe()
        .context("locate the running benchmark binary")?
        .with_file_name(name);
    if !exe.is_file() {
        bail!(
            "sibling binary not found at {}. Build the crate first: cargo build --release",
            exe.display()
        );
    }

    println!("\n$ {}", exe.display());
    let mut command = Command::new(&exe);
    for (key, value) in envs {
        command.env(key, value);
    }
    let status = command.status().with_context(|| format!("run {name}"))?;
    if !status.success() {
        bail!("{name} failed ({status})");
    }
    Ok(())
}

fn public_signal_count(path: &Path) -> Result<usize> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let signals: Vec<String> =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    Ok(signals.len())
}

/// One proving run of `prove_verify`; its summary goes under `out_dir`.
fn measure_cft_only(out_dir: &Path) -> Result<CftOnly> {
    println!("=== CFT-only prove_verify ===");
    run_sibling(
        "zkfriendly_prove_verify",
        &[
            ("BENCH_N", "1".into()),
            ("BENCH_WARMUP", "0".into()),
            ("KEEP_ARTIFACTS", "1".into()),
            (
                "BENCH_OUT",
                out_dir.join("prove_verify").display().to_string(),
            ),
        ],
    )?;

    let public_json = paths::artifacts("prove_verify")
        .join("iter_0000")
        .join("public.json");
    let count = public_signal_count(&public_json)?;
    let binary_bytes = count * FIELD_BYTES;

    Ok(CftOnly {
        circuit: "prove_verify (age-check + CFT)",
        proof: ProofSize {
            serialized_proof_bytes: GROTH16_COMPRESSED,
            note: "canonical BN254 Groth16 compressed (32+64+32)",
        },
        public_inputs: PublicInputs {
            count,
            binary_bytes,
            cft_bytes: CFT_BYTES,
        },
        show_message_if_proof_plus_all_public: GROTH16_COMPRESSED + binary_bytes,
        show_message_if_proof_plus_cft_only_cached_keys: GROTH16_COMPRESSED + CFT_BYTES,
    })
}

/// One proving run per scale; its summary goes under `out_dir`.
fn measure_revocation(scales: &[u32], out_dir: &Path) -> Result<Revocation> {
    println!("=== prove_verify + packed revocation ===");
    run_sibling(
        "zkfriendly_prove_verify_revocation",
        &[
            ("BENCH_N", "1".into()),
            ("BENCH_WARMUP", "0".into()),
            ("KEEP_ARTIFACTS", "1".into()),
            (
                "BENCH_OUT",
                out_dir
                    .join("prove_verify_revocation")
                    .display()
                    .to_string(),
            ),
            (
                "REVOC_LOG2_LIST",
                scales
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ],
    )?;

    let artifacts = paths::artifacts("prove_verify_revocation");

    let mut by_scale = Vec::with_capacity(scales.len());
    let mut public_inputs_bytes = None;
    for &revoc_log2 in scales {
        let public_json = artifacts
            .join(format!("l{revoc_log2}"))
            .join("iter_0000")
            .join("public.json");
        let bytes = public_signal_count(&public_json)? * FIELD_BYTES;
        public_inputs_bytes.get_or_insert(bytes);
        by_scale.push(ScaleRow {
            revoc_log2,
            merkle_depth: packed_depth(revoc_log2),
            serialized_proof_bytes: GROTH16_COMPRESSED,
        });
    }

    Ok(Revocation {
        circuit: "prove_verify + CFT + packed status-list",
        cft_bytes: CFT_BYTES,
        public_inputs_bytes,
        by_scale,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let out_dir = args.out.dir(paths::STACK, "communication_size");
    std::fs::create_dir_all(&out_dir)?;

    let cft_only = measure_cft_only(&out_dir)?;
    let revocation = measure_revocation(&args.revoc_log2, &out_dir)?;
    let fit = fit_vs_depth(&revocation.by_scale);

    write_pretty(&out_dir.join("cft_only.json"), &cft_only)?;
    write_pretty(&out_dir.join("revocation.json"), &revocation)?;

    let report = Report {
        meta: Meta {
            kind: "zk-friendly",
        },
        cft_only,
        with_revocation: WithRevocation {
            revocation,
            fit_vs_depth: fit,
        },
    };
    let written = report::write(&out_dir, &report)?;

    println!("\n=== communication-size summary ===");
    println!("{}", serde_json::to_string_pretty(&report)?);
    println!("\nWrote {}", written.display());
    Ok(())
}

fn write_pretty<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut body = serde_json::to_vec_pretty(value)?;
    body.push(b'\n');
    std::fs::write(path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
