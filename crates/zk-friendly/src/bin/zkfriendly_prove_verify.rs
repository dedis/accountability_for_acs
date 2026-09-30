//! Age-check presentation with a CFT: `C4 = EdDSA(poseidon(t, r2·pk))` under
//! the credential identity, flat commitment over 32 attributes.
//!
//! Timing:
//! - `witness` — per-show input refresh, writing `input.json`, and the circom
//!   C++ witness calculator. Issuance runs once and is not counted.
//! - `prove` — rapidsnark only.
//! - `verify` — the Groth16 pairing check only; parsing happens outside the
//!   timer, with the verification key read once.

use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Result};
use clap::Parser;
use rand::rngs::StdRng;
use rand::SeedableRng;

use babyjub::poseidon::Poseidon;
use bench_core::cli::Out;
use bench_core::report;
use bench_core::stats::{self, SummaryMs, P95};
use bench_core::time::{self, elapsed_ms};
use zk_friendly::credential::{write_json, Credential};
use zk_friendly::groth16::{ProofBundle, VerifyingKey};
use zk_friendly::paths;
use zk_friendly::summary::{AvgMs, Meta, Results, StatsMs, TimingSummary};
use zk_friendly::zk_common::{self, Groth16Spec, IterArgs, Toolchain};

const VARIANT: &str = "prove_verify";

#[derive(Parser)]
#[command(about = "Groth16 prove/verify benchmark for the age-check + CFT presentation")]
struct Args {
    /// Print setup sections and per-iteration lines.
    #[arg(long)]
    verbose: bool,
    /// Keep the per-iteration inputs, witnesses and proofs.
    #[arg(long, env = "KEEP_ARTIFACTS", value_parser = clap::builder::BoolishValueParser::new())]
    keep_artifacts: bool,
    #[command(flatten)]
    iters: IterArgs,
    #[command(flatten)]
    out: Out,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let artifacts_dir = paths::artifacts(VARIANT);
    std::fs::create_dir_all(&artifacts_dir)?;

    if !args.verbose {
        println!("Setting up Groth16 artifacts (compile + zkey + witness generator on first run).");
        println!(
            "  This can take several minutes with no other output — use --verbose for details.\n"
        );
    }

    let zk = Toolchain::from_env(args.verbose);
    let spec = Groth16Spec::new(paths::circuits().join("prove_verify.circom"));
    let artifacts = zk.prepare_groth16(&spec)?;

    let poseidon = Poseidon::new();
    let mut rng = StdRng::from_entropy();
    let credential = Credential::issue(&poseidon, &mut rng);

    let vkey = VerifyingKey::read(&artifacts.vkey)?;

    if !args.verbose {
        println!("Iterations: {}", args.iters.describe());
        println!(
            "Cleanup after run: {}\n",
            if args.keep_artifacts {
                "disabled (--keep-artifacts)"
            } else {
                "enabled (default)"
            }
        );
    }

    let mut witness_ms = Vec::with_capacity(args.iters.n);
    let mut prove_ms = Vec::with_capacity(args.iters.n);
    let mut verify_ms = Vec::with_capacity(args.iters.n);
    let mut failures = 0usize;

    for i in 0..(args.iters.n + args.iters.warmup) {
        let is_warmup = i < args.iters.warmup;
        let iter_dir = artifacts_dir.join(format!("iter_{i:04}"));
        std::fs::create_dir_all(&iter_dir)?;

        let input_path = iter_dir.join("input.json");
        let witness_path = iter_dir.join("witness.wtns");
        let proof_path = iter_dir.join("proof.json");
        let public_path = iter_dir.join("public.json");

        let started = Instant::now();
        let input = credential.show_input(&poseidon, i as u64, &mut rng);
        write_json(&input_path, &input)?;
        let witness = zk.run_witness(&artifacts.witness_bin, &input_path, &witness_path)?;
        let w_ms = elapsed_ms(started);
        if !witness.ok {
            eprintln!("  iter {i}: witness FAILED");
            if args.verbose {
                eprintln!("{}", witness.message());
            }
            failures += 1;
            continue;
        }

        let started = Instant::now();
        let proved = zk.run_prover(&artifacts.zkey, &witness_path, &proof_path, &public_path)?;
        let p_ms = elapsed_ms(started);
        if !proved.ok {
            eprintln!("  iter {i}: prove FAILED");
            if args.verbose {
                eprintln!("{}", proved.message());
            }
            failures += 1;
            continue;
        }
        if !proof_path.is_file() || !public_path.is_file() {
            eprintln!("  iter {i}: prove produced no proof/public outputs");
            failures += 1;
            continue;
        }

        let bundle = ProofBundle::read(&proof_path, &public_path)?;

        if is_warmup {
            for _ in 0..args.iters.verify_warmup {
                bundle.verify(&vkey)?;
            }
        }

        let started = Instant::now();
        let ok = bundle.verify(&vkey)?;
        let v_ms = elapsed_ms(started);
        if !ok {
            eprintln!("  iter {i}: verify FAILED");
            failures += 1;
            continue;
        }

        if !is_warmup {
            witness_ms.push(w_ms);
            prove_ms.push(p_ms);
            verify_ms.push(v_ms);
            if args.verbose {
                println!(
                    "  [{:>3}/{}] witness={w_ms:.0}ms  prove={p_ms:.0}ms  verify={v_ms:.0}ms  total={:.0}ms",
                    i - args.iters.warmup + 1,
                    args.iters.n,
                    w_ms + p_ms + v_ms
                );
            }
        }
    }

    let successful = witness_ms.len();
    let prover_total = stats::add_series(&witness_ms, &prove_ms);
    let full_cycle = stats::add_series(&prover_total, &verify_ms);

    let summary = TimingSummary {
        meta: Meta {
            kind: "zk-friendly",
            variant: VARIANT,
            n: args.iters.n,
            credential_mode: "init_once_per_show_refresh",
            timestamp_iso: time::iso8601_now(),
        },
        results: Results {
            successful_iters: successful,
        },
        avg_ms: AvgMs {
            witness: stats::mean(&witness_ms),
            prove: stats::mean(&prove_ms),
            verify: stats::mean(&verify_ms),
        },
        stats_ms: StatsMs {
            witness: stats::summary_ms(&witness_ms, P95::FloorN),
            prove: stats::summary_ms(&prove_ms, P95::FloorN),
            verify: stats::summary_ms(&verify_ms, P95::FloorN),
            prover_total: stats::summary_ms(&prover_total, P95::FloorN),
            full_cycle: stats::summary_ms(&full_cycle, P95::FloorN),
        },
    };
    let written = report::write(&args.out.dir(paths::STACK, VARIANT), &summary)?;

    print_report(&args, &written, &summary, successful, failures);
    zk_common::clean_artifacts(&artifacts_dir, args.keep_artifacts);

    if failures > 0 {
        bail!("{failures} iteration(s) failed");
    }
    Ok(())
}

fn print_report(
    args: &Args,
    written: &Path,
    summary: &TimingSummary,
    successful: usize,
    failures: usize,
) {
    if args.verbose {
        return;
    }
    println!(
        "\nSummary written: {} ({})",
        written.display(),
        if args.keep_artifacts {
            "artifacts kept"
        } else {
            "artifacts cleaned"
        }
    );

    match summary.stats_ms.full_cycle {
        Some(cycle) if successful > 0 => {
            println!(
                "  full cycle avg: {:.1} ms ({successful}/{} ok)",
                cycle.avg_ms, args.iters.n
            );
            print_verify_note(summary.stats_ms.verify);
        }
        _ if failures > 0 => println!("  {failures} iteration(s) failed"),
        _ => {}
    }
}

fn print_verify_note(verify: Option<SummaryMs>) {
    if let Some(v) = verify {
        println!(
            "  verify median: {:.1} ms (max {:.1} ms)",
            v.median_ms, v.max_ms
        );
    }
}
