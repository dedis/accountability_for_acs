//! Age-check presentation without a CFT — the baseline the accountability
//! overhead is measured against.
//!
//! The credential carries a hardware public key instead of the identity point,
//! and the show proves knowledge of a hardware signature over a nonce `m`.

use std::time::Instant;

use anyhow::Result;
use ark_ec::CurveGroup;
use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

use babyjub::curve::{fr_to_fq, rand_scalar, Fq, PointAffine};
use babyjub::eddsa::{SecretKey, Signature};
use babyjub::poseidon::Poseidon;
use bench_core::cli::Out;
use bench_core::report;
use bench_core::stats::{self, P95};
use bench_core::time::{self, elapsed_ms};
use zk_friendly::credential::{
    claim_name, days_ms, eighteen_years_ms, flat_commitment, point_strings, write_json,
    BASE_NOW_MS, NUM_ATTRS,
};
use zk_friendly::groth16::{ProofBundle, VerifyingKey};
use zk_friendly::hash::sha256_utf8_to_field;
use zk_friendly::paths;
use zk_friendly::summary::{AvgMs, Meta, Results, StatsMs, TimingSummary};
use zk_friendly::zk_common::{self, Groth16Spec, IterArgs, Toolchain};

const VARIANT: &str = "prove_verify_no_cft";

/// Slots 14 and 15 hold the hardware key, so they replace the identity labels.
const LABELS: [&str; NUM_ATTRS] = [
    "IDx",
    "IDy",
    "name",
    "familyName",
    "birthDate",
    "validFrom",
    "validUntil",
    "addressStreet",
    "addressNumber",
    "addressLocalityNumber",
    "addressCity",
    "addressCanton",
    "addressCountry",
    "cantonOfOrigin",
    "hwPkX",
    "hwPkY",
    "attr_16",
    "attr_17",
    "attr_18",
    "attr_19",
    "attr_20",
    "attr_21",
    "attr_22",
    "attr_23",
    "attr_24",
    "attr_25",
    "attr_26",
    "attr_27",
    "attr_28",
    "attr_29",
    "attr_30",
    "attr_31",
];

/// The no-CFT credential: no identity point, a hardware key instead.
struct Credential {
    max_birth_date_ms: u64,
    birth_date_ms: u64,
    valid_from_ms: u64,
    valid_until_ms: u64,
    issuer_pub: PointAffine,
    hw_pub: PointAffine,
    nonce: String,
    claim_names: [Fq; NUM_ATTRS],
    claim_values: [Fq; NUM_ATTRS],
    signature: Signature,
    hw_signature: Signature,
}

impl Credential {
    fn issue<R: Rng + ?Sized>(poseidon: &Poseidon, rng: &mut R) -> Self {
        let max_birth_date_ms = BASE_NOW_MS - eighteen_years_ms();
        let birth_date_ms = max_birth_date_ms - days_ms(365);
        let valid_from_ms = BASE_NOW_MS - days_ms(1);
        let valid_until_ms = BASE_NOW_MS + days_ms(365);

        let issuer = SecretKey::rand(rng);
        let hw = SecretKey::rand(rng);
        let hw_pub = hw.public_key().into_affine();
        let nonce = rand_scalar(rng);

        let claim_names = LABELS.map(|label| claim_name(poseidon, label));
        let mut claim_values = [Fq::from(0u64); NUM_ATTRS];
        claim_values[2] = sha256_utf8_to_field("Alice");
        claim_values[3] = sha256_utf8_to_field("Doe");
        claim_values[4] = Fq::from(birth_date_ms);
        claim_values[5] = Fq::from(valid_from_ms);
        claim_values[6] = Fq::from(valid_until_ms);
        claim_values[7] = sha256_utf8_to_field("Main Street");
        claim_values[8] = Fq::from(12u64);
        claim_values[9] = Fq::from(1000u64);
        claim_values[10] = sha256_utf8_to_field("Lausanne");
        claim_values[11] = sha256_utf8_to_field("VD");
        claim_values[12] = sha256_utf8_to_field("CH");
        claim_values[13] = sha256_utf8_to_field("VD");
        claim_values[14] = hw_pub.x;
        claim_values[15] = hw_pub.y;

        let commitment = flat_commitment(poseidon, &claim_names, &claim_values);
        let nonce_field = fr_to_fq(nonce);

        Self {
            max_birth_date_ms,
            birth_date_ms,
            valid_from_ms,
            valid_until_ms,
            issuer_pub: issuer.public_key().into_affine(),
            hw_pub,
            nonce: nonce.to_string(),
            claim_names,
            claim_values,
            signature: issuer.sign_poseidon(poseidon, commitment, rng),
            hw_signature: hw.sign_poseidon(poseidon, nonce_field, rng),
        }
    }

    fn show_input(&self, show_index: u64) -> ShowInput {
        ShowInput {
            issuer_pub_key: point_strings(self.issuer_pub),
            m: self.nonce.clone(),
            now: (BASE_NOW_MS + show_index).to_string(),
            max_birth_date: self.max_birth_date_ms.to_string(),
            bd_claim_name: self.claim_names[4].to_string(),
            vf_claim_name: self.claim_names[5].to_string(),
            vu_claim_name: self.claim_names[6].to_string(),
            hw_pk_x_claim_name: self.claim_names[14].to_string(),
            hw_pk_y_claim_name: self.claim_names[15].to_string(),
            pad0: "0".into(),
            pad1: "0".into(),
            pad2: "0".into(),
            pad3: "0".into(),
            pad4: "0".into(),
            pad5: "0".into(),
            claim_names: self.claim_names.iter().map(Fq::to_string).collect(),
            claim_values: self.claim_values.iter().map(Fq::to_string).collect(),
            birth_date: self.birth_date_ms.to_string(),
            valid_from: self.valid_from_ms.to_string(),
            valid_until: self.valid_until_ms.to_string(),
            hw_pk: point_strings(self.hw_pub),
            sig_r: point_strings(self.signature.r8),
            sig_s: self.signature.s.to_string(),
            hw_sig_r: point_strings(self.hw_signature.r8),
            hw_sig_s: self.hw_signature.s.to_string(),
        }
    }
}

#[derive(Serialize)]
struct ShowInput {
    #[serde(rename = "issuerPubKey")]
    issuer_pub_key: [String; 2],
    m: String,
    now: String,
    #[serde(rename = "maxBirthDate")]
    max_birth_date: String,
    #[serde(rename = "bdClaimName")]
    bd_claim_name: String,
    #[serde(rename = "vfClaimName")]
    vf_claim_name: String,
    #[serde(rename = "vuClaimName")]
    vu_claim_name: String,
    #[serde(rename = "hwPkXClaimName")]
    hw_pk_x_claim_name: String,
    #[serde(rename = "hwPkYClaimName")]
    hw_pk_y_claim_name: String,
    pad0: String,
    pad1: String,
    pad2: String,
    pad3: String,
    pad4: String,
    pad5: String,
    #[serde(rename = "claimNames")]
    claim_names: Vec<String>,
    #[serde(rename = "claimValues")]
    claim_values: Vec<String>,
    #[serde(rename = "birthDate")]
    birth_date: String,
    #[serde(rename = "validFrom")]
    valid_from: String,
    #[serde(rename = "validUntil")]
    valid_until: String,
    #[serde(rename = "hwPk")]
    hw_pk: [String; 2],
    #[serde(rename = "sig_R")]
    sig_r: [String; 2],
    #[serde(rename = "sig_S")]
    sig_s: String,
    #[serde(rename = "hwSig_R")]
    hw_sig_r: [String; 2],
    #[serde(rename = "hwSig_S")]
    hw_sig_s: String,
}

#[derive(Parser)]
#[command(about = "Groth16 prove/verify benchmark for the no-CFT age-check baseline")]
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

    let zk = Toolchain::from_env(args.verbose);
    let spec = Groth16Spec::new(paths::circuits().join("prove_verify_no_cft.circom"));
    let artifacts = zk.prepare_groth16(&spec)?;

    zk.section("Initialising crypto primitives");
    let poseidon = Poseidon::new();
    let mut rng = StdRng::from_entropy();
    let credential = Credential::issue(&poseidon, &mut rng);
    let vkey = VerifyingKey::read(&artifacts.vkey)?;

    zk.section(&format!("Benchmark — {} iterations", args.iters.n));
    if !args.verbose {
        println!("Iterations: {}", args.iters.describe());
        println!(
            "Cleanup after run: {}",
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
        write_json(&input_path, &credential.show_input(i as u64))?;
        let witness = zk.run_witness(&artifacts.witness_bin, &input_path, &witness_path)?;
        let w_ms = elapsed_ms(started);
        if !witness.ok {
            eprintln!("  iter {i}: witness FAILED");
            failures += 1;
            continue;
        }

        let started = Instant::now();
        let proved = zk.run_prover(&artifacts.zkey, &witness_path, &proof_path, &public_path)?;
        let p_ms = elapsed_ms(started);
        if !proved.ok {
            eprintln!("  iter {i}: prove FAILED");
            failures += 1;
            continue;
        }
        if !proof_path.is_file() || !public_path.is_file() {
            eprintln!("  iter {i}: prove produced no proof/public outputs");
            if args.verbose {
                eprintln!("{}", proved.message());
            }
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

    if args.verbose && successful > 0 {
        stats::print_stats("witness", &witness_ms, P95::FloorN);
        stats::print_stats("prove", &prove_ms, P95::FloorN);
        stats::print_stats("verify", &verify_ms, P95::FloorN);
        stats::print_stats("prover total", &prover_total, P95::FloorN);
        stats::print_stats("full cycle", &full_cycle, P95::FloorN);
    }

    zk_common::clean_artifacts(&artifacts_dir, args.keep_artifacts);

    if !args.verbose {
        println!(
            "Summary written: {} ({})",
            written.display(),
            if args.keep_artifacts {
                "artifacts kept"
            } else {
                "artifacts cleaned"
            }
        );
        if let Some(v) = summary.stats_ms.verify {
            println!(
                "  verify median: {:.1} ms (max {:.1} ms)",
                v.median_ms, v.max_ms
            );
        }
    }

    if failures > 0 {
        std::process::exit(1);
    }
    Ok(())
}
