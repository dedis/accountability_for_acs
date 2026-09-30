//! Attribute-commitment sweep: a Merkle root over per-claim leaves versus a
//! flat Poseidon accumulator over every claim.
//!
//! For each `(total attributes n, disclosed attributes k)` the benchmark
//! generates both circuits, proves and verifies them, and reports average
//! prover and verifier time.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Result};
use ark_ff::UniformRand;
use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use serde_json::{json, Map, Value};

use babyjub::curve::Fq;
use babyjub::poseidon::Poseidon;
use bench_core::cli::Out;
use bench_core::report;
use bench_core::stats::{self, P95};
use bench_core::time::{self, elapsed_ms};
use zk_friendly::credential::claim_name;
use zk_friendly::groth16::{ProofBundle, VerifyingKey};
use zk_friendly::paths;
use zk_friendly::poseidon_merkle::{build_leaf, MerkleTree};
use zk_friendly::zk_common::{self, Groth16Spec, Toolchain};

const BENCH: &str = "merkle_vs_flat";

#[derive(Parser)]
#[command(about = "Merkle versus flat attribute commitment sweep")]
struct Args {
    /// Credential sizes n.
    #[arg(long, env = "TOTAL_ATTRS", value_delimiter = ',', default_values_t = [8usize, 16, 32, 64])]
    totals: Vec<usize>,
    /// Disclosed counts k; points with k > n are skipped.
    #[arg(long, env = "USED_ATTRS", value_delimiter = ',', default_values_t = [1usize, 2, 4, 8, 16])]
    used: Vec<usize>,
    #[arg(long, env = "BENCH_N", default_value_t = 10)]
    n: usize,
    #[arg(long)]
    verbose: bool,
    /// Compatibility flag; quiet output is already the default.
    #[arg(long)]
    quiet: bool,
    /// Hide per-point sample statistics.
    #[arg(long)]
    compact: bool,
    /// Remove this sweep's generated circuits and artifacts before running.
    #[arg(long, env = "CLEAN", value_parser = clap::builder::BoolishValueParser::new())]
    clean: bool,
    /// Keep the per-iteration inputs, witnesses and proofs.
    #[arg(long, env = "KEEP_ARTIFACTS", value_parser = clap::builder::BoolishValueParser::new())]
    keep_artifacts: bool,
    #[command(flatten)]
    out: Out,
}

/// Which commitment scheme a point measures.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Merkle,
    Flat,
}

impl Mode {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Merkle => "merkle",
            Self::Flat => "flat",
        }
    }
}

#[derive(Serialize, Clone, Copy)]
struct Cell {
    #[serde(rename = "avgWitnessMs")]
    avg_witness_ms: Option<f64>,
    #[serde(rename = "avgProveMs")]
    avg_prove_ms: Option<f64>,
    #[serde(rename = "avgProverMs")]
    avg_prover_ms: Option<f64>,
    #[serde(rename = "avgVerifyMs")]
    avg_verify_ms: Option<f64>,
    #[serde(rename = "successfulIters")]
    successful_iters: usize,
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

fn merkle_circuit(total_attrs: usize, used_attrs: usize) -> String {
    let depth = total_attrs.trailing_zeros();
    let mut lines = vec![
        "pragma circom 2.0.0;".to_string(),
        String::new(),
        "include \"circomlib/circuits/poseidon.circom\";".to_string(),
        "include \"circomlib/circuits/switcher.circom\";".to_string(),
        String::new(),
        "template MerkleClaimProof(depth) {".to_string(),
        "    signal input claimName;".to_string(),
        "    signal input claimValue;".to_string(),
        "    signal input pathElements[depth];".to_string(),
        "    signal input pathIndices[depth];".to_string(),
        "    signal output root;".to_string(),
        String::new(),
        "    component nameHash = Poseidon(1);".to_string(),
        "    nameHash.inputs[0] <== claimName;".to_string(),
        String::new(),
        "    component leafHash = Poseidon(2);".to_string(),
        "    leafHash.inputs[0] <== nameHash.out;".to_string(),
        "    leafHash.inputs[1] <== claimValue;".to_string(),
        String::new(),
        "    component hashers[depth];".to_string(),
        "    component switchers[depth];".to_string(),
        "    signal currentHash[depth + 1];".to_string(),
        "    currentHash[0] <== leafHash.out;".to_string(),
        String::new(),
        "    for (var i = 0; i < depth; i++) {".to_string(),
        "        switchers[i] = Switcher();".to_string(),
        "        switchers[i].sel <== pathIndices[i];".to_string(),
        "        switchers[i].L   <== currentHash[i];".to_string(),
        "        switchers[i].R   <== pathElements[i];".to_string(),
        String::new(),
        "        hashers[i] = Poseidon(2);".to_string(),
        "        hashers[i].inputs[0] <== switchers[i].outL;".to_string(),
        "        hashers[i].inputs[1] <== switchers[i].outR;".to_string(),
        String::new(),
        "        currentHash[i + 1] <== hashers[i].out;".to_string(),
        "    }".to_string(),
        String::new(),
        "    root <== currentHash[depth];".to_string(),
        "}".to_string(),
        String::new(),
        "template CredentialMerkleBench() {".to_string(),
        "    signal input root;".to_string(),
        String::new(),
    ];

    for i in 0..used_attrs {
        lines.push(format!("    signal input claimName_{i};"));
        lines.push(format!("    signal input claimValue_{i};"));
        lines.push(format!("    signal input pathElements_{i}[{depth}];"));
        lines.push(format!("    signal input pathIndices_{i}[{depth}];"));
        lines.push(String::new());
    }

    lines.push("    signal output ok;".to_string());
    lines.push(String::new());
    lines.push(format!("    component proofs[{used_attrs}];"));
    for i in 0..used_attrs {
        lines.push(format!("    proofs[{i}] = MerkleClaimProof({depth});"));
        lines.push(format!("    proofs[{i}].claimName <== claimName_{i};"));
        lines.push(format!("    proofs[{i}].claimValue <== claimValue_{i};"));
        lines.push(format!("    for (var d = 0; d < {depth}; d++) {{"));
        lines.push(format!(
            "        proofs[{i}].pathElements[d] <== pathElements_{i}[d];"
        ));
        lines.push(format!(
            "        proofs[{i}].pathIndices[d]  <== pathIndices_{i}[d];"
        ));
        lines.push("    }".to_string());
        lines.push(format!("    proofs[{i}].root === root;"));
        lines.push(String::new());
    }

    let mut public_inputs = vec!["root".to_string()];
    public_inputs.extend((0..used_attrs).map(|i| format!("claimName_{i}")));

    lines.push("    ok <== 1;".to_string());
    lines.push("}".to_string());
    lines.push(String::new());
    lines.push(format!(
        "component main {{public [{}]}} = CredentialMerkleBench();",
        public_inputs.join(", ")
    ));
    lines.push(String::new());
    lines.join("\n")
}

fn flat_circuit(total_attrs: usize, used_attrs: usize) -> String {
    let mut public_inputs = vec!["flatHash".to_string()];
    for i in 0..used_attrs {
        public_inputs.push(format!("revealName_{i}"));
        public_inputs.push(format!("revealValue_{i}"));
    }

    let mut lines = vec![
        "pragma circom 2.0.0;".to_string(),
        String::new(),
        "include \"circomlib/circuits/poseidon.circom\";".to_string(),
        String::new(),
        "template CredentialFlatBench() {".to_string(),
        "    signal input flatHash;".to_string(),
        String::new(),
        format!("    signal input claimNames[{total_attrs}];"),
        format!("    signal input claimValues[{total_attrs}];"),
        String::new(),
    ];

    for i in 0..used_attrs {
        lines.push(format!("    signal input revealName_{i};"));
        lines.push(format!("    signal input revealValue_{i};"));
    }
    lines.push(String::new());
    lines.push("    signal output ok;".to_string());
    lines.push(String::new());
    for i in 0..used_attrs {
        lines.push(format!("    revealName_{i} === claimNames[{i}];"));
        lines.push(format!("    revealValue_{i} === claimValues[{i}];"));
    }
    lines.push(String::new());
    lines.push(format!("    signal acc[{total_attrs} + 1];"));
    lines.push("    acc[0] <== 0;".to_string());
    lines.push(format!("    component mix[{total_attrs}];"));
    lines.push(format!("    for (var i = 0; i < {total_attrs}; i++) {{"));
    lines.push("        mix[i] = Poseidon(3);".to_string());
    lines.push("        mix[i].inputs[0] <== acc[i];".to_string());
    lines.push("        mix[i].inputs[1] <== claimNames[i];".to_string());
    lines.push("        mix[i].inputs[2] <== claimValues[i];".to_string());
    lines.push("        acc[i + 1] <== mix[i].out;".to_string());
    lines.push("    }".to_string());
    lines.push(String::new());
    lines.push(format!("    flatHash === acc[{total_attrs}];"));
    lines.push(String::new());
    lines.push("    ok <== 1;".to_string());
    lines.push("}".to_string());
    lines.push(String::new());
    lines.push(format!(
        "component main {{public [{}]}} = CredentialFlatBench();",
        public_inputs.join(", ")
    ));
    lines.push(String::new());
    lines.join("\n")
}

/// A fresh credential: deterministic claim names, random claim values.
fn fresh_credential<R: Rng + ?Sized>(
    poseidon: &Poseidon,
    total_attrs: usize,
    rng: &mut R,
) -> (Vec<Fq>, Vec<Fq>) {
    let names = (0..total_attrs)
        .map(|i| claim_name(poseidon, &format!("attr_{i}")))
        .collect();
    let values = (0..total_attrs).map(|_| Fq::rand(rng)).collect();
    (names, values)
}

fn merkle_input<R: Rng + ?Sized>(
    poseidon: &Poseidon,
    total_attrs: usize,
    used_attrs: usize,
    rng: &mut R,
) -> Result<Value> {
    let (names, values) = fresh_credential(poseidon, total_attrs, rng);
    let depth = total_attrs.trailing_zeros() as usize;

    let leaves: Vec<Fq> = names
        .iter()
        .zip(&values)
        .map(|(name, value)| build_leaf(poseidon, *name, *value))
        .collect();
    let tree = MerkleTree::build(poseidon, &leaves)?;

    let mut input = Map::new();
    input.insert("root".into(), json!(tree.root().to_string()));
    for i in 0..used_attrs {
        let proof = tree.proof(i, depth)?;
        input.insert(format!("claimName_{i}"), json!(names[i].to_string()));
        input.insert(format!("claimValue_{i}"), json!(values[i].to_string()));
        input.insert(
            format!("pathElements_{i}"),
            json!(proof
                .path_elements
                .iter()
                .map(Fq::to_string)
                .collect::<Vec<_>>()),
        );
        input.insert(format!("pathIndices_{i}"), json!(proof.path_indices));
    }
    Ok(Value::Object(input))
}

fn flat_input<R: Rng + ?Sized>(
    poseidon: &Poseidon,
    total_attrs: usize,
    used_attrs: usize,
    rng: &mut R,
) -> Value {
    let (names, values) = fresh_credential(poseidon, total_attrs, rng);

    let mut acc = Fq::from(0u64);
    for i in 0..total_attrs {
        acc = poseidon.hash(&[acc, names[i], values[i]]);
    }

    let mut input = Map::new();
    input.insert("flatHash".into(), json!(acc.to_string()));
    input.insert(
        "claimNames".into(),
        json!(names.iter().map(Fq::to_string).collect::<Vec<_>>()),
    );
    input.insert(
        "claimValues".into(),
        json!(values.iter().map(Fq::to_string).collect::<Vec<_>>()),
    );
    for i in 0..used_attrs {
        input.insert(format!("revealName_{i}"), json!(names[i].to_string()));
        input.insert(format!("revealValue_{i}"), json!(values[i].to_string()));
    }
    Value::Object(input)
}

struct Point {
    mode: Mode,
    total_attrs: usize,
    used_attrs: usize,
}

impl Point {
    fn label(&self) -> String {
        format!(
            "{}_t{}_u{}",
            self.mode.prefix(),
            self.total_attrs,
            self.used_attrs
        )
    }
}

fn bench_point(
    point: &Point,
    args: &Args,
    zk: &Toolchain,
    poseidon: &Poseidon,
    artifacts_dir: &Path,
    rng: &mut StdRng,
) -> Result<Cell> {
    let label = point.label();
    let source = match point.mode {
        Mode::Merkle => merkle_circuit(point.total_attrs, point.used_attrs),
        Mode::Flat => flat_circuit(point.total_attrs, point.used_attrs),
    };
    let dir = paths::generated(&label);
    std::fs::create_dir_all(&dir)?;
    let circom_path = dir.join(format!("{label}.circom"));
    // Rewrite only on change, so the cached R1CS stays newer than its source.
    if std::fs::read_to_string(&circom_path).ok().as_deref() != Some(source.as_str()) {
        std::fs::write(&circom_path, &source)?;
    }

    let spec = Groth16Spec::new(circom_path);
    let artifacts = zk.prepare_groth16(&spec)?;
    let vkey = VerifyingKey::read(&artifacts.vkey)?;

    let mut witness_ms = Vec::with_capacity(args.n);
    let mut prove_ms = Vec::with_capacity(args.n);
    let mut verify_ms = Vec::with_capacity(args.n);

    const WARMUP: usize = 1;
    for i in 0..(args.n + WARMUP) {
        let case_dir = artifacts_dir.join(&label).join(format!("iter_{i:04}"));
        std::fs::create_dir_all(&case_dir)?;
        let input_path = case_dir.join("input.json");
        let witness_path = case_dir.join("witness.wtns");
        let proof_path = case_dir.join("proof.json");
        let public_path = case_dir.join("public.json");

        // Input preparation sits outside the prover timer for this sweep.
        let input = match point.mode {
            Mode::Merkle => merkle_input(poseidon, point.total_attrs, point.used_attrs, rng)?,
            Mode::Flat => flat_input(poseidon, point.total_attrs, point.used_attrs, rng),
        };
        std::fs::write(&input_path, serde_json::to_vec_pretty(&input)?)?;

        let started = Instant::now();
        let witness = zk.run_witness(&artifacts.witness_bin, &input_path, &witness_path)?;
        let w_ms = elapsed_ms(started);
        if !witness.ok {
            bail!("{label}: witness failed: {}", witness.message());
        }

        let started = Instant::now();
        let proved = zk.run_prover(&artifacts.zkey, &witness_path, &proof_path, &public_path)?;
        let p_ms = elapsed_ms(started);
        if !proved.ok {
            bail!("{label}: prove failed: {}", proved.message());
        }

        // Verifier time includes parsing: the service receives proof and
        // signals over the wire.
        let started = Instant::now();
        let bundle = ProofBundle::read(&proof_path, &public_path)?;
        let ok = bundle.verify(&vkey)?;
        let v_ms = elapsed_ms(started);
        if !ok {
            bail!("{label}: verify failed");
        }

        if i >= WARMUP {
            witness_ms.push(w_ms);
            prove_ms.push(p_ms);
            verify_ms.push(v_ms);
        }
    }

    if args.verbose && !args.compact {
        stats::print_stats(&format!("{label} witness"), &witness_ms, P95::FloorN);
        stats::print_stats(&format!("{label} prove"), &prove_ms, P95::FloorN);
        stats::print_stats(&format!("{label} verify"), &verify_ms, P95::FloorN);
    }

    let avg_witness = stats::mean(&witness_ms);
    let avg_prove = stats::mean(&prove_ms);
    Ok(Cell {
        avg_witness_ms: avg_witness,
        avg_prove_ms: avg_prove,
        avg_prover_ms: avg_witness.zip(avg_prove).map(|(w, p)| w + p),
        avg_verify_ms: stats::mean(&verify_ms),
        successful_iters: witness_ms.len(),
    })
}

fn print_recap(title: &str, grid: &Grid, totals: &[usize], used: &[usize]) {
    println!("\n{}", "━".repeat(51));
    println!("  {title}");
    println!("  cell = avgProverMs/avgVerifyMs (prover = witness+prove)");
    println!("{}", "━".repeat(51));

    const COL: usize = 12;
    let header = std::iter::once(format!("{:<COL$}", "total\\used"))
        .chain(used.iter().map(|u| format!("{u:>COL$}")))
        .collect::<String>();
    println!("{header}");
    println!("{}", "-".repeat(header.len()));

    for total in totals {
        let mut row = format!("{total:<COL$}");
        for u in used {
            let text = grid
                .get(total)
                .and_then(|r| r.get(u))
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

/// Removes the circuits (and their compiled outputs) this sweep generates.
fn remove_generated_circuits() {
    let Ok(entries) = std::fs::read_dir(paths::work().join("generated")) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("merkle_t") || name.starts_with("flat_t") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    // A Merkle inclusion proof needs a power-of-two leaf count and depth >= 1.
    if let Some(n) = args.totals.iter().find(|n| **n < 2 || !n.is_power_of_two()) {
        bail!("TOTAL_ATTRS entries must be powers of two >= 2, got {n}");
    }
    if args.used.contains(&0) {
        bail!("USED_ATTRS entries must be >= 1");
    }
    let artifacts_dir = paths::artifacts(BENCH);
    if args.clean {
        let _ = std::fs::remove_dir_all(&artifacts_dir);
        remove_generated_circuits();
    }
    std::fs::create_dir_all(&artifacts_dir)?;

    let totals = sorted_unique(&args.totals);
    let used = sorted_unique(&args.used);

    println!("Iterations per point: {}", args.n);
    println!("Totals: {}", join(&totals));
    println!("Used:   {}", join(&used));
    println!(
        "Cleanup after run: {}\n",
        if args.keep_artifacts {
            "disabled (--keep-artifacts)"
        } else {
            "enabled (default)"
        }
    );

    let zk = Toolchain::from_env(args.verbose);
    let poseidon = Poseidon::new();
    let mut rng = StdRng::from_entropy();

    let mut merkle: Grid = Grid::new();
    let mut flat: Grid = Grid::new();

    for &total_attrs in &totals {
        for &used_attrs in &used {
            if used_attrs > total_attrs {
                continue;
            }
            for mode in [Mode::Merkle, Mode::Flat] {
                println!(
                    "total={total_attrs} used={used_attrs} mode={}",
                    mode.prefix()
                );
                let point = Point {
                    mode,
                    total_attrs,
                    used_attrs,
                };
                let cell = bench_point(&point, &args, &zk, &poseidon, &artifacts_dir, &mut rng)?;
                let grid = if mode == Mode::Merkle {
                    &mut merkle
                } else {
                    &mut flat
                };
                grid.entry(total_attrs)
                    .or_default()
                    .insert(used_attrs, cell);
            }
        }
    }

    print_recap("Recap — Flat hash", &flat, &totals, &used);
    print_recap("Recap — Merkle", &merkle, &totals, &used);

    let report = SweepSummary {
        meta: Meta {
            kind: "zk-friendly",
            n: args.n,
            totals: totals.clone(),
            used: used.clone(),
            timestamp_iso: time::iso8601_now(),
        },
        merkle,
        flat,
    };
    let written = report::write(&args.out.dir(paths::STACK, BENCH), &report)?;
    println!("\nSummary: {}", written.display());
    zk_common::clean_artifacts(&artifacts_dir, args.keep_artifacts);

    Ok(())
}

fn sorted_unique(values: &[usize]) -> Vec<usize> {
    let mut out = values.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn join(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
