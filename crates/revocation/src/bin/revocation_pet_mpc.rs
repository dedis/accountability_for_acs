//! CFTCondOpen-style benchmark: a plaintext-equivalence test over every CFT
//! pair, a MP-SPDZ predicate matrix, then a conditional reveal.
//!
//! - Blinded pairwise differences of `C1` and `C3`
//! - Sequential partial decryption by police, judge and NGO
//! - MP-SPDZ decides, per row, whether the CFT recurs at least `tau` times
//! - Integrity check `poseidon(ID, t, sk·C2) == C4`, then reveal

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context as _, Result};
use ark_ec::CurveGroup;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

use babyjub::curve::{base8, fr_to_fq, rand_scalar, Fq, Fr, Point, PointAffine};
use babyjub::poseidon::Poseidon;
use bench_core::time;
use revocation::csv;
use revocation::env;
use revocation::mpc_runner;
use revocation::paths;
use revocation::stats::n_pairs;

const PARTIES: usize = 3;
const MPC_PROGRAM: &str = "predicate_matrix_partials";

const CSV_HEADERS: [&str; 22] = [
    "ts",
    "iter",
    "n_cfts",
    "tau",
    "n_recurring_expected",
    "n_pairs",
    "pet_phase_ms",
    "mpc_wall_ms",
    "mpc_total_ms",
    "mpc_online_ms",
    "mpc_offline_ms",
    "mpc_online_bytes",
    "mpc_online_rounds",
    "mpc_offline_bytes",
    "mpc_offline_rounds",
    "mpc_data_sent_bytes",
    "mpc_global_data_sent_bytes",
    "integrity_phase_ms",
    "n_flagged_by_mpc",
    "n_integrity_checked",
    "n_integrity_failed",
    "n_unique_ids_revealed",
];

/// An additive 3-of-3 sharing of the aggregate decryption key.
struct Keys {
    police: Fr,
    judge: Fr,
    ngo: Fr,
    pk_ag: Point,
}

impl Keys {
    fn generate<R: Rng + ?Sized>(rng: &mut R) -> Self {
        let main_sk = rand_scalar(rng);
        let police = rand_scalar(rng);
        let judge = rand_scalar(rng);
        Self {
            police,
            judge,
            ngo: main_sk - police - judge,
            pk_ag: base8() * main_sk,
        }
    }
}

/// One CFT; `C4` is a Poseidon binding here rather than a signature.
struct Entry {
    c1: Point,
    c2: Point,
    c3: Point,
    c4: Fq,
    t: Fr,
}

struct Batch {
    entries: Vec<Entry>,
    n_recurring: usize,
}

/// `C4 = poseidon(ID.x, ID.y, t, D2.x, D2.y)`.
fn c4_hash(poseidon: &Poseidon, id: PointAffine, t: Fr, d2: PointAffine) -> Fq {
    poseidon.hash(&[id.x, id.y, fr_to_fq(t), d2.x, d2.y])
}

/// 20% of slots share one identity, 5% another, the rest are unique.
fn build_batch<R: Rng + ?Sized>(poseidon: &Poseidon, pk_ag: Point, n: usize, rng: &mut R) -> Batch {
    let n_a = (n as f64 * 0.2).round() as usize;
    let n_b = (n as f64 * 0.05).round() as usize;
    let n_unique = n - n_a - n_b;

    let id_a = base8() * rand_scalar(rng);
    let id_b = base8() * rand_scalar(rng);

    let mut slots: Vec<Point> = Vec::with_capacity(n);
    slots.extend(std::iter::repeat_n(id_a, n_a));
    slots.extend(std::iter::repeat_n(id_b, n_b));
    slots.extend((0..n_unique).map(|_| base8() * rand_scalar(rng)));
    slots.shuffle(rng);

    let entries = slots
        .into_iter()
        .map(|id_u| {
            let r1 = rand_scalar(rng);
            let r2 = rand_scalar(rng);
            let t = rand_scalar(rng);
            let d2 = (pk_ag * r2).into_affine();
            Entry {
                c1: base8() * r1,
                c2: base8() * r2,
                c3: id_u + pk_ag * r1,
                c4: c4_hash(poseidon, id_u.into_affine(), t, d2),
                t,
            }
        })
        .collect();

    Batch {
        entries,
        n_recurring: n_a + n_b,
    }
}

/// The upper triangle (including the diagonal) of a symmetric `n × n` matrix,
/// stored flat.
///
/// The pairwise difference matrices are symmetric, so the JS mirrored every
/// entry into both halves; keeping one half halves the memory without changing
/// how many group operations are performed.
struct Triangle {
    n: usize,
    values: Vec<Point>,
}

impl Triangle {
    fn with_capacity(n: usize) -> Self {
        Self {
            n,
            values: Vec::with_capacity(Self::len(n)),
        }
    }

    const fn len(n: usize) -> usize {
        n * (n + 1) / 2
    }

    /// Flat offset of `(i, j)` for `i <= j`.
    #[inline]
    fn index(&self, i: usize, j: usize) -> usize {
        debug_assert!(i <= j && j < self.n);
        i * self.n - i * i.saturating_sub(1) / 2 + (j - i)
    }
}

/// Builds the blinded pairwise differences of `C1` and `C3`.
fn blinded_differences<R: Rng + ?Sized>(entries: &[Entry], rng: &mut R) -> (Triangle, Triangle) {
    let n = entries.len();
    let mut c1 = Triangle::with_capacity(n);
    let mut c3 = Triangle::with_capacity(n);

    for i in 0..n {
        for j in i..n {
            let b = rand_scalar(rng);
            c1.values.push((entries[i].c1 - entries[j].c1) * b);
            c3.values.push((entries[i].c3 - entries[j].c3) * b);
        }
    }

    (c1, c3)
}

/// One authority's partial decryption of every blinded difference.
fn partial_decrypt(blinded: &Triangle, sk: Fr) -> Triangle {
    Triangle {
        n: blinded.n,
        values: blinded.values.iter().map(|p| *p * sk).collect(),
    }
}

/// `Player-Data/Input-P0-0` holds `M'.x` and `M'.y` for each `i < j` pair.
///
/// The whole triangle is normalised to affine in one batch (one field
/// inversion) instead of one inversion per point.
fn write_mpc_inputs(spdz_path: &std::path::Path, m_prime: &Triangle) -> Result<()> {
    let n = m_prime.n;
    let affine = Point::normalize_batch(&m_prime.values);
    let mut lines = Vec::with_capacity(2 * n_pairs(n as u64) as usize);
    for i in 0..n {
        for j in (i + 1)..n {
            let p = affine[m_prime.index(i, j)];
            lines.push(p.x.to_string());
            lines.push(p.y.to_string());
        }
    }

    mpc_runner::write_player_inputs(spdz_path, &lines, PARTIES)?;
    println!("wrote inputs for {n} CFTs / {} pairs:", n_pairs(n as u64));
    println!(
        "  Input-P0-0: {} lines (2 per pair: M'.x, M'.y)",
        lines.len()
    );
    Ok(())
}

/// Threshold-opens one CFT and re-checks its Poseidon binding.
fn check_integrity(poseidon: &Poseidon, entry: &Entry, keys: &Keys) -> (bool, PointAffine) {
    let d1 = entry.c1 * keys.police + entry.c1 * keys.judge + entry.c1 * keys.ngo;
    let d2 = entry.c2 * keys.police + entry.c2 * keys.judge + entry.c2 * keys.ngo;
    let id = (entry.c3 - d1).into_affine();
    let expected = c4_hash(poseidon, id, entry.t, d2.into_affine());
    (expected == entry.c4, id)
}

#[derive(Clone, Copy)]
struct Scenario<'a> {
    iter: usize,
    num_cfts: usize,
    tau: usize,
    poseidon: &'a Poseidon,
    spdz_path: &'a std::path::Path,
    mpc_src: &'a std::path::Path,
    csv_path: &'a std::path::Path,
}

fn run_once(scenario: &Scenario<'_>, rng: &mut StdRng) -> Result<()> {
    let Scenario {
        iter,
        num_cfts,
        tau,
        poseidon,
        spdz_path,
        mpc_src,
        csv_path,
    } = *scenario;

    let keys = Keys::generate(rng);
    let batch = build_batch(poseidon, keys.pk_ag, num_cfts, rng);

    // PET phase: blinded differences plus the police partial decryption. The
    // judge and NGO passes run on other machines in a deployment, so they are
    // computed but not charged to this phase — as in the JS.
    let pet_start = Instant::now();
    let (blinded_c1, mut blinded_c3) = blinded_differences(&batch.entries, rng);
    let police = partial_decrypt(&blinded_c1, keys.police);
    let pet_phase_ms = pet_start.elapsed().as_secs_f64() * 1e3;

    let judge = partial_decrypt(&blinded_c1, keys.judge);
    let ngo = partial_decrypt(&blinded_c1, keys.ngo);
    drop(blinded_c1);

    // M' = blinded C3 difference minus the fully decrypted C1 difference,
    // written in place.
    for (index, value) in blinded_c3.values.iter_mut().enumerate() {
        *value -= police.values[index] + judge.values[index] + ngo.values[index];
    }
    drop(police);
    drop(judge);
    drop(ngo);

    write_mpc_inputs(spdz_path, &blinded_c3)?;
    drop(blinded_c3);

    let full_name = mpc_runner::compile(
        spdz_path,
        mpc_src,
        MPC_PROGRAM,
        &[num_cfts.to_string(), tau.to_string()],
    )?;

    let mpc_start = Instant::now();
    let output = mpc_runner::run(spdz_path, &full_name, PARTIES)?;
    let mpc_wall_ms = mpc_start.elapsed().as_secs_f64() * 1e3;

    let predicates = mpc_runner::parse_predicates(&output.stdout[0], num_cfts)?;
    let flagged = predicates.iter().filter(|p| **p).count();
    println!("# CFTs flagged: {flagged}");

    let stats =
        mpc_runner::parse_spdz_stats(&format!("{}\n{}", output.stdout[0], output.stderr[0]));

    let integrity_start = Instant::now();
    let mut checked = 0usize;
    let mut failed = 0usize;
    let mut revealed: HashSet<PointAffine> = HashSet::new();
    for (entry, flag) in batch.entries.iter().zip(&predicates) {
        if !flag {
            continue;
        }
        checked += 1;
        let (ok, id) = check_integrity(poseidon, entry, &keys);
        if ok {
            revealed.insert(id);
        } else {
            failed += 1;
        }
    }
    let integrity_ms = integrity_start.elapsed().as_secs_f64() * 1e3;

    println!("Integrity check: {integrity_ms:.2} ms ({checked} checked, {failed} failed)");
    println!("Revealed unique IDs: {}", revealed.len());

    csv::append(
        csv_path,
        &CSV_HEADERS,
        &[
            time::iso8601_now(),
            iter.to_string(),
            num_cfts.to_string(),
            tau.to_string(),
            batch.n_recurring.to_string(),
            n_pairs(num_cfts as u64).to_string(),
            pet_phase_ms.to_string(),
            mpc_wall_ms.to_string(),
            opt_f64(stats.total_ms),
            opt_f64(stats.online_ms),
            opt_f64(stats.offline_ms),
            opt_u64(stats.online_bytes),
            opt_u64(stats.online_rounds),
            opt_u64(stats.offline_bytes),
            opt_u64(stats.offline_rounds),
            opt_u64(stats.data_sent_bytes),
            opt_u64(stats.global_data_sent_bytes),
            integrity_ms.to_string(),
            flagged.to_string(),
            checked.to_string(),
            failed.to_string(),
            revealed.len().to_string(),
        ],
    )?;
    println!("appended row to {}", csv_path.display());

    Ok(())
}

fn opt_f64(v: Option<f64>) -> String {
    v.map_or_else(String::new, |x| x.to_string())
}

fn opt_u64(v: Option<u64>) -> String {
    v.map_or_else(String::new, |x| x.to_string())
}

/// `CFT_BENCH_NUMS` (comma- or space-separated) wins over `CFT_BENCH_NUM`.
fn parse_sizes() -> Result<Vec<usize>> {
    let raw = env::var("CFT_BENCH_NUMS")
        .or_else(|| env::var("CFT_BENCH_NUM"))
        .unwrap_or_else(|| "10".to_string());
    let sizes: Vec<usize> = raw
        .split([',', ' ', '\t', '\n'])
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .collect();
    anyhow::ensure!(
        !sizes.is_empty(),
        "CFT_BENCH_NUMS / CFT_BENCH_NUM produced an empty list"
    );
    Ok(sizes)
}

fn main() -> Result<()> {
    let sizes = parse_sizes()?;
    let iterations = env::usize_or("CFT_BENCH_ITERS", 1)?;
    let tau = env::usize_or("CFT_MIN_PID_COUNT", 2)?;

    let spdz_path = PathBuf::from(
        env::var("MP_SPDZ_PATH").context("MP_SPDZ_PATH must point at an MP-SPDZ install")?,
    );
    let mpc_src = paths::mpc().join(format!("{MPC_PROGRAM}.mpc"));
    let csv_path = env::var("RESULTS_CSV").map_or_else(
        || bench_core::paths::work(paths::STACK).join("out/mpc/results.csv"),
        PathBuf::from,
    );

    let poseidon = Poseidon::new();
    let mut rng = StdRng::from_entropy();

    let total_runs = iterations * sizes.len();
    println!(
        "Running {iterations} iter(s) × {} size(s) = {total_runs} scenario(s) at tau={tau}",
        sizes.len()
    );
    println!(
        "Sizes (N): [{}]",
        sizes
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Interleaved: every size once per iteration, so a partial sweep still
    // covers the whole range.
    let mut done = 0usize;
    for iter in 1..=iterations {
        for &num_cfts in &sizes {
            done += 1;
            println!("\n──── [{done}/{total_runs}] iter {iter}/{iterations}  N={num_cfts} ────");
            run_once(
                &Scenario {
                    iter,
                    num_cfts,
                    tau,
                    poseidon: &poseidon,
                    spdz_path: &spdz_path,
                    mpc_src: &mpc_src,
                    csv_path: &csv_path,
                },
                &mut rng,
            )?;
        }
    }

    println!(
        "\n──── done. {total_runs} scenario(s) appended to {} ────",
        csv_path.display()
    );
    Ok(())
}
