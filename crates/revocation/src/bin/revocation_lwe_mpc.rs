//! Post-quantum CFT decryption in the MPC (`pq` feature): the police, the
//! judge and the NGO compute their Module-LWE decryption shares of every CFT,
//! give them to MP-SPDZ as private inputs (`mpc/lwe_decrypt.mpc`), and the MPC
//! reveals only `ID || r2`. One MPC run opens one CFT. Every party prints the
//! revealed message, which must agree, hash to the CFT's binding `h` and name
//! a registered ID before the next CFT opens; a failed check halts all
//! openings under the key (`lwe_cft::OpeningLog`). The benchmark also
//! compares it with the native combination of the shares, which only a
//! process holding all three can compute. The shares reach the parties
//! through pipes, never the disk. Times and counters in the CSV are the sums
//! over the runs.
//!
//! Needs `MP_SPDZ_PATH` (an MP-SPDZ install with `shamir-party.x` and the
//! party certificates of `Scripts/setup-ssl.sh 3`). Sizes: `CFT_BENCH_NUMS`
//! (or `CFT_BENCH_NUM`, default 10); runs per size: `CFT_BENCH_ITERS`
//! (default 1); output: `RESULTS_CSV` (default
//! `.work/revocation/out/mpc/lwe_decrypt.csv`), one row per run.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{ensure, Context as _, Result};
use rand::rngs::StdRng;
use rand::SeedableRng;

use bench_core::time;
use pqc::lwe::{self, DecryptionShare, MSG_BYTES, N, PARTIES, SLOTS};
use revocation::csv;
use revocation::env;
use revocation::lwe_cft::{self, Authorities, Batch, Selected, JUDGE, NGO, POLICE};
use revocation::mpc_runner::{self, SpdzStats};
use revocation::paths;

const MPC_PROGRAM: &str = "lwe_decrypt";
/// The message, revealed in 32-bit words.
const WORDS: usize = MSG_BYTES / 4;

const CSV_HEADERS: [&str; 18] = [
    "ts",
    "iter",
    "n_cfts",
    "c4_signature",
    "police_shares_ms",
    "judge_shares_ms",
    "ngo_shares_ms",
    "mpc_wall_ms",
    "mpc_total_ms",
    "mpc_online_ms",
    "mpc_offline_ms",
    "mpc_online_bytes",
    "mpc_online_rounds",
    "mpc_data_sent_bytes",
    "mpc_global_data_sent_bytes",
    "integrity_ms",
    "n_ids_registered",
    "n_unique_ids_revealed",
];

/// The MP-SPDZ input of one authority for one CFT: its share coefficients,
/// slot by slot. Written in place, in a buffer of the largest size (seven
/// digits and a space per coefficient), so no copy of the share is left
/// behind; [`mpc_runner::run`] clears it.
fn party_input(share: &DecryptionShare) -> String {
    let mut body = String::with_capacity(SLOTS * N * 8);
    for x in share.coefficients().iter().flatten() {
        write!(body, "{x} ").expect("writing to a String");
    }
    body
}

/// The message of the revealed words: word `k` holds bytes `4k..4k + 4`,
/// little-endian.
fn message_of(words: &[u64]) -> Result<[u8; MSG_BYTES]> {
    let mut m = [0u8; MSG_BYTES];
    for (chunk, &w) in m.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        let w = u32::try_from(w).context("revealed word above 32 bits")?;
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    Ok(m)
}

struct Scenario {
    iter: usize,
    num_cfts: usize,
    spdz_path: PathBuf,
    mpc_src: PathBuf,
    csv_path: PathBuf,
}

// Party p of the MPC is authority p.
const _: () = assert!(POLICE == 0 && JUDGE == 1 && NGO == 2);

/// Opens one CFT in the MPC: every party must print the same message.
fn open_one(
    s: &Scenario,
    full_name: &str,
    shares: &[DecryptionShare; PARTIES],
    stats: &mut SpdzStats,
    wall_ms: &mut f64,
) -> Result<[u8; MSG_BYTES]> {
    // The decryption shares give the key shares (pqc::lwe): they reach the
    // parties through pipes, never the disk, and are cleared after the run.
    let inputs = shares.iter().map(party_input).collect();
    let start = Instant::now();
    let output = mpc_runner::run(&s.spdz_path, full_name, inputs)?;
    *wall_ms += start.elapsed().as_secs_f64() * 1e3;
    stats.add(&mpc_runner::parse_spdz_stats(&format!(
        "{}\n{}",
        output.stdout[0], output.stderr[0]
    )));
    let rows = mpc_runner::parse_rows(&output.stdout[0], "cft", 1, WORDS)?;
    for (party, out) in output.stdout.iter().enumerate().skip(1) {
        ensure!(
            mpc_runner::parse_rows(out, "cft", 1, WORDS)? == rows,
            "party {party} printed another message than party 0"
        );
    }
    message_of(&rows[0])
}

fn run_once(s: &Scenario, rng: &mut StdRng) -> Result<()> {
    let mut authorities = Authorities::generate(rng)?;
    let batch: Batch<Selected> = lwe_cft::build_batch(&authorities.pk, s.num_cfts, 0.1, rng)?;

    let timed = |who: usize| {
        let t0 = Instant::now();
        let shares: Vec<DecryptionShare> = batch
            .cfts
            .iter()
            .map(|c| authorities.decryption_share(who, &c.ct))
            .collect();
        (shares, t0.elapsed().as_secs_f64() * 1e3)
    };
    let (police, police_ms) = timed(POLICE);
    let (judge, judge_ms) = timed(JUDGE);
    let (ngo, ngo_ms) = timed(NGO);

    // One CFT per MPC run, checked against its binding before the next
    // opens; any failed check halts all openings under this key
    // (lwe_cft::OpeningLog).
    let full_name = mpc_runner::compile(&s.spdz_path, &s.mpc_src, MPC_PROGRAM, &["1".to_string()])?;
    let log = &mut authorities.log;
    let mut opened = 0usize;
    let mut stats = SpdzStats::default();
    let (mut mpc_wall_ms, mut integrity_ms) = (0.0, 0.0);
    let mut revealed = HashSet::new();
    for (i, ((cft, p), (j, n))) in batch
        .cfts
        .iter()
        .zip(police)
        .zip(judge.into_iter().zip(ngo))
        .enumerate()
    {
        if !log.admit(cft)? {
            println!("CFT {i}: its ciphertext was opened before; skipped");
            continue;
        }
        opened += 1;
        let shares = [p, j, n];
        let opened = open_one(s, &full_name, &shares, &mut stats, &mut mpc_wall_ms).and_then(|m| {
            let t0 = Instant::now();
            ensure!(
                m == lwe::combine(&shares),
                "the MPC output differs from the native decryption"
            );
            log.check(cft, &m)?;
            ensure!(
                lwe_cft::identify::<Selected>(&batch.registry, &m).is_some(),
                "the opened ID is not registered"
            );
            integrity_ms += t0.elapsed().as_secs_f64() * 1e3;
            Ok(m)
        });
        match opened {
            Ok(m) => revealed.insert(m[..lwe_cft::ID_BYTES].to_vec()),
            Err(e) => {
                log.halt();
                return Err(e.context(format!("CFT {i}; openings halted")));
            }
        };
    }
    println!(
        "n={}: MPC {mpc_wall_ms:.0} ms in {opened} runs; IDs registered, {} unique IDs",
        s.num_cfts,
        revealed.len()
    );

    let opt_f64 = |v: Option<f64>| v.map_or_else(String::new, |x| x.to_string());
    let opt_u64 = |v: Option<u64>| v.map_or_else(String::new, |x| x.to_string());
    csv::append(
        &s.csv_path,
        &CSV_HEADERS,
        &[
            time::iso8601_now(),
            s.iter.to_string(),
            s.num_cfts.to_string(),
            lwe_cft::C4_NAME.to_string(),
            police_ms.to_string(),
            judge_ms.to_string(),
            ngo_ms.to_string(),
            mpc_wall_ms.to_string(),
            opt_f64(stats.total_ms),
            opt_f64(stats.online_ms),
            opt_f64(stats.offline_ms),
            opt_u64(stats.online_bytes),
            opt_u64(stats.online_rounds),
            opt_u64(stats.data_sent_bytes),
            opt_u64(stats.global_data_sent_bytes),
            integrity_ms.to_string(),
            opened.to_string(),
            revealed.len().to_string(),
        ],
    )?;
    Ok(())
}

/// `CFT_BENCH_NUMS` (comma- or space-separated) wins over `CFT_BENCH_NUM`.
fn parse_sizes() -> Result<Vec<usize>> {
    let raw = env::var("CFT_BENCH_NUMS")
        .or_else(|| env::var("CFT_BENCH_NUM"))
        .unwrap_or_else(|| "10".to_string());
    let sizes = raw
        .split([',', ' ', '\t', '\n'])
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.parse::<usize>()
                .ok()
                .filter(|n| *n >= 2)
                .with_context(|| format!("CFT size {v:?} is not an integer >= 2"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!sizes.is_empty(), "CFT_BENCH_NUMS / CFT_BENCH_NUM is empty");
    Ok(sizes)
}

fn main() -> Result<()> {
    let sizes = parse_sizes()?;
    let iterations = env::usize_or("CFT_BENCH_ITERS", 1)?;
    let spdz_path = PathBuf::from(
        env::var("MP_SPDZ_PATH").context("MP_SPDZ_PATH must point at an MP-SPDZ install")?,
    );
    let csv_path = env::var("RESULTS_CSV").map_or_else(
        || bench_core::paths::work(paths::STACK).join("out/mpc/lwe_decrypt.csv"),
        PathBuf::from,
    );
    println!("C4 signature: {}", lwe_cft::C4_NAME);

    let mut rng = StdRng::from_entropy();
    for iter in 1..=iterations {
        for &num_cfts in &sizes {
            run_once(
                &Scenario {
                    iter,
                    num_cfts,
                    spdz_path: spdz_path.clone(),
                    mpc_src: paths::mpc().join(format!("{MPC_PROGRAM}.mpc")),
                    csv_path: csv_path.clone(),
                },
                &mut rng,
            )?;
        }
    }
    println!("rows appended to {}", csv_path.display());
    Ok(())
}
