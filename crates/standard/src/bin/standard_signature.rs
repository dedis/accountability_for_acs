//! Longfellow: verification of the signature scheme chosen at compile time,
//! on a private message under a public key. Built with the `pq` feature.
//!
//! | Features | Scheme | Benchmark |
//! |---|---|---|
//! | (none) | ML-DSA-65 | `ml_dsa_65_zk_test` |
//! | `level-5` | ML-DSA-87 | `ml_dsa_87_zk_test` |
//! | `slh-dsa` | SLH-DSA-SHAKE-192s | `slh_dsa_zk_test` |
//! | `slh-dsa`, `level-5` | SLH-DSA-SHAKE-256s | `slh_dsa_zk_5_test` |
//! | `slh-dsa-f` | SLH-DSA-SHAKE-192f | `slh_dsa_zk_test` |
//! | `slh-dsa-f`, `level-5` | SLH-DSA-SHAKE-256f | `slh_dsa_zk_5_test` |
//!
//! Every proof has the soundness of its NIST category: 192 bits at level 3
//! (GF(2^256) or Fq^12, 48-byte digests), 256 bits at level 5 (GF(2^384) or
//! Fq^12, 64-byte digests).
//!
//! The summary also has the native signing time (`statsMs.sign`) of the same
//! scheme, with the signer of `revocation` (fips204 / fips205).

use std::time::Instant;

use anyhow::Result;
use clap::Parser;
use revocation::pq_sig::{PqSig, Selected};
use standard::cli::Common;
use standard::driver::{self, Bench};

/// Native signing with the system's signer (`revocation::pq_sig::Selected`,
/// the scheme the proof is for): one key, a 32-byte message (the size of a C4
/// message), one untimed warm-up, then `reps` timed signatures (ms).
fn sign_ms(reps: usize) -> Result<Vec<f64>> {
    let (_, sk) = Selected::keygen()?;
    let msg = [0x5a; 32];
    Selected::sign(&sk, &msg)?;
    (0..reps)
        .map(|_| {
            let t0 = Instant::now();
            Selected::sign(&sk, &msg)?;
            Ok(t0.elapsed().as_secs_f64() * 1e3)
        })
        .collect()
}

#[cfg(all(not(feature = "slh-dsa"), not(feature = "level-5")))]
const BENCH: Bench = Bench {
    backend: "Longfellow - ml_dsa_65_zk_test (ML-DSA-65 verify on mu; Fq^12, 192-bit soundness)",
    variant: "ml_dsa65",
    default_filter: "BM_MLDSA65ZK_Combined",
    test_name: "circuits/tests/pq/ml_dsa/ml_dsa_65_zk_test",
    bin_env: &["LONGFELLOW_SIGNATURE_BENCH_BIN"],
    sign: Some(sign_ms),
};

#[cfg(all(not(feature = "slh-dsa"), feature = "level-5"))]
const BENCH: Bench = Bench {
    backend: "Longfellow - ml_dsa_87_zk_test (ML-DSA-87 verify on mu; Fq^12, 256-bit soundness)",
    variant: "ml_dsa87",
    default_filter: "BM_MLDSA87ZK_Combined",
    test_name: "circuits/tests/pq/ml_dsa/ml_dsa_87_zk_test",
    bin_env: &["LONGFELLOW_SIGNATURE_BENCH_BIN"],
    sign: Some(sign_ms),
};

#[cfg(all(
    feature = "slh-dsa",
    not(feature = "slh-dsa-f"),
    not(feature = "level-5")
))]
const BENCH: Bench = Bench {
    backend: "Longfellow - slh_dsa_zk_test \
              (SLH-DSA-SHAKE-192s verify on a private message; GF(2^256), 5,748 copies)",
    variant: "slh_dsa_shake_192s",
    default_filter: "SLHDSA_SHAKE_192s$",
    test_name: "circuits/tests/pq/slh_dsa/slh_dsa_zk_test",
    bin_env: &["LONGFELLOW_SIGNATURE_BENCH_BIN"],
    sign: Some(sign_ms),
};

#[cfg(all(feature = "slh-dsa", not(feature = "slh-dsa-f"), feature = "level-5"))]
const BENCH: Bench = Bench {
    backend: "Longfellow - slh_dsa_zk_5_test \
              (SLH-DSA-SHAKE-256s verify on a private message; GF(2^384), 8,578 copies)",
    variant: "slh_dsa_shake_256s",
    default_filter: "SLHDSA_SHAKE_256s$",
    test_name: "circuits/tests/pq/slh_dsa/slh_dsa_zk_5_test",
    bin_env: &["LONGFELLOW_SIGNATURE_BENCH_BIN"],
    sign: Some(sign_ms),
};

#[cfg(all(feature = "slh-dsa-f", not(feature = "level-5")))]
const BENCH: Bench = Bench {
    backend: "Longfellow - slh_dsa_zk_test \
              (SLH-DSA-SHAKE-192f verify on a private message; GF(2^256), 17,421 copies)",
    variant: "slh_dsa_shake_192f",
    default_filter: "SLHDSA_SHAKE_192f$",
    test_name: "circuits/tests/pq/slh_dsa/slh_dsa_zk_test",
    bin_env: &["LONGFELLOW_SIGNATURE_BENCH_BIN"],
    sign: Some(sign_ms),
};

#[cfg(all(feature = "slh-dsa-f", feature = "level-5"))]
const BENCH: Bench = Bench {
    backend: "Longfellow - slh_dsa_zk_5_test \
              (SLH-DSA-SHAKE-256f verify on a private message; GF(2^384), 17,803 copies)",
    variant: "slh_dsa_shake_256f",
    default_filter: "SLHDSA_SHAKE_256f$",
    test_name: "circuits/tests/pq/slh_dsa/slh_dsa_zk_5_test",
    bin_env: &["LONGFELLOW_SIGNATURE_BENCH_BIN"],
    sign: Some(sign_ms),
};

#[derive(Parser)]
#[command(
    about = "Longfellow prove/verify benchmark for the signature scheme chosen at build time"
)]
struct Args {
    /// Google Benchmark filter regex.
    #[arg(long)]
    filter: Option<String>,
    #[command(flatten)]
    common: Common,
}

fn main() -> Result<()> {
    let args = Args::parse();
    driver::run(&BENCH, args.common, args.filter)
}
