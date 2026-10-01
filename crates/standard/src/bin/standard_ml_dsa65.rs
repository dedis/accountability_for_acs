//! Longfellow: ML-DSA-65 signature verification (FIPS 204) on a private
//! message hash under a public key, over Fp24_6. Built with the `pq` feature.

use anyhow::Result;
use clap::Parser;
use standard::cli::Common;
use standard::driver::{self, Bench};

const BENCH: Bench = Bench {
    backend: "Longfellow - ml_dsa_65_zk_test (ML-DSA-65 verify on mu; Fp24_6)",
    variant: "ml_dsa65",
    default_filter: "BM_MLDSA65ZK_Combined",
    test_name: "circuits/tests/pq/ml_dsa/ml_dsa_65_zk_test",
    bin_env: &["LONGFELLOW_ML_DSA65_BENCH_BIN"],
};

#[derive(Parser)]
#[command(about = "Longfellow prove/verify benchmark for ML-DSA-65 signature verification")]
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
