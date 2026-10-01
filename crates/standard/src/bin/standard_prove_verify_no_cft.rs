//! Longfellow: age-check presentation without a CFT — 5 disclosed attributes
//! (indices 4, 5, 6, 14, 15) and no ElGamal `c1..c4` relations.

use anyhow::Result;
use clap::Parser;
use standard::cli::Common;
use standard::driver::{self, Bench};

const BENCH: Bench = Bench {
    backend: "Longfellow - prove_verify_no_cft_test (32 attrs, flat SHA, 5 used; no CFT)",
    variant: "prove_verify_no_cft",
    default_filter: "BM_CredentialCommitmentProveVerifyNoCftCombined_P256",
    test_name: "circuits/tests/ec/prove_verify_no_cft_test",
    bin_env: &["LONGFELLOW_NO_CFT_BENCH_BIN", "LONGFELLOW_CRED_BENCH_BIN"],
};

#[derive(Parser)]
#[command(about = "Longfellow prove/verify benchmark for the no-CFT age-check baseline")]
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
