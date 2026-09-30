//! Longfellow: age-check + CFT presentation (flat SHA-256 over 32 attributes,
//! C4 = ECDSA).

use anyhow::Result;
use clap::Parser;
use standard::cli::Common;
use standard::driver::{self, Bench};

const BENCH: Bench = Bench {
    backend: "Longfellow - prove_verify_test (32 attrs, flat SHA, 5 used; C4 = ECDSA)",
    variant: "prove_verify",
    default_filter: "BM_CredentialCommitmentProveVerifyCombined_P256",
    test_name: "prove_verify_test",
    bin_env: &["LONGFELLOW_CRED_BENCH_BIN"],
};

#[derive(Parser)]
#[command(about = "Longfellow prove/verify benchmark for the age-check + CFT presentation")]
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
