//! Longfellow: age-check + CFT presentation (flat hash over 32 attributes,
//! C4 = ECDSA).

use anyhow::Result;
use clap::Parser;
use standard::cli::Common;
use standard::driver::{self, Bench};
use standard::paths::Tree;

const BENCH: Bench = Bench {
    backend: "Longfellow - prove_verify (32 attrs, flat hash, 5 used; C4 = ECDSA)",
    variant: "prove_verify",
    default_filter: "BM_CredentialCommitmentProveVerifyCombined_P256",
    tree: Tree::Main,
    test_name: standard::ec_bench!("prove_verify"),
    bin_env: &["LONGFELLOW_CRED_BENCH_BIN"],
    sign: None,
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
