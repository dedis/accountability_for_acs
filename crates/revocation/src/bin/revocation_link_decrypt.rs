//! Link CFTs to pseudonyms, keep the recurring ones, decrypt only those.

use anyhow::Result;
use bench_core::cli::Out;
use clap::Parser;
use revocation::experiment::{self, Benchmark, Context, Options};
use revocation::paths;

#[derive(Parser)]
#[command(about = "CFT link-then-decrypt experiment")]
struct Args {
    /// CSV folder (default `.work/revocation/out/experiments`).
    #[command(flatten)]
    out: Out,
}

fn main() -> Result<()> {
    let dir = Args::parse().out.out.unwrap_or_else(paths::experiments);
    let benchmark = Benchmark::LinkDecrypt;
    let options = Options::from_env(benchmark, dir)?;
    experiment::run(benchmark, &mut Context::new(), &options)?;
    Ok(())
}
