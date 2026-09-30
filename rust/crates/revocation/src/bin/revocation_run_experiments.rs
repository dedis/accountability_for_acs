//! Runs direct-decrypt then link-decrypt, sharing one crypto context.

use anyhow::Result;
use bench_core::cli::Out;
use clap::Parser;
use revocation::experiment::{self, Benchmark, Context, Options};
use revocation::paths;

#[derive(Parser)]
#[command(about = "Both CFT revocation experiments")]
struct Args {
    /// CSV folder (default `.work/revocation/out/experiments`).
    #[command(flatten)]
    out: Out,
}

fn main() -> Result<()> {
    let dir = Args::parse().out.out.unwrap_or_else(paths::experiments);
    let mut ctx = Context::new();

    for (index, benchmark) in Benchmark::ALL.into_iter().enumerate() {
        if index > 0 {
            println!("\n{}\n", "─".repeat(60));
        }
        let options = Options::from_env(benchmark, dir.clone())?;
        experiment::run(benchmark, &mut ctx, &options)?;
    }

    println!("\nAll experiments done. CSVs in {}:", dir.display());
    for benchmark in Benchmark::ALL {
        for suffix in ["_runs.csv", "_summary.csv", "_fit.csv"] {
            println!("  {}{suffix}", dir.join(benchmark.as_str()).display());
        }
    }
    Ok(())
}
