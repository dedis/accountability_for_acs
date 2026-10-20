//! Longfellow: the post-quantum age-check presentation without CFT, with the signature chosen at
//! compile time (`standard::pq_credential`). Built with the `pq` feature.

use anyhow::Result;
use clap::Parser;
use standard::cli::Common;
use standard::driver;
use standard::pq_credential::NO_CFT;

#[derive(Parser)]
#[command(
    about = "Longfellow prove/verify benchmark for the post-quantum age-check presentation without CFT"
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
    driver::run(&NO_CFT, args.common, args.filter)
}
