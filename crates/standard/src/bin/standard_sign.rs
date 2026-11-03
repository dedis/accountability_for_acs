//! Native signing time of the six post-quantum signatures (`pqc::sig`),
//! independent of the signature features. Prints one JSON object to stdout:
//! scheme name to the timed signatures (ms). Built with the `pq` feature.

use anyhow::Result;
use clap::Parser;
use pqc::sig::{MlDsa65, MlDsa87, PqSig, SlhDsa192f, SlhDsa192s, SlhDsa256f, SlhDsa256s};
use serde_json::{Map, Value};
use standard::sign::sign_ms;

#[derive(Parser)]
#[command(about = "Native signing time of ML-DSA-65/87 and SLH-DSA-SHAKE-192s/192f/256s/256f")]
struct Args {
    /// Timed signatures per scheme.
    #[arg(long, default_value_t = 10)]
    repetitions: usize,
}

fn entry<P: PqSig>(out: &mut Map<String, Value>, reps: usize) -> Result<()> {
    out.insert(P::NAME.to_string(), sign_ms::<P>(reps)?.into());
    Ok(())
}

fn main() -> Result<()> {
    let reps = Args::parse().repetitions;
    let mut out = Map::new();
    entry::<MlDsa65>(&mut out, reps)?;
    entry::<MlDsa87>(&mut out, reps)?;
    entry::<SlhDsa192s>(&mut out, reps)?;
    entry::<SlhDsa192f>(&mut out, reps)?;
    entry::<SlhDsa256s>(&mut out, reps)?;
    entry::<SlhDsa256f>(&mut out, reps)?;
    println!("{}", Value::Object(out));
    Ok(())
}
