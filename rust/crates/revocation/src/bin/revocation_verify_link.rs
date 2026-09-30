//! Protocol sanity check: confirms the curve matches circom's `Base8` and that
//! both revocation strategies open a small batch.

use anyhow::{bail, Result};
use ark_ec::CurveGroup;
use babyjub::curve::{base8, BASE8_X, BASE8_Y};
use revocation::cft;
use revocation::experiment::Context;

fn main() -> Result<()> {
    let generator = base8().into_affine();
    let base_ok = generator.x == BASE8_X && generator.y == BASE8_Y;
    println!("Baby Jubjub (arkworks, circomlib parameters) | Base8 match circom: {base_ok}");
    if !base_ok {
        bail!("subgroup generator is not circom's Base8");
    }

    let mut ctx = Context::new();
    for pct in [0.1, 0.5] {
        let batch = cft::build_batch(&ctx.poseidon, ctx.keys.pk_ag, 100, pct, &mut ctx.rng)?;
        cft::bench_direct_decrypt(&ctx.poseidon, &batch, &ctx.keys)?;
        let linked = cft::bench_link_decrypt(&ctx.poseidon, &batch, &ctx.keys, &mut ctx.rng)?;
        if linked.n_after_filter != batch.n_recurring {
            bail!(
                "link-decrypt kept {} entries, expected {}",
                linked.n_after_filter,
                batch.n_recurring
            );
        }
        println!("ok n=100 recurring= {}%", (pct * 100.0).round() as i64);
    }

    println!("verify done");
    Ok(())
}
