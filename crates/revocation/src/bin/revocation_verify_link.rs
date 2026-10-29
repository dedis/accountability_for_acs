//! Protocol sanity check. Classical build: the curve matches circom's `Base8`
//! and both revocation strategies open a small batch. Post-quantum build:
//! direct decryption opens a small Module-LWE batch, before and after a share
//! refresh.

use anyhow::Result;
use revocation::experiment::{Context, C4_NAME};

#[cfg(not(feature = "pq"))]
fn check(ctx: &mut Context) -> Result<()> {
    use anyhow::bail;
    use ark_ec::CurveGroup;
    use babyjub::curve::{base8, BASE8_X, BASE8_Y};
    use revocation::{c4, cft};

    let generator = base8().into_affine();
    let base_ok = generator.x == BASE8_X && generator.y == BASE8_Y;
    println!("Baby Jubjub (arkworks, circomlib parameters) | Base8 match circom: {base_ok}");
    if !base_ok {
        bail!("subgroup generator is not circom's Base8");
    }
    for pct in [0.1, 0.5] {
        let scheme = c4::Selected::default();
        let batch = cft::build_batch(&scheme, ctx.keys.pk_ag, 100, pct, &mut ctx.rng)?;
        cft::bench_direct_decrypt(&ctx.poseidon, &scheme, &batch, &ctx.keys)?;
        let linked =
            cft::bench_link_decrypt(&ctx.poseidon, &scheme, &batch, &ctx.keys, &mut ctx.rng)?;
        if linked.n_after_filter != batch.n_recurring {
            bail!(
                "link-decrypt kept {} entries, expected {}",
                linked.n_after_filter,
                batch.n_recurring
            );
        }
        println!("ok n=100 recurring= {}%", (pct * 100.0).round() as i64);
    }
    Ok(())
}

#[cfg(feature = "pq")]
fn check(ctx: &mut Context) -> Result<()> {
    use revocation::lwe_cft::{self, Selected};

    // A ciphertext opens once (lwe_cft::OpeningLog): the second batch is
    // made before the refresh and opened after it.
    let batch = lwe_cft::build_batch::<Selected, _>(&ctx.authorities.pk, 20, 0.1, &mut ctx.rng)?;
    let old = lwe_cft::build_batch::<Selected, _>(&ctx.authorities.pk, 20, 0.1, &mut ctx.rng)?;
    lwe_cft::bench_direct_decrypt(&batch, &mut ctx.authorities)?;
    println!("ok n=20 direct-decrypt");
    ctx.authorities.refresh(&mut ctx.rng);
    lwe_cft::bench_direct_decrypt(&old, &mut ctx.authorities)?;
    println!("ok n=20 direct-decrypt after a share refresh, of CFTs made before it");
    Ok(())
}

fn main() -> Result<()> {
    println!("C4 signature: {C4_NAME}");
    check(&mut Context::new()?)?;
    println!("verify done");
    Ok(())
}
