//! Native signing time with the system's signer (`pqc::sig`, fips204 /
//! fips205). Built with the `pq` feature.

use std::time::Instant;

use anyhow::Result;
use pqc::sig::PqSig;

/// One key, a message of the size of a C4 message (`SHAKE256(t || r2)`: 48
/// bytes at category 3, 64 at category 5), one untimed warm-up, then `reps`
/// timed signatures (ms).
pub fn sign_ms<P: PqSig>(reps: usize) -> Result<Vec<f64>> {
    let (_, sk) = P::keygen()?;
    let msg = [0x5a; 64];
    let msg = &msg[..if P::CATEGORY == 5 { 64 } else { 48 }];
    P::sign(&sk, msg)?;
    (0..reps)
        .map(|_| {
            let t0 = Instant::now();
            P::sign(&sk, msg)?;
            Ok(t0.elapsed().as_secs_f64() * 1e3)
        })
        .collect()
}
