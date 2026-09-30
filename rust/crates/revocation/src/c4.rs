//! The C4 tag binding: `C4 = EdDSA_{IDu}(poseidon(t, D2))`.
//!
//! Matches the zk-friendly `prove_verify.circom` wire format.

use rand::Rng;

use babyjub::curve::{fr_to_fq, Fq, Fr, PointAffine};
use babyjub::eddsa::{self, SecretKey, Signature};
use babyjub::poseidon::Poseidon;

/// The message signed by C4: `poseidon(t, D2.x, D2.y)`.
#[inline]
pub fn tag_message(poseidon: &Poseidon, t: Fr, d2: PointAffine) -> Fq {
    poseidon.hash(&[fr_to_fq(t), d2.x, d2.y])
}

/// Signs the C4 tag under the user identity key.
pub fn sign<R: Rng + ?Sized>(
    poseidon: &Poseidon,
    user_sk: &SecretKey,
    t: Fr,
    d2: PointAffine,
    rng: &mut R,
) -> Signature {
    user_sk.sign_poseidon(poseidon, tag_message(poseidon, t, d2), rng)
}

/// Verifies `C4 = EdDSA_{IDu}(poseidon(t, D2))`.
pub fn verify(
    poseidon: &Poseidon,
    id_u: PointAffine,
    t: Fr,
    d2: PointAffine,
    sig: &Signature,
) -> bool {
    eddsa::verify_poseidon(poseidon, id_u, tag_message(poseidon, t, d2), sig)
}
