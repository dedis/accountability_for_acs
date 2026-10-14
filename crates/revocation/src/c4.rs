//! The C4 tag binding: `C4 = Sign_{IDu}(H(t, D2))`, with `H` Poseidon, or
//! SHAKE256 with the `pq` feature ([`crate::hash`]), and the signature scheme
//! given by a [`Scheme`].
//!
//! Without `pq`, [`EdDsa`] matches the zk-friendly `prove_verify.circom` wire
//! format.

use anyhow::Result;
use rand::Rng;

use babyjub::curve::{fr_to_fq, Fq, Fr, Point, PointAffine};
use babyjub::eddsa::{self, SecretKey, Signature};
use babyjub::poseidon::Poseidon;

use crate::hash;

/// A signature scheme for C4. The identity `IDu` is the Baby Jubjub point that
/// C3 encrypts; `verify` finds the verification key from it.
///
/// Batch building calls `keygen` and `sign` from several threads. [`Poseidon`]
/// is not `Sync`, so each thread passes its own.
pub trait Scheme: Sync {
    type SigningKey: Send + Sync;
    type Signature: Send;

    /// Generates a user signing key and the identity bound to it.
    fn keygen<R: Rng + ?Sized>(&self, rng: &mut R) -> Result<(Point, Self::SigningKey)>;

    fn sign<R: Rng + ?Sized>(
        &self,
        poseidon: &Poseidon,
        key: &Self::SigningKey,
        msg: Fq,
        rng: &mut R,
    ) -> Result<Self::Signature>;

    fn verify(
        &self,
        poseidon: &Poseidon,
        id_u: PointAffine,
        msg: Fq,
        sig: &Self::Signature,
    ) -> bool;
}

/// EdDSA-Poseidon over Baby Jubjub: the identity is the public key.
#[derive(Default)]
pub struct EdDsa;

/// The C4 scheme of the benchmarks: EdDSA-Poseidon without the `pq` feature,
/// the post-quantum signature chosen at compile time with it
/// ([`crate::pq_sig::Selected`]).
#[cfg(not(feature = "pq"))]
pub type Selected = EdDsa;
/// The C4 scheme of the benchmarks: EdDSA-Poseidon without the `pq` feature,
/// the post-quantum signature chosen at compile time with it
/// ([`crate::pq_sig::Selected`]).
#[cfg(feature = "pq")]
pub type Selected = crate::pq_sig::PqC4<crate::pq_sig::Selected>;

/// Name of [`Selected`].
#[cfg(not(feature = "pq"))]
pub const SELECTED_NAME: &str = "EdDSA-Poseidon";
/// Name of [`Selected`].
#[cfg(feature = "pq")]
pub const SELECTED_NAME: &str = <crate::pq_sig::Selected as crate::pq_sig::PqSig>::NAME;

impl Scheme for EdDsa {
    type SigningKey = SecretKey;
    type Signature = Signature;

    fn keygen<R: Rng + ?Sized>(&self, rng: &mut R) -> Result<(Point, SecretKey)> {
        let sk = SecretKey::rand(rng);
        Ok((sk.public_key(), sk))
    }

    fn sign<R: Rng + ?Sized>(
        &self,
        poseidon: &Poseidon,
        key: &SecretKey,
        msg: Fq,
        rng: &mut R,
    ) -> Result<Signature> {
        Ok(key.sign_poseidon(poseidon, msg, rng))
    }

    fn verify(&self, poseidon: &Poseidon, id_u: PointAffine, msg: Fq, sig: &Signature) -> bool {
        eddsa::verify_poseidon(poseidon, id_u, msg, sig)
    }
}

/// The message signed by C4: `H(t, D2.x, D2.y)`.
#[inline]
pub fn tag_message(poseidon: &Poseidon, t: Fr, d2: PointAffine) -> Fq {
    hash::to_fq(poseidon, &[fr_to_fq(t), d2.x, d2.y])
}

/// Signs the C4 tag under the user signing key.
pub fn sign<S: Scheme, R: Rng + ?Sized>(
    poseidon: &Poseidon,
    scheme: &S,
    user_sk: &S::SigningKey,
    t: Fr,
    d2: PointAffine,
    rng: &mut R,
) -> Result<S::Signature> {
    scheme.sign(poseidon, user_sk, tag_message(poseidon, t, d2), rng)
}

/// Verifies `C4 = Sign_{IDu}(H(t, D2))`.
pub fn verify<S: Scheme>(
    poseidon: &Poseidon,
    scheme: &S,
    id_u: PointAffine,
    t: Fr,
    d2: PointAffine,
    sig: &S::Signature,
) -> bool {
    scheme.verify(poseidon, id_u, tag_message(poseidon, t, d2), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use babyjub::curve::{base8, rand_scalar};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn changed_tag_is_rejected<S: Scheme>(scheme: &S) {
        let mut rng = StdRng::seed_from_u64(42);
        let poseidon = Poseidon::new();
        let (id_u, sk) = scheme.keygen(&mut rng).unwrap();
        let id_u = id_u.into_affine();
        let t = rand_scalar(&mut rng);
        let d2 = (base8() * rand_scalar(&mut rng)).into_affine();
        let sig = sign(&poseidon, scheme, &sk, t, d2, &mut rng).unwrap();

        assert!(verify(&poseidon, scheme, id_u, t, d2, &sig));
        assert!(!verify(&poseidon, scheme, id_u, t + Fr::from(1u64), d2, &sig));
    }

    #[test]
    fn eddsa_rejects_a_changed_tag() {
        changed_tag_is_rejected(&EdDsa);
    }

    #[cfg(feature = "pq")]
    #[test]
    fn post_quantum_rejects_a_changed_tag() {
        changed_tag_is_rejected(&Selected::default());
    }
}
