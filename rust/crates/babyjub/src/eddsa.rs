//! EdDSA over Baby Jubjub with Poseidon, in the circomlib convention.
//!
//! `circomlib`'s `EdDSAPoseidonVerifier` multiplies through by the cofactor and
//! checks `S·Base8 == R8 + (8·hm)·A`, so the signer sets `S = r + 8·hm·sk` for
//! `A = sk·Base8` and `R8 = r·Base8`.
//!
//! Keys are sampled directly as subgroup scalars. `circomlibjs` instead derives
//! the scalar from a BLAKE-512 hash of a 32-byte private key; both give
//! signatures that satisfy the same verification relation.

use ark_ec::CurveGroup;
use rand::Rng;

use crate::curve::{base8, fq_to_fr, rand_scalar, Fq, Fr, Point, PointAffine};
use crate::poseidon::Poseidon;

/// A Baby Jubjub EdDSA signing key.
#[derive(Clone, Copy, Debug)]
pub struct SecretKey(Fr);

/// `(R8, S)` as `circomlibjs` reports it.
#[derive(Clone, Copy, Debug)]
pub struct Signature {
    pub r8: PointAffine,
    pub s: Fr,
}

impl SecretKey {
    pub fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Self(rand_scalar(rng))
    }

    /// Wraps an already-sampled scalar, for callers that need the key material
    /// itself (the CFT batch builder reuses one identity across slots).
    pub const fn from_scalar(sk: Fr) -> Self {
        Self(sk)
    }

    pub const fn scalar(&self) -> Fr {
        self.0
    }

    pub fn public_key(&self) -> Point {
        base8() * self.0
    }

    /// Signs a field element under the circomlib cofactor convention.
    pub fn sign_poseidon<R: Rng + ?Sized>(
        &self,
        poseidon: &Poseidon,
        msg: Fq,
        rng: &mut R,
    ) -> Signature {
        let r = rand_scalar(rng);
        let r8 = (base8() * r).into_affine();
        let a = self.public_key().into_affine();
        let hm = challenge(poseidon, r8, a, msg);
        Signature {
            r8,
            s: r + hm * Fr::from(8u64) * self.0,
        }
    }
}

/// `hm = poseidon(R8x, R8y, Ax, Ay, msg)`, reduced into the scalar field.
fn challenge(poseidon: &Poseidon, r8: PointAffine, a: PointAffine, msg: Fq) -> Fr {
    fq_to_fr(poseidon.hash(&[r8.x, r8.y, a.x, a.y, msg]))
}

/// Checks `S·Base8 == R8 + (8·hm)·A`.
///
/// The JS verifier also rejected `S >= BABYJUB_ORDER`; here that is structural,
/// because [`Fr`] cannot hold an out-of-range scalar.
pub fn verify_poseidon(
    poseidon: &Poseidon,
    public_key: PointAffine,
    msg: Fq,
    sig: &Signature,
) -> bool {
    let hm = challenge(poseidon, sig.r8, public_key, msg);
    let lhs = base8() * sig.s;
    let rhs = Point::from(sig.r8) + Point::from(public_key) * (hm * Fr::from(8u64));
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        let poseidon = Poseidon::new();
        let sk = SecretKey::rand(&mut rng);
        let pk = sk.public_key().into_affine();
        let msg = Fq::from(1234567890u64);

        let sig = sk.sign_poseidon(&poseidon, msg, &mut rng);
        assert!(verify_poseidon(&poseidon, pk, msg, &sig));
        assert!(!verify_poseidon(&poseidon, pk, msg + Fq::from(1u64), &sig));

        let other = SecretKey::rand(&mut rng).public_key().into_affine();
        assert!(!verify_poseidon(&poseidon, other, msg, &sig));
    }
}
