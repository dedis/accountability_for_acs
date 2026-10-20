//! Post-quantum signatures for C4 (`pq` feature): ML-DSA (FIPS 204) and
//! SLH-DSA (FIPS 205), and the scheme chosen at compile time.
//!
//! The `slh-dsa` feature selects SLH-DSA in place of ML-DSA, the `level-5`
//! feature NIST security category 5 in place of 3, and the `slh-dsa-f`
//! feature (which implies `slh-dsa`) the fast SLH-DSA variant in place of the
//! small one:
//!
//! | Features | Scheme |
//! |---|---|
//! | (none) | ML-DSA-65 |
//! | `level-5` | ML-DSA-87 |
//! | `slh-dsa` | SLH-DSA-SHAKE-192s |
//! | `slh-dsa`, `level-5` | SLH-DSA-SHAKE-256s |
//! | `slh-dsa-f` | SLH-DSA-SHAKE-192f |
//! | `slh-dsa-f`, `level-5` | SLH-DSA-SHAKE-256f |
//!
//! The s variants sign in about 1 s and have smaller signatures; the f
//! variants sign in about 0.1 s, but their proofs need about twice as many
//! Keccak-f calls.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Mutex;

use anyhow::{bail, Result};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use rand::Rng;

use babyjub::curve::{base8, rand_scalar, Fq, Point, PointAffine};
use babyjub::poseidon::Poseidon;
use fips204::{ml_dsa_65, ml_dsa_87};
use fips205::{slh_dsa_shake_192f, slh_dsa_shake_192s, slh_dsa_shake_256f, slh_dsa_shake_256s};

use crate::c4::Scheme;

/// Context string of every C4 signature (FIPS 204/205 `ctx`).
pub const CONTEXT: &[u8] = b"PQ-CFT-C4-v1";

/// One post-quantum signature parameter set. Signing is hedged with OS
/// randomness.
pub trait PqSig {
    /// Name, as in the FIPS.
    const NAME: &'static str;
    /// NIST security category.
    const CATEGORY: u8;
    /// Signature size in bytes.
    const SIG_LEN: usize;

    type PublicKey: Send;
    type SigningKey: Send + Sync;
    type Signature: AsRef<[u8]> + Send;

    fn keygen() -> Result<(Self::PublicKey, Self::SigningKey)>;
    fn sign(sk: &Self::SigningKey, msg: &[u8]) -> Result<Self::Signature>;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
}

/// ML-DSA parameter set `K`.
pub struct MlDsa<K>(PhantomData<K>);

/// SLH-DSA parameter set `K`.
pub struct SlhDsa<K>(PhantomData<K>);

macro_rules! pq_sig {
    ($wrapper:ident, $krate:ident, $name:literal, $category:literal, $module:ident, $($hedged:expr)?) => {
        impl PqSig for $wrapper<$module::KG> {
            const NAME: &'static str = $name;
            const CATEGORY: u8 = $category;
            const SIG_LEN: usize = $module::SIG_LEN;

            type PublicKey = $module::PublicKey;
            type SigningKey = $module::PrivateKey;
            type Signature = [u8; $module::SIG_LEN];

            fn keygen() -> Result<(Self::PublicKey, Self::SigningKey)> {
                <$module::KG as $krate::traits::KeyGen>::try_keygen().map_err(anyhow::Error::msg)
            }

            fn sign(sk: &Self::SigningKey, msg: &[u8]) -> Result<Self::Signature> {
                $krate::traits::Signer::try_sign(sk, msg, CONTEXT $(, $hedged)?)
                    .map_err(anyhow::Error::msg)
            }

            fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
                $krate::traits::Verifier::verify(pk, msg, sig, CONTEXT)
            }
        }
    };
}

pq_sig!(MlDsa, fips204, "ML-DSA-65", 3, ml_dsa_65,);
pq_sig!(MlDsa, fips204, "ML-DSA-87", 5, ml_dsa_87,);
pq_sig!(
    SlhDsa,
    fips205,
    "SLH-DSA-SHAKE-192s",
    3,
    slh_dsa_shake_192s,
    true
);
pq_sig!(
    SlhDsa,
    fips205,
    "SLH-DSA-SHAKE-192f",
    3,
    slh_dsa_shake_192f,
    true
);
pq_sig!(
    SlhDsa,
    fips205,
    "SLH-DSA-SHAKE-256s",
    5,
    slh_dsa_shake_256s,
    true
);
pq_sig!(
    SlhDsa,
    fips205,
    "SLH-DSA-SHAKE-256f",
    5,
    slh_dsa_shake_256f,
    true
);

pub type MlDsa65 = MlDsa<ml_dsa_65::KG>;
pub type MlDsa87 = MlDsa<ml_dsa_87::KG>;
pub type SlhDsa192s = SlhDsa<slh_dsa_shake_192s::KG>;
pub type SlhDsa192f = SlhDsa<slh_dsa_shake_192f::KG>;
pub type SlhDsa256s = SlhDsa<slh_dsa_shake_256s::KG>;
pub type SlhDsa256f = SlhDsa<slh_dsa_shake_256f::KG>;

/// The signature scheme chosen at compile time.
#[cfg(all(not(feature = "slh-dsa"), not(feature = "level-5")))]
pub type Selected = MlDsa65;
/// The signature scheme chosen at compile time.
#[cfg(all(not(feature = "slh-dsa"), feature = "level-5"))]
pub type Selected = MlDsa87;
/// The signature scheme chosen at compile time.
#[cfg(all(
    feature = "slh-dsa",
    not(feature = "slh-dsa-f"),
    not(feature = "level-5")
))]
pub type Selected = SlhDsa192s;
/// The signature scheme chosen at compile time.
#[cfg(all(feature = "slh-dsa", not(feature = "slh-dsa-f"), feature = "level-5"))]
pub type Selected = SlhDsa256s;
/// The signature scheme chosen at compile time.
#[cfg(all(feature = "slh-dsa-f", not(feature = "level-5")))]
pub type Selected = SlhDsa192f;
/// The signature scheme chosen at compile time.
#[cfg(all(feature = "slh-dsa-f", feature = "level-5"))]
pub type Selected = SlhDsa256f;

/// C4 with a post-quantum signature. The identity is a random Baby Jubjub
/// point, and `registry` maps it to the user's public key. Keygen runs on
/// several threads, so the registry is behind a mutex.
pub struct PqC4<P: PqSig> {
    registry: Mutex<HashMap<PointAffine, P::PublicKey>>,
}

impl<P: PqSig> Default for PqC4<P> {
    fn default() -> Self {
        Self {
            registry: Mutex::new(HashMap::new()),
        }
    }
}

impl<P: PqSig> Scheme for PqC4<P> {
    type SigningKey = P::SigningKey;
    type Signature = P::Signature;

    fn keygen<R: Rng + ?Sized>(&self, rng: &mut R) -> Result<(Point, P::SigningKey)> {
        let (pk, sk) = P::keygen()?;
        let id_u = base8() * rand_scalar(rng);
        match self
            .registry
            .lock()
            .expect("registry lock")
            .entry(id_u.into_affine())
        {
            Entry::Occupied(_) => bail!("identity already registered"),
            Entry::Vacant(slot) => slot.insert(pk),
        };
        Ok((id_u, sk))
    }

    /// Signs the 32-byte big-endian encoding of `msg`.
    fn sign<R: Rng + ?Sized>(
        &self,
        _: &Poseidon,
        key: &P::SigningKey,
        msg: Fq,
        _: &mut R,
    ) -> Result<P::Signature> {
        P::sign(key, &msg.into_bigint().to_bytes_be())
    }

    fn verify(&self, _: &Poseidon, id_u: PointAffine, msg: Fq, sig: &P::Signature) -> bool {
        self.registry
            .lock()
            .expect("registry lock")
            .get(&id_u)
            .is_some_and(|pk| P::verify(pk, &msg.into_bigint().to_bytes_be(), sig))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<P: PqSig>() {
        let (pk, sk) = P::keygen().unwrap();
        let sig = P::sign(&sk, b"message").unwrap();
        assert_eq!(sig.as_ref().len(), P::SIG_LEN);
        assert!(P::verify(&pk, b"message", &sig));
        assert!(!P::verify(&pk, b"messagf", &sig));
    }

    #[test]
    fn selected_scheme_signs_and_verifies() {
        roundtrip::<Selected>();
    }

    #[test]
    fn ml_dsa_signs_and_verifies() {
        roundtrip::<MlDsa65>();
        roundtrip::<MlDsa87>();
    }

    #[test]
    fn duplicate_identity_keeps_the_registered_key() {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let scheme = PqC4::<MlDsa65>::default();
        let poseidon = Poseidon::new();
        let msg = Fq::from(7u64);
        let (id, sk) = scheme.keygen(&mut StdRng::seed_from_u64(1)).unwrap();
        let sig = scheme
            .sign(&poseidon, &sk, msg, &mut rand::thread_rng())
            .unwrap();
        assert!(scheme.keygen(&mut StdRng::seed_from_u64(1)).is_err());
        assert!(scheme.verify(&poseidon, id.into_affine(), msg, &sig));
    }
}
