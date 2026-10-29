//! ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), and the scheme chosen at
//! compile time: the C4 and issuer signatures of the post-quantum stacks.
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

use std::marker::PhantomData;

use anyhow::Result;
use fips204::{ml_dsa_65, ml_dsa_87};
use fips205::{slh_dsa_shake_192f, slh_dsa_shake_192s, slh_dsa_shake_256f, slh_dsa_shake_256s};

/// Context string of every signature (FIPS 204/205 `ctx`): empty, as the
/// witnesses of the credential proof (OpenSSL's default,
/// `third_party/longfellow-zk/lib/circuits/tests/pq/credential/ossl_sig.h`),
/// so that a C4 signed here verifies in the proof and the reverse.
pub const CONTEXT: &[u8] = b"";

/// One post-quantum signature parameter set. Signing is hedged with OS
/// randomness.
pub trait PqSig {
    /// Name, as in the FIPS.
    const NAME: &'static str;
    /// NIST security category.
    const CATEGORY: u8;
    /// Signature size in bytes.
    const SIG_LEN: usize;

    type PublicKey: Clone + Send + Sync;
    type SigningKey: Send + Sync;
    type Signature: AsRef<[u8]> + Send;

    fn keygen() -> Result<(Self::PublicKey, Self::SigningKey)>;
    fn sign(sk: &Self::SigningKey, msg: &[u8]) -> Result<Self::Signature>;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
    /// The encoded public key (FIPS 204 `pkEncode`, FIPS 205 `PK.seed || PK.root`).
    fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8>;
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

            fn public_key_bytes(pk: &Self::PublicKey) -> Vec<u8> {
                $krate::traits::SerDes::into_bytes(pk.clone()).to_vec()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<P: PqSig>() {
        let (pk, sk) = P::keygen().unwrap();
        let sig = P::sign(&sk, b"message").unwrap();
        assert_eq!(sig.as_ref().len(), P::SIG_LEN);
        assert!(P::verify(&pk, b"message", &sig));
        assert!(!P::verify(&pk, b"messagf", &sig));
        let (other, _) = P::keygen().unwrap();
        assert!(!P::verify(&other, b"message", &sig));
        assert_ne!(P::public_key_bytes(&pk), P::public_key_bytes(&other));
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

    /// FIPS 204 Table 2: public key sizes.
    #[test]
    fn ml_dsa_public_keys_have_the_fips_size() {
        assert_eq!(
            MlDsa65::public_key_bytes(&MlDsa65::keygen().unwrap().0).len(),
            1952
        );
        assert_eq!(
            MlDsa87::public_key_bytes(&MlDsa87::keygen().unwrap().0).len(),
            2592
        );
    }
}
