//! The hash behind the C4 message and the PET C4 binding: Poseidon, or
//! SHAKE256 with the `pq` feature.

use babyjub::curve::Fq;
use babyjub::poseidon::Poseidon;

/// Hashes field elements to a field element with Poseidon.
#[cfg(not(feature = "pq"))]
#[inline]
pub fn to_fq(poseidon: &Poseidon, inputs: &[Fq]) -> Fq {
    poseidon.hash(inputs)
}

/// Hashes field elements to a field element with SHAKE256: the input is the
/// concatenation of their 32-byte big-endian encodings, and the 32-byte output
/// is read as a big-endian integer modulo p.
#[cfg(feature = "pq")]
pub fn to_fq(_: &Poseidon, inputs: &[Fq]) -> Fq {
    use ark_ff::PrimeField;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut shake = sha3::Shake256::default();
    for x in inputs {
        // Little-endian 64-bit limbs, most significant first: 32 bytes BE.
        for limb in x.into_bigint().0.iter().rev() {
            shake.update(&limb.to_be_bytes());
        }
    }
    let mut out = [0u8; 32];
    shake.finalize_xof().read(&mut out);
    Fq::from_be_bytes_mod_order(&out)
}

#[cfg(all(test, feature = "pq"))]
mod tests {
    use super::*;

    /// Reference value from Python: `int.from_bytes(hashlib.shake_256(
    /// b"".join(x.to_bytes(32, "big") for x in [1, 2, 3])).digest(32), "big") % p`.
    #[test]
    fn matches_python_shake256() {
        let inputs = [Fq::from(1u64), Fq::from(2u64), Fq::from(3u64)];
        assert_eq!(
            to_fq(&Poseidon::new(), &inputs).to_string(),
            "6815949648680181216063604780429555423187430649667665861448413699688549098149"
        );
    }
}
