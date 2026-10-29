//! Hashing helpers of the classical credential that are not Poseidon. The
//! post-quantum credential (`pq` module) hashes with SHAKE256 only.

use ark_ff::PrimeField;

use babyjub::curve::Fq;

/// `sha256(message) mod p`, the JS `sha256Utf8ToField`.
///
/// The digest is read big-endian, as `bytesToBigIntBE` did.
pub fn utf8_to_field(message: &str) -> Fq {
    use sha2::{Digest, Sha256};

    Fq::from_be_bytes_mod_order(&Sha256::digest(message.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values produced with Node's `crypto` module and the JS
    /// `sha256Utf8ToField(label, poseidon.F.p)`.
    #[test]
    fn matches_the_js_helper() {
        assert_eq!(
            utf8_to_field("birthDate").to_string(),
            "9983360410105296554386776852684647305244910782762386124785209477480273135523"
        );
        assert_eq!(
            utf8_to_field("IDx").to_string(),
            "12732709020872652360069269925832650377223872363138398435307608778311378246123"
        );
        assert_eq!(
            utf8_to_field("revocationIndex").to_string(),
            "556636330850170629258383134745417724444263682277322717598551509432075897268"
        );
    }
}
