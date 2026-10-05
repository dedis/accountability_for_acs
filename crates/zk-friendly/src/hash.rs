//! Hashing helpers that are not Poseidon.

use ark_ff::PrimeField;

use babyjub::curve::Fq;

/// `sha256(message) mod p`, the JS `sha256Utf8ToField`.
///
/// The digest is read big-endian, as `bytesToBigIntBE` did.
#[cfg(not(feature = "pq"))]
pub fn utf8_to_field(message: &str) -> Fq {
    use sha2::{Digest, Sha256};

    Fq::from_be_bytes_mod_order(&Sha256::digest(message.as_bytes()))
}

/// `shake256(message, 32 bytes) mod p`, the output read big-endian.
#[cfg(feature = "pq")]
pub fn utf8_to_field(message: &str) -> Fq {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let mut shake = sha3::Shake256::default();
    shake.update(message.as_bytes());
    let mut out = [0u8; 32];
    shake.finalize_xof().read(&mut out);
    Fq::from_be_bytes_mod_order(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference values produced with Node's `crypto` module and the JS
    /// `sha256Utf8ToField(label, poseidon.F.p)`.
    #[cfg(not(feature = "pq"))]
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

    /// Reference values from Python:
    /// `int.from_bytes(hashlib.shake_256(label.encode()).digest(32), "big") % p`.
    #[cfg(feature = "pq")]
    #[test]
    fn matches_python_shake256() {
        assert_eq!(
            utf8_to_field("birthDate").to_string(),
            "2432600820075956650057236295598837727148010477977098202214308242479968788307"
        );
        assert_eq!(
            utf8_to_field("IDx").to_string(),
            "821813632651930500733163207434146967684851077976555995501718932720860447588"
        );
        assert_eq!(
            utf8_to_field("revocationIndex").to_string(),
            "2885427765150852092277827815434377694420497462120866805931999758378821402326"
        );
    }
}
