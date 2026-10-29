//! SHAKE256, the hash of every post-quantum construction.

use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Digest length: 48 bytes (192-bit collision resistance, NIST category 3),
/// or 64 bytes with the `level-5` feature (category 5).
pub const DIGEST_BYTES: usize = if cfg!(feature = "level-5") { 64 } else { 48 };

/// A SHAKE256 digest of [`DIGEST_BYTES`] bytes.
pub type Digest = [u8; DIGEST_BYTES];

/// The first `N` bytes of SHAKE256 of the concatenation of `parts`.
pub fn shake256<const N: usize>(parts: &[&[u8]]) -> [u8; N] {
    let mut shake = sha3::Shake256::default();
    for part in parts {
        shake.update(part);
    }
    let mut out = [0u8; N];
    shake.finalize_xof().read(&mut out);
    out
}

/// SHAKE256 of the concatenation of `parts`, [`DIGEST_BYTES`] bytes.
pub fn digest(parts: &[&[u8]]) -> Digest {
    shake256(parts)
}

/// The event tag of a presentation request, from its public transcript:
/// `t = SHAKE256(be64(ts) || rid || verifier)`, [`DIGEST_BYTES`] bytes, as
/// `event_tag` in
/// `third_party/longfellow-zk/lib/circuits/tests/pq/credential/credential.h`.
/// C4 signs it, which binds a presentation to one request of one verifier.
pub fn event_tag(ts_ms: u64, rid: &[u8; 32], verifier: &[u8; 32]) -> Digest {
    digest(&[&ts_ms.to_be_bytes(), rid, verifier])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHAKE256 of the empty string (FIPS 202 test vectors), first 32 bytes.
    #[test]
    fn matches_the_empty_string_vector() {
        let expected = [
            0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13, 0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e,
            0xeb, 0x24, 0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82, 0xb5, 0x0c, 0x27, 0x64,
            0x6e, 0xd5, 0x76, 0x2f,
        ];
        assert_eq!(shake256::<32>(&[]), expected);
    }

    /// The vector `EventTag.MatchesTheVector` (`pq_credential_test.cc`) checks
    /// too, from Python's `hashlib.shake_256`.
    #[test]
    fn event_tag_matches_the_vector() {
        let hex: String = event_tag(1, &[1; 32], &[2; 32])
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let expected = "6ec7fb42c33190e4fa743e81aba1349dc5a787ac42d1885aa7220bea8e222dd9\
                        0836a8c10a2fd01c8b8b2d8037384413\
                        5f25dc356c2b29d64bc25d42547e3fc5";
        assert_eq!(hex, expected[..2 * DIGEST_BYTES]);
    }

    #[test]
    fn hashes_the_concatenation() {
        assert_eq!(digest(&[b"ab", b"c"]), digest(&[b"abc"]));
        assert_ne!(digest(&[b"abc"]), digest(&[b"abd"]));
        let short: [u8; 32] = shake256(&[b"abc"]);
        assert_eq!(short[..], digest(&[b"abc"])[..32]);
    }
}
