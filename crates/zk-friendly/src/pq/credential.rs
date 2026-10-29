//! The post-quantum credential and its presentation, as
//! `third_party/longfellow-zk/lib/circuits/tests/pq/credential/credential.h`:
//! 32 attributes of 32 bytes; leaf `i = SHAKE256(be32(i) || attribute i)`;
//! the credential digest `D = SHAKE256(leaf 0 || ... || leaf 31)`, signed by
//! the issuer. Used attributes:
//!
//! - 4, 5, 6: birth, valid from, valid until: 43-bit millisecond timestamps,
//!   big-endian in the last 8 bytes;
//! - 0, 1 with CFT: the ID of the user (C4) key, bytes 0-31 and 32-63;
//! - 14, 15 without CFT: the ID of the hardware key.
//!
//! `ID = SHAKE256(public key, 64 bytes)`. A presentation with CFT answers a
//! request `rid` of a verifier at time `now`: the event tag
//! `t = event_tag(now, rid, verifier)` ([`pqc::shake::event_tag`]), the
//! private `C4 = Sign_user(SHAKE256(t || r2))`, the Module-LWE encryption
//! of `ID || r2` under the authorities' key and the binding
//! `h = SHAKE256(ID || r2)`; without CFT, a hardware-key signature on a fresh
//! nonce. [`Credential::check`] verifies the statement the proof would show,
//! natively, except the encryption relation, which needs the encryption
//! randomness: the tests check it by decrypting.

use anyhow::{ensure, Result};
use rand::{CryptoRng, Rng};

use pqc::lwe::{self, Ciphertext, MSG_BYTES};
use pqc::shake::{self, Digest};
use pqc::sig::{PqSig, Selected};

use crate::credential::{days_ms, eighteen_years_ms, BASE_NOW_MS, NUM_ATTRS};

pub const ATTR_BYTES: usize = 32;
/// `SHAKE256(pk, 64 bytes)`.
pub const ID_BYTES: usize = 64;
/// Timestamps are below `2^43` ms.
pub const TS_BITS: u32 = 43;
pub const SLOT_BIRTH: usize = 4;
pub const SLOT_VALID_FROM: usize = 5;
pub const SLOT_VALID_UNTIL: usize = 6;
/// Length of the request ID, the verifier ID, `r2` and the nonce.
pub const NONCE_BYTES: usize = 32;
const _: () = assert!(ID_BYTES + NONCE_BYTES == MSG_BYTES);

pub type Attribute = [u8; ATTR_BYTES];
pub type Id = [u8; ID_BYTES];

/// First of the two attributes holding the ID: the user key with CFT, the
/// hardware key without.
pub const fn id_slot(cft: bool) -> usize {
    if cft {
        0
    } else {
        14
    }
}

/// `ID = SHAKE256(pk, 64 bytes)`.
pub fn id_of<P: PqSig>(pk: &P::PublicKey) -> Id {
    shake::shake256(&[&P::public_key_bytes(pk)])
}

/// A presentation. With CFT, `rid`, `verifier`, `ct` and `h` are public;
/// `r2` and `c4` are private inputs of the proof. C4 must stay private: an
/// ML-DSA or SLH-DSA signature shows its public key without the message.
pub enum Presentation<S> {
    Cft {
        rid: [u8; NONCE_BYTES],
        verifier: [u8; NONCE_BYTES],
        r2: [u8; NONCE_BYTES],
        ct: Ciphertext,
        h: Digest,
        c4: S,
    },
    NoCft {
        nonce: [u8; NONCE_BYTES],
        sig: S,
    },
}

/// One presentation of a credential, with its public time bounds.
pub struct Show<S> {
    pub now_ms: u64,
    pub max_birth_ms: u64,
    pub presentation: Presentation<S>,
}

/// An issued credential plus the keys needed to present it: the user (C4)
/// key with CFT, the hardware key without.
pub struct Credential<P: PqSig = Selected> {
    issuer_pk: P::PublicKey,
    issuer_sk: P::SigningKey,
    holder_pk: P::PublicKey,
    holder_sk: P::SigningKey,
    pub cft: bool,
    pub attrs: [Attribute; NUM_ATTRS],
    pub max_birth_ms: u64,
    signature: P::Signature,
}

/// `x` big-endian in the last 8 bytes of an attribute.
fn timestamp(x: u64) -> Attribute {
    let mut a = [0u8; ATTR_BYTES];
    a[ATTR_BYTES - 8..].copy_from_slice(&x.to_be_bytes());
    a
}

fn read_timestamp(a: &Attribute) -> Option<u64> {
    a[..ATTR_BYTES - 8]
        .iter()
        .all(|&b| b == 0)
        .then(|| u64::from_be_bytes(a[ATTR_BYTES - 8..].try_into().expect("8 bytes")))
        .filter(|&x| x < 1 << TS_BITS)
}

impl<P: PqSig> Credential<P> {
    /// Issues the benchmark credential, with the time bounds of the classical
    /// one ([`crate::credential::Credential::issue`]): born a year before the
    /// 18-year bound, valid from a day before [`BASE_NOW_MS`] for a year.
    /// The other attributes are random.
    pub fn issue<R: Rng + CryptoRng + ?Sized>(cft: bool, rng: &mut R) -> Result<Self> {
        let (issuer_pk, issuer_sk) = P::keygen()?;
        let (holder_pk, holder_sk) = P::keygen()?;
        let max_birth_ms = BASE_NOW_MS - eighteen_years_ms();

        let mut attrs: [Attribute; NUM_ATTRS] = std::array::from_fn(|_| rng.gen());
        attrs[SLOT_BIRTH] = timestamp(max_birth_ms - days_ms(365));
        attrs[SLOT_VALID_FROM] = timestamp(BASE_NOW_MS - days_ms(1));
        attrs[SLOT_VALID_UNTIL] = timestamp(BASE_NOW_MS + days_ms(365));
        let id = id_of::<P>(&holder_pk);
        let s = id_slot(cft);
        attrs[s].copy_from_slice(&id[..ATTR_BYTES]);
        attrs[s + 1].copy_from_slice(&id[ATTR_BYTES..]);

        let signature = P::sign(&issuer_sk, &digest(&attrs))?;
        Ok(Self {
            issuer_pk,
            issuer_sk,
            holder_pk,
            holder_sk,
            cft,
            attrs,
            max_birth_ms,
            signature,
        })
    }

    /// Re-issues the credential with a revocation index in `slot`, big-endian
    /// in the last 8 bytes.
    pub fn set_revocation_index(&mut self, slot: usize, index: u64) -> Result<()> {
        let s = id_slot(self.cft);
        ensure!(
            slot < NUM_ATTRS
                && ![SLOT_BIRTH, SLOT_VALID_FROM, SLOT_VALID_UNTIL, s, s + 1].contains(&slot),
            "attribute {slot} holds no revocation index"
        );
        self.attrs[slot] = timestamp(index);
        self.signature = P::sign(&self.issuer_sk, &digest(&self.attrs))?;
        Ok(())
    }

    /// A presentation at `BASE_NOW_MS + show_index` for the request `rid` of
    /// `verifier`, both chosen by the verifier: with CFT, a fresh `r2`, C4,
    /// the encryption of `ID || r2` under `key` and its binding; without, a
    /// signature on a fresh nonce.
    pub fn show<R: Rng + CryptoRng + ?Sized>(
        &self,
        key: &lwe::PublicKey,
        verifier: &[u8; NONCE_BYTES],
        rid: &[u8; NONCE_BYTES],
        show_index: u64,
        rng: &mut R,
    ) -> Result<Show<P::Signature>> {
        let now_ms = BASE_NOW_MS + show_index;
        let presentation = if self.cft {
            let r2: [u8; NONCE_BYTES] = rng.gen();
            let t = shake::event_tag(now_ms, rid, verifier);
            let mut m = [0u8; MSG_BYTES];
            m[..ID_BYTES].copy_from_slice(&id_of::<P>(&self.holder_pk));
            m[ID_BYTES..].copy_from_slice(&r2);
            Presentation::Cft {
                c4: P::sign(&self.holder_sk, &shake::digest(&[&t, &r2]))?,
                ct: lwe::encrypt(key, &m, rng),
                h: shake::digest(&[&m]),
                rid: *rid,
                verifier: *verifier,
                r2,
            }
        } else {
            let nonce: [u8; NONCE_BYTES] = rng.gen();
            Presentation::NoCft {
                sig: P::sign(&self.holder_sk, &nonce)?,
                nonce,
            }
        };
        Ok(Show {
            now_ms,
            max_birth_ms: self.max_birth_ms,
            presentation,
        })
    }

    /// The statement of a presentation, checked natively: the issuer signed
    /// the digest; `now` and `max_birth` are below `2^43` (the width the
    /// proof compares), `birth <= max_birth` and `valid_from <= now <=
    /// valid_until`; the ID attributes are `SHAKE256` of the holder key; the
    /// holder key signed `SHAKE256(t || r2)`, with `t` the event tag of the
    /// show, or the nonce; and `h = SHAKE256(ID || r2)`. Not the encryption
    /// relation: see the module documentation.
    pub fn check(&self, show: &Show<P::Signature>) -> bool {
        let ts = |slot: usize| read_timestamp(&self.attrs[slot]);
        let (Some(birth), Some(from), Some(until)) =
            (ts(SLOT_BIRTH), ts(SLOT_VALID_FROM), ts(SLOT_VALID_UNTIL))
        else {
            return false;
        };
        let s = id_slot(self.cft);
        let id = id_of::<P>(&self.holder_pk);
        let holder_signed = match &show.presentation {
            Presentation::Cft {
                rid,
                verifier,
                r2,
                h,
                c4,
                ..
            } => {
                let t = shake::event_tag(show.now_ms, rid, verifier);
                self.cft
                    && P::verify(&self.holder_pk, &shake::digest(&[&t, r2]), c4)
                    && *h == shake::digest(&[&id, r2])
            }
            Presentation::NoCft { nonce, sig } => {
                !self.cft && P::verify(&self.holder_pk, nonce, sig)
            }
        };
        P::verify(&self.issuer_pk, &self.digest(), &self.signature)
            && show.now_ms < 1 << TS_BITS
            && show.max_birth_ms < 1 << TS_BITS
            && birth <= show.max_birth_ms
            && from <= show.now_ms
            && show.now_ms <= until
            && self.attrs[s][..] == id[..ATTR_BYTES]
            && self.attrs[s + 1][..] == id[ATTR_BYTES..]
            && holder_signed
    }

    /// Leaf `i`: `SHAKE256(be32(i) || attribute i)`.
    pub fn leaf(&self, i: usize) -> Digest {
        leaf(i, &self.attrs[i])
    }

    /// The credential digest the issuer signs.
    pub fn digest(&self) -> Digest {
        digest(&self.attrs)
    }
}

/// `SHAKE256(be32(i) || attribute)`.
pub fn leaf(i: usize, attribute: &Attribute) -> Digest {
    let mut index = [0u8; 32];
    index[28..].copy_from_slice(&u32::try_from(i).expect("attribute index").to_be_bytes());
    shake::digest(&[&index, attribute])
}

/// `D = SHAKE256(leaf 0 || ... || leaf 31)`.
pub fn digest(attrs: &[Attribute; NUM_ATTRS]) -> Digest {
    let leaves: Vec<Digest> = attrs.iter().enumerate().map(|(i, a)| leaf(i, a)).collect();
    let parts: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    shake::digest(&parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqc::lwe::{PublicKey, Share, PARTIES};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// The authorities' key shares and joint key.
    fn authorities(rng: &mut StdRng) -> ([Share; PARTIES], PublicKey) {
        let seed = [3u8; 32];
        let a = lwe::expand_a(&seed).unwrap();
        let (s0, c0) = lwe::contribute(&a, rng);
        let (s1, c1) = lwe::contribute(&a, rng);
        let (s2, c2) = lwe::contribute(&a, rng);
        let commitments = [
            c0.commitment(&seed, 0),
            c1.commitment(&seed, 1),
            c2.commitment(&seed, 2),
        ];
        let key = PublicKey::new(&seed, &[c0, c1, c2], &commitments).unwrap();
        ([s0, s1, s2], key)
    }

    const VERIFIER: [u8; NONCE_BYTES] = [0x56; NONCE_BYTES];
    const RID: [u8; NONCE_BYTES] = [0x52; NONCE_BYTES];

    #[test]
    fn leaves_follow_credential_h() {
        let attr = [9u8; ATTR_BYTES];
        let mut input = [0u8; 64];
        input[31] = 7;
        input[32..].copy_from_slice(&attr);
        assert_eq!(leaf(7, &attr), shake::digest(&[&input]));
    }

    #[test]
    fn a_cft_presentation_holds_and_decrypts_to_id_and_r2() {
        let mut rng = StdRng::seed_from_u64(1);
        let (shares, key) = authorities(&mut rng);
        let cred = Credential::<Selected>::issue(true, &mut rng).unwrap();
        let show = cred.show(&key, &VERIFIER, &RID, 7, &mut rng).unwrap();
        assert_eq!(show.now_ms, BASE_NOW_MS + 7);
        assert!(cred.check(&show));

        let Presentation::Cft { ct, r2, .. } = &show.presentation else {
            panic!("CFT credential");
        };
        let m = lwe::combine(&std::array::from_fn(|i| shares[i].decrypt(ct, i == 0)));
        assert_eq!(m[..ID_BYTES], id_of::<Selected>(&cred.holder_pk)[..]);
        assert_eq!(m[ID_BYTES..], r2[..]);
    }

    #[test]
    fn a_cft_presentation_is_bound_to_its_request() {
        let mut rng = StdRng::seed_from_u64(5);
        let (_, key) = authorities(&mut rng);
        let cred = Credential::<Selected>::issue(true, &mut rng).unwrap();
        let show = cred.show(&key, &VERIFIER, &RID, 0, &mut rng).unwrap();
        assert!(cred.check(&show));
        let Presentation::Cft {
            rid,
            verifier,
            r2,
            ct,
            h,
            c4,
        } = show.presentation
        else {
            panic!("CFT credential");
        };
        let flip = |mut x: [u8; NONCE_BYTES]| {
            x[0] ^= 1;
            x
        };
        let mut other_h = h;
        other_h[0] ^= 1;
        for (now_ms, rid, verifier, h) in [
            (show.now_ms, flip(rid), verifier, h),
            (show.now_ms, rid, flip(verifier), h),
            (show.now_ms + 1, rid, verifier, h),
            (show.now_ms, rid, verifier, other_h),
        ] {
            let moved = Show {
                now_ms,
                max_birth_ms: show.max_birth_ms,
                presentation: Presentation::Cft {
                    rid,
                    verifier,
                    r2,
                    ct: ct.clone(),
                    h,
                    c4,
                },
            };
            assert!(!cred.check(&moved));
        }
    }

    #[test]
    fn a_presentation_without_cft_holds() {
        let mut rng = StdRng::seed_from_u64(2);
        let (_, key) = authorities(&mut rng);
        let cred = Credential::<Selected>::issue(false, &mut rng).unwrap();
        assert!(cred.check(&cred.show(&key, &VERIFIER, &RID, 0, &mut rng).unwrap()));
    }

    #[test]
    fn a_changed_statement_fails() {
        let mut rng = StdRng::seed_from_u64(3);
        let (_, key) = authorities(&mut rng);
        let mut cred = Credential::<Selected>::issue(true, &mut rng).unwrap();
        let show = cred.show(&key, &VERIFIER, &RID, 0, &mut rng).unwrap();

        // Too young: max_birth before the birth date.
        let young = Show {
            max_birth_ms: show.max_birth_ms - days_ms(366),
            ..cred.show(&key, &VERIFIER, &RID, 0, &mut rng).unwrap()
        };
        assert!(!cred.check(&young));
        // Expired.
        let late = Show {
            now_ms: BASE_NOW_MS + days_ms(366),
            ..cred.show(&key, &VERIFIER, &RID, 0, &mut rng).unwrap()
        };
        assert!(!cred.check(&late));
        // A changed attribute: the issuer signature fails.
        cred.attrs[9][0] ^= 1;
        assert!(!cred.check(&show));
    }

    #[test]
    fn a_revocation_index_is_signed_afresh() {
        let mut rng = StdRng::seed_from_u64(4);
        let (_, key) = authorities(&mut rng);
        let mut cred = Credential::<Selected>::issue(true, &mut rng).unwrap();
        cred.set_revocation_index(14, 4242).unwrap();
        assert_eq!(read_timestamp(&cred.attrs[14]), Some(4242));
        assert!(cred.check(&cred.show(&key, &VERIFIER, &RID, 0, &mut rng).unwrap()));
        for used in [0, 1, SLOT_BIRTH, SLOT_VALID_UNTIL, NUM_ATTRS] {
            assert!(cred.set_revocation_index(used, 1).is_err());
        }
    }
}
