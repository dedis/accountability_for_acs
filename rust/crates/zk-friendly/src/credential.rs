//! The 32-attribute credential and the per-show circuit input.

use anyhow::Result;
use ark_ec::CurveGroup;
use rand::Rng;
use serde::Serialize;

use crate::hash::sha256_utf8_to_field;
use babyjub::curve::{base8, fr_to_fq, rand_scalar, Fq, Point, PointAffine};
use babyjub::eddsa::{SecretKey, Signature};
use babyjub::poseidon::Poseidon;

pub const NUM_ATTRS: usize = 32;

/// Fixed reference instant the show inputs are built around.
pub const BASE_NOW_MS: u64 = 1_710_000_000_000;

const MS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

/// 18 Julian years (365.25 days) in milliseconds.
pub const fn eighteen_years_ms() -> u64 {
    18 * 36525 * MS_PER_DAY / 100
}

pub const fn days_ms(days: u64) -> u64 {
    days * MS_PER_DAY
}

/// `claimName = poseidon(sha256(label) mod p)`.
pub fn claim_name(poseidon: &Poseidon, label: &str) -> Fq {
    poseidon.hash(&[sha256_utf8_to_field(label)])
}

/// The attribute labels the benchmark credential carries.
const LABELS: [&str; NUM_ATTRS] = [
    "IDx",
    "IDy",
    "name",
    "familyName",
    "birthDate",
    "validFrom",
    "validUntil",
    "addressStreet",
    "addressNumber",
    "addressLocalityNumber",
    "addressCity",
    "addressCanton",
    "addressCountry",
    "cantonOfOrigin",
    "attr_14",
    "attr_15",
    "attr_16",
    "attr_17",
    "attr_18",
    "attr_19",
    "attr_20",
    "attr_21",
    "attr_22",
    "attr_23",
    "attr_24",
    "attr_25",
    "attr_26",
    "attr_27",
    "attr_28",
    "attr_29",
    "attr_30",
    "attr_31",
];

/// An issued credential plus the keys needed to present it.
///
/// Building one is the untracked issuance step; [`Credential::show_input`]
/// produces the per-presentation witness input that the benchmarks time.
pub struct Credential {
    issuer: SecretKey,
    issuer_pub: PointAffine,
    user_sk: SecretKey,
    elgamal_pub: Point,
    pub base_now_ms: u64,
    pub max_birth_date_ms: u64,
    pub birth_date_ms: u64,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    id: PointAffine,
    claim_names: [Fq; NUM_ATTRS],
    claim_values: [Fq; NUM_ATTRS],
    signature: Signature,
}

/// Accumulates the flat attribute commitment
/// `acc_{i+1} = poseidon(acc_i, name_i, value_i)`.
pub fn flat_commitment(
    poseidon: &Poseidon,
    names: &[Fq; NUM_ATTRS],
    values: &[Fq; NUM_ATTRS],
) -> Fq {
    let mut acc = Fq::from(0u64);
    for i in 0..NUM_ATTRS {
        acc = poseidon.hash(&[acc, names[i], values[i]]);
    }
    acc
}

impl Credential {
    /// Issues the benchmark credential once; shows refresh only the per-use
    /// randomness.
    pub fn issue<R: Rng + ?Sized>(poseidon: &Poseidon, rng: &mut R) -> Self {
        let max_birth_date_ms = BASE_NOW_MS - eighteen_years_ms();
        let birth_date_ms = max_birth_date_ms - days_ms(365);
        let valid_from_ms = BASE_NOW_MS - days_ms(1);
        let valid_until_ms = BASE_NOW_MS + days_ms(365);

        let issuer = SecretKey::rand(rng);
        let user_sk = SecretKey::rand(rng);
        let elgamal_sk = rand_scalar(rng);
        let id = user_sk.public_key().into_affine();

        let claim_names = LABELS.map(|label| claim_name(poseidon, label));
        let mut claim_values = [Fq::from(0u64); NUM_ATTRS];
        claim_values[0] = id.x;
        claim_values[1] = id.y;
        claim_values[2] = sha256_utf8_to_field("Alice");
        claim_values[3] = sha256_utf8_to_field("Doe");
        claim_values[4] = Fq::from(birth_date_ms);
        claim_values[5] = Fq::from(valid_from_ms);
        claim_values[6] = Fq::from(valid_until_ms);
        claim_values[7] = sha256_utf8_to_field("Main Street");
        claim_values[8] = Fq::from(12u64);
        claim_values[9] = Fq::from(1000u64);
        claim_values[10] = sha256_utf8_to_field("Lausanne");
        claim_values[11] = sha256_utf8_to_field("VD");
        claim_values[12] = sha256_utf8_to_field("CH");
        claim_values[13] = sha256_utf8_to_field("VD");

        let commitment = flat_commitment(poseidon, &claim_names, &claim_values);
        let signature = issuer.sign_poseidon(poseidon, commitment, rng);

        Self {
            issuer_pub: issuer.public_key().into_affine(),
            issuer,
            user_sk,
            elgamal_pub: base8() * elgamal_sk,
            base_now_ms: BASE_NOW_MS,
            max_birth_date_ms,
            birth_date_ms,
            valid_from_ms,
            valid_until_ms,
            id,
            claim_names,
            claim_values,
            signature,
        }
    }

    /// Re-issues the credential with a revocation index in `slot`.
    pub fn with_revocation_index<R: Rng + ?Sized>(
        &self,
        poseidon: &Poseidon,
        slot: usize,
        index: u64,
        rng: &mut R,
    ) -> Self {
        let mut claim_names = self.claim_names;
        let mut claim_values = self.claim_values;
        claim_names[slot] = claim_name(poseidon, "revocationIndex");
        claim_values[slot] = Fq::from(index);

        let commitment = flat_commitment(poseidon, &claim_names, &claim_values);
        Self {
            issuer: self.issuer,
            issuer_pub: self.issuer_pub,
            user_sk: self.user_sk,
            elgamal_pub: self.elgamal_pub,
            id: self.id,
            signature: self.issuer.sign_poseidon(poseidon, commitment, rng),
            claim_names,
            claim_values,
            ..*self
        }
    }

    /// Builds the witness input for one presentation.
    pub fn show_input<R: Rng + ?Sized>(
        &self,
        poseidon: &Poseidon,
        show_index: u64,
        rng: &mut R,
    ) -> ShowInput {
        let t = rand_scalar(rng);
        let random_val1 = rand_scalar(rng);
        let random_val2 = rand_scalar(rng);

        let d2 = (self.elgamal_pub * random_val2).into_affine();
        let tag = poseidon.hash(&[fr_to_fq(t), d2.x, d2.y]);
        let c4 = self.user_sk.sign_poseidon(poseidon, tag, rng);

        ShowInput {
            elgamal_pub_key: point_strings(self.elgamal_pub.into_affine()),
            issuer_pub_key: point_strings(self.issuer_pub),
            t: t.to_string(),
            now: (self.base_now_ms + show_index).to_string(),
            max_birth_date: self.max_birth_date_ms.to_string(),
            idx_claim_name: self.claim_names[0].to_string(),
            idy_claim_name: self.claim_names[1].to_string(),
            bd_claim_name: self.claim_names[4].to_string(),
            vf_claim_name: self.claim_names[5].to_string(),
            vu_claim_name: self.claim_names[6].to_string(),
            claim_names: field_strings(&self.claim_names),
            claim_values: field_strings(&self.claim_values),
            id_x: self.id.x.to_string(),
            id_y: self.id.y.to_string(),
            birth_date: self.birth_date_ms.to_string(),
            valid_from: self.valid_from_ms.to_string(),
            valid_until: self.valid_until_ms.to_string(),
            sig_r: point_strings(self.signature.r8),
            sig_s: self.signature.s.to_string(),
            c4_sig_r: point_strings(c4.r8),
            c4_sig_s: c4.s.to_string(),
            random_val1: random_val1.to_string(),
            random_val2: random_val2.to_string(),
        }
    }
}

/// `[x, y]` as decimal strings, the circom input encoding of a point.
pub fn point_strings(p: PointAffine) -> [String; 2] {
    [p.x.to_string(), p.y.to_string()]
}

fn field_strings(values: &[Fq; NUM_ATTRS]) -> Vec<String> {
    values.iter().map(Fq::to_string).collect()
}

/// `input.json` for `prove_verify.circom`.
#[derive(Serialize)]
pub struct ShowInput {
    #[serde(rename = "elgamalPubKey")]
    pub elgamal_pub_key: [String; 2],
    #[serde(rename = "issuerPubKey")]
    pub issuer_pub_key: [String; 2],
    pub t: String,
    pub now: String,
    #[serde(rename = "maxBirthDate")]
    pub max_birth_date: String,
    #[serde(rename = "idxClaimName")]
    pub idx_claim_name: String,
    #[serde(rename = "idyClaimName")]
    pub idy_claim_name: String,
    #[serde(rename = "bdClaimName")]
    pub bd_claim_name: String,
    #[serde(rename = "vfClaimName")]
    pub vf_claim_name: String,
    #[serde(rename = "vuClaimName")]
    pub vu_claim_name: String,
    #[serde(rename = "claimNames")]
    pub claim_names: Vec<String>,
    #[serde(rename = "claimValues")]
    pub claim_values: Vec<String>,
    #[serde(rename = "IDx")]
    pub id_x: String,
    #[serde(rename = "IDy")]
    pub id_y: String,
    #[serde(rename = "birthDate")]
    pub birth_date: String,
    #[serde(rename = "validFrom")]
    pub valid_from: String,
    #[serde(rename = "validUntil")]
    pub valid_until: String,
    #[serde(rename = "sig_R")]
    pub sig_r: [String; 2],
    #[serde(rename = "sig_S")]
    pub sig_s: String,
    #[serde(rename = "c4Sig_R")]
    pub c4_sig_r: [String; 2],
    #[serde(rename = "c4Sig_S")]
    pub c4_sig_s: String,
    #[serde(rename = "randomVal1")]
    pub random_val1: String,
    #[serde(rename = "randomVal2")]
    pub random_val2: String,
}

/// Writes an input object as pretty JSON, as the JS `writeJson` did.
pub fn write_json<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use babyjub::eddsa;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn eighteen_years_matches_the_js_constant() {
        assert_eq!(eighteen_years_ms(), 568_036_800_000);
        assert_eq!(BASE_NOW_MS - eighteen_years_ms(), 1_141_963_200_000);
    }

    #[test]
    fn issued_signature_verifies_under_the_issuer_key() {
        let poseidon = Poseidon::new();
        let mut rng = StdRng::seed_from_u64(1);
        let cred = Credential::issue(&poseidon, &mut rng);

        let commitment = flat_commitment(&poseidon, &cred.claim_names, &cred.claim_values);
        assert!(eddsa::verify_poseidon(
            &poseidon,
            cred.issuer_pub,
            commitment,
            &cred.signature
        ));
    }

    #[test]
    fn revocation_index_is_signed_afresh() {
        let poseidon = Poseidon::new();
        let mut rng = StdRng::seed_from_u64(2);
        let cred = Credential::issue(&poseidon, &mut rng)
            .with_revocation_index(&poseidon, 14, 4242, &mut rng);

        assert_eq!(cred.claim_values[14], Fq::from(4242u64));
        assert_eq!(
            cred.claim_names[14],
            claim_name(&poseidon, "revocationIndex")
        );

        let commitment = flat_commitment(&poseidon, &cred.claim_names, &cred.claim_values);
        assert!(eddsa::verify_poseidon(
            &poseidon,
            cred.issuer_pub,
            commitment,
            &cred.signature
        ));
    }

    #[test]
    fn show_input_carries_the_identity_claims() {
        let poseidon = Poseidon::new();
        let mut rng = StdRng::seed_from_u64(3);
        let cred = Credential::issue(&poseidon, &mut rng);
        let input = cred.show_input(&poseidon, 7, &mut rng);

        assert_eq!(input.now, (BASE_NOW_MS + 7).to_string());
        assert_eq!(input.claim_values[0], input.id_x);
        assert_eq!(input.claim_values[1], input.id_y);
        assert_eq!(input.claim_names.len(), NUM_ATTRS);
    }
}
