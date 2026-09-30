//! Groth16 verification over BN254, reading `snarkjs`' JSON encodings.
//!
//! Replaces the in-process `snarkjs.groth16.verify` call. The verification
//! equation is the standard one,
//!
//! ```text
//! e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1,
//! vk_x = IC₀ + Σ publicᵢ · ICᵢ₊₁
//! ```
//!
//! and is evaluated as a single multi-Miller loop with one final
//! exponentiation. The key's `γ` and `δ` are kept in prepared form. Each
//! verification computes the public-input MSM and the pairing equation.

use std::path::Path;

use anyhow::{bail, Context, Result};
use ark_bn254::{Bn254, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};

type G2Prepared = <Bn254 as Pairing>::G2Prepared;
use ark_ff::{One, PrimeField};
use serde::Deserialize;

/// `["x", "y", "z"]` — a G1 point in Jacobian coordinates.
type JsonG1 = [String; 3];
/// `[x, y, z]` — a G2 point in Jacobian coordinates, each Fq2 as `[c0, c1]`.
type JsonG2 = [[String; 2]; 3];

#[derive(Deserialize)]
struct VerifyingKeyJson {
    protocol: String,
    curve: String,
    vk_alpha_1: JsonG1,
    vk_beta_2: JsonG2,
    vk_gamma_2: JsonG2,
    vk_delta_2: JsonG2,
    #[serde(rename = "IC")]
    ic: Vec<JsonG1>,
}

#[derive(Deserialize)]
struct ProofJson {
    protocol: String,
    /// snarkjs writes it; rapidsnark does not.
    curve: Option<String>,
    pi_a: JsonG1,
    pi_b: JsonG2,
    pi_c: JsonG1,
}

/// A parsed `vkey-*.json`, with the input-independent pairing precomputed.
pub struct VerifyingKey {
    gamma_g2: G2Prepared,
    delta_g2: G2Prepared,
    ic: Vec<G1Affine>,
    /// `e(α, β)`, constant for a given key.
    alpha_beta: <Bn254 as Pairing>::TargetField,
}

/// A parsed `proof.json`.
pub struct Proof {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
}

fn field<F: PrimeField>(raw: &str) -> Result<F> {
    // Parsing directly into a field reduces modulo its order. Parse the
    // integer first so out-of-range inputs cannot alias valid field values.
    raw.parse::<F::BigInt>()
        .ok()
        .and_then(F::from_bigint)
        .with_context(|| format!("{raw:?} is not an unsigned integer below the field modulus"))
}

fn g1(raw: &JsonG1) -> Result<G1Affine> {
    let point = G1Projective::new_unchecked(field(&raw[0])?, field(&raw[1])?, field(&raw[2])?)
        .into_affine();
    if !point.is_on_curve() {
        bail!("G1 point is not on the curve");
    }
    Ok(point)
}

fn g2(raw: &JsonG2) -> Result<G2Affine> {
    let x = Fq2::new(field(&raw[0][0])?, field(&raw[0][1])?);
    let y = Fq2::new(field(&raw[1][0])?, field(&raw[1][1])?);
    let z = Fq2::new(field(&raw[2][0])?, field(&raw[2][1])?);
    let point = G2Projective::new_unchecked(x, y, z).into_affine();
    if !point.is_on_curve() {
        bail!("G2 point is not on the curve");
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        bail!("G2 point is not in the prime-order subgroup");
    }
    Ok(point)
}

fn check_header(protocol: &str, curve: Option<&str>) -> Result<()> {
    if protocol != "groth16" {
        bail!("expected a groth16 artifact, got protocol {protocol:?}");
    }
    if let Some(curve) = curve.filter(|c| *c != "bn128") {
        bail!("expected curve bn128, got {curve:?}");
    }
    Ok(())
}

impl VerifyingKey {
    pub fn from_json(text: &str) -> Result<Self> {
        let json: VerifyingKeyJson =
            serde_json::from_str(text).context("parse snarkjs verification key")?;
        check_header(&json.protocol, Some(&json.curve))?;

        let alpha = g1(&json.vk_alpha_1)?;
        let beta = g2(&json.vk_beta_2)?;
        let ic = json.ic.iter().map(g1).collect::<Result<Vec<_>>>()?;
        if ic.is_empty() {
            bail!("verification key has an empty IC");
        }

        Ok(Self {
            gamma_g2: g2(&json.vk_gamma_2)?.into(),
            delta_g2: g2(&json.vk_delta_2)?.into(),
            ic,
            alpha_beta: Bn254::pairing(alpha, beta).0,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        Self::from_json(
            &std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
        )
    }

    /// Number of public signals the key expects.
    pub fn public_input_count(&self) -> usize {
        self.ic.len() - 1
    }
}

impl Proof {
    pub fn from_json(text: &str) -> Result<Self> {
        let json: ProofJson = serde_json::from_str(text).context("parse snarkjs proof")?;
        check_header(&json.protocol, json.curve.as_deref())?;
        Ok(Self {
            a: g1(&json.pi_a)?,
            b: g2(&json.pi_b)?,
            c: g1(&json.pi_c)?,
        })
    }

    pub fn read(path: &Path) -> Result<Self> {
        Self::from_json(
            &std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?,
        )
    }
}

/// Reads a `public.json` array of decimal strings.
pub fn read_public_signals(path: &Path) -> Result<Vec<Fr>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    parse_public_signals(&text)
}

pub fn parse_public_signals(text: &str) -> Result<Vec<Fr>> {
    let raw: Vec<String> = serde_json::from_str(text).context("parse public signals")?;
    raw.iter().map(|s| field(s)).collect()
}

/// Checks the proof against the public signals.
///
/// Returns `false` for a well-formed but invalid proof, and an error only when
/// the inputs do not fit the key.
pub fn verify(vk: &VerifyingKey, public_signals: &[Fr], proof: &Proof) -> Result<bool> {
    if public_signals.len() != vk.public_input_count() {
        bail!(
            "expected {} public signals, got {}",
            vk.public_input_count(),
            public_signals.len()
        );
    }

    let msm = G1Projective::msm(&vk.ic[1..], public_signals)
        .map_err(|len| anyhow::anyhow!("IC and public signal lengths disagree ({len})"))?;
    let vk_x = (vk.ic[0].into_group() + msm).into_affine();

    let product = Bn254::multi_pairing(
        [-proof.a, vk_x, proof.c],
        [proof.b.into(), vk.gamma_g2.clone(), vk.delta_g2.clone()],
    );

    Ok((product.0 * vk.alpha_beta).is_one())
}

/// Reads and validates proof points and public signals before verification.
/// The presentation benchmarks exclude this work from their verify timer;
/// the Merkle-versus-flat sweep includes it.
pub struct ProofBundle {
    pub proof: Proof,
    pub public_signals: Vec<Fr>,
}

impl ProofBundle {
    pub fn read(proof_path: &Path, public_path: &Path) -> Result<Self> {
        Ok(Self {
            proof: Proof::read(proof_path)?,
            public_signals: read_public_signals(public_path)?,
        })
    }

    pub fn verify(&self, vk: &VerifyingKey) -> Result<bool> {
        verify(vk, &self.public_signals, &self.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;
    use ark_ec::PrimeGroup;
    use ark_ff::{Field, UniformRand};
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    /// `snarkjs` writes an Fq2 coordinate as `[c0, c1]` for `c0 + c1·u`. The
    /// canonical BN254 G2 generator pins that convention: if the halves were
    /// swapped, this point would not parse.
    #[test]
    fn g2_coordinate_order_matches_snarkjs() {
        let generator = g2(&[
            [
                "10857046999023057135944570762232829481370756359578518086990519993285655852781"
                    .into(),
                "11559732032986387107991004021392285783925812861821192530917403151452391805634"
                    .into(),
            ],
            [
                "8495653923123431417604973247489272438418190587263600148770280649306958101930"
                    .into(),
                "4082367875863433681332203403145435568316851327593401208105741076214120093531"
                    .into(),
            ],
            ["1".into(), "0".into()],
        ])
        .unwrap();
        assert_eq!(generator, G2Affine::generator());
    }

    fn g1_json(p: G1Affine) -> JsonG1 {
        [p.x.to_string(), p.y.to_string(), "1".into()]
    }

    fn g2_json(p: G2Affine) -> JsonG2 {
        [
            [p.x.c0.to_string(), p.x.c1.to_string()],
            [p.y.c0.to_string(), p.y.c1.to_string()],
            ["1".into(), "0".into()],
        ]
    }

    /// Builds a key and a proof that satisfy the Groth16 equation by
    /// construction, using a trapdoor the test knows.
    fn fixture(public_signals: &[Fr]) -> (String, String) {
        let mut rng = StdRng::seed_from_u64(11);
        let g1 = G1Projective::generator();
        let g2p = G2Projective::generator();

        let alpha = Fr::rand(&mut rng);
        let beta = Fr::rand(&mut rng);
        let gamma = Fr::rand(&mut rng);
        let delta = Fr::rand(&mut rng);

        let ic_scalars: Vec<Fr> = (0..=public_signals.len())
            .map(|_| Fr::rand(&mut rng))
            .collect();
        let x = ic_scalars[0]
            + ic_scalars[1..]
                .iter()
                .zip(public_signals)
                .map(|(ic, s)| *ic * s)
                .sum::<Fr>();

        // e(A, B) = e(α, β)·e(vk_x, γ)·e(C, δ)  ⟺  a·b = αβ + xγ + cδ
        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = (a * b - alpha * beta - x * gamma) * delta.inverse().unwrap();

        let vkey = serde_json::json!({
            "protocol": "groth16",
            "curve": "bn128",
            "nPublic": public_signals.len(),
            "vk_alpha_1": g1_json((g1 * alpha).into_affine()),
            "vk_beta_2": g2_json((g2p * beta).into_affine()),
            "vk_gamma_2": g2_json((g2p * gamma).into_affine()),
            "vk_delta_2": g2_json((g2p * delta).into_affine()),
            "IC": ic_scalars
                .iter()
                .map(|s| g1_json((g1 * s).into_affine()))
                .collect::<Vec<_>>(),
        });
        let proof = serde_json::json!({
            "protocol": "groth16",
            "curve": "bn128",
            "pi_a": g1_json((g1 * a).into_affine()),
            "pi_b": g2_json((g2p * b).into_affine()),
            "pi_c": g1_json((g1 * c).into_affine()),
        });

        (vkey.to_string(), proof.to_string())
    }

    #[test]
    fn accepts_a_satisfying_proof() {
        let signals = [Fr::from(7u64), Fr::from(11u64), Fr::from(13u64)];
        let (vkey_json, proof_json) = fixture(&signals);

        let vkey = VerifyingKey::from_json(&vkey_json).unwrap();
        let proof = Proof::from_json(&proof_json).unwrap();
        assert_eq!(vkey.public_input_count(), 3);
        assert!(verify(&vkey, &signals, &proof).unwrap());
    }

    #[test]
    fn rejects_tampered_public_signals() {
        let signals = [Fr::from(7u64), Fr::from(11u64), Fr::from(13u64)];
        let (vkey_json, proof_json) = fixture(&signals);

        let vkey = VerifyingKey::from_json(&vkey_json).unwrap();
        let proof = Proof::from_json(&proof_json).unwrap();

        let tampered = [Fr::from(7u64), Fr::from(12u64), Fr::from(13u64)];
        assert!(!verify(&vkey, &tampered, &proof).unwrap());
    }

    #[test]
    fn rejects_a_wrong_signal_count() {
        let signals = [Fr::from(7u64), Fr::from(11u64), Fr::from(13u64)];
        let (vkey_json, proof_json) = fixture(&signals);

        let vkey = VerifyingKey::from_json(&vkey_json).unwrap();
        let proof = Proof::from_json(&proof_json).unwrap();
        assert!(verify(&vkey, &signals[..2], &proof).is_err());
    }

    /// rapidsnark writes `proof.json` without the `curve` field.
    #[test]
    fn accepts_a_rapidsnark_proof_without_curve() {
        let signals = [Fr::from(7u64)];
        let (vkey_json, proof_json) = fixture(&signals);
        let mut proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
        proof.as_object_mut().unwrap().remove("curve");
        let vkey = VerifyingKey::from_json(&vkey_json).unwrap();
        let proof = Proof::from_json(&proof.to_string()).unwrap();
        assert!(verify(&vkey, &signals, &proof).unwrap());

        let text = r#"{"protocol":"groth16","curve":"bls12381","pi_a":["1","2","1"],
            "pi_b":[["1","2"],["3","4"],["1","0"]],"pi_c":["1","2","1"]}"#;
        assert!(Proof::from_json(text).is_err());
    }

    #[test]
    fn rejects_a_non_groth16_artifact() {
        let text = r#"{"protocol":"plonk","curve":"bn128","pi_a":["1","2","1"],
            "pi_b":[["1","2"],["3","4"],["1","0"]],"pi_c":["1","2","1"]}"#;
        assert!(Proof::from_json(text).is_err());
    }

    #[test]
    fn rejects_a_point_off_the_curve() {
        let text = r#"{"protocol":"groth16","curve":"bn128","pi_a":["1","3","1"],
            "pi_b":[["1","2"],["3","4"],["1","0"]],"pi_c":["1","2","1"]}"#;
        assert!(Proof::from_json(text).is_err());
    }

    #[test]
    fn reads_public_signals() {
        let signals = parse_public_signals(r#"["1","2","3"]"#).unwrap();
        assert_eq!(signals, [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
    }

    #[test]
    fn public_signals_must_be_in_the_scalar_field() {
        let largest = -Fr::one();
        let encoded = serde_json::to_string(&["0".to_string(), largest.to_string()]).unwrap();
        assert_eq!(
            parse_public_signals(&encoded).unwrap(),
            [Fr::from(0), largest]
        );
        for invalid in ["-1".to_string(), Fr::MODULUS.to_string(), "9".repeat(100)] {
            let encoded = serde_json::to_string(&[invalid]).unwrap();
            assert!(parse_public_signals(&encoded).is_err());
        }
    }

    #[test]
    fn every_point_coordinate_must_be_in_the_base_field() {
        assert_eq!(field::<Fq>(&(-Fq::one()).to_string()).unwrap(), -Fq::one());
        for invalid in ["-1".to_string(), Fq::MODULUS.to_string(), "9".repeat(100)] {
            for coordinate in 0..3 {
                let mut point = g1_json(G1Affine::generator());
                point[coordinate] = invalid.clone();
                assert!(g1(&point).is_err());
                for component in 0..2 {
                    let mut point = g2_json(G2Affine::generator());
                    point[coordinate][component] = invalid.clone();
                    assert!(g2(&point).is_err());
                }
            }
        }
    }

    #[test]
    fn parses_jacobian_coordinates_and_identity() {
        let p = G1Affine::generator();
        let z = Fq::from(2);
        assert_eq!(
            g1(&[
                (p.x * z.square()).to_string(),
                (p.y * z.square() * z).to_string(),
                z.to_string(),
            ])
            .unwrap(),
            p
        );
        let q = G2Affine::generator();
        let z = Fq2::new(Fq::from(2), Fq::from(3));
        let pair = |v: Fq2| [v.c0.to_string(), v.c1.to_string()];
        assert_eq!(
            g2(&[pair(q.x * z.square()), pair(q.y * z.square() * z), pair(z)]).unwrap(),
            q
        );
        assert!(g1(&["0".into(), "1".into(), "0".into()]).unwrap().is_zero());
        assert!(g2(&[
            ["0".into(), "0".into()],
            ["1".into(), "0".into()],
            ["0".into(), "0".into()],
        ])
        .unwrap()
        .is_zero());
    }

    #[test]
    fn changing_a_proof_point_to_identity_invalidates_the_proof() {
        let signals = [Fr::from(0)];
        let (vkey_json, proof_json) = fixture(&signals);
        let vkey = VerifyingKey::from_json(&vkey_json).unwrap();
        assert!(verify(&vkey, &signals, &Proof::from_json(&proof_json).unwrap()).unwrap());
        for name in ["pi_a", "pi_b", "pi_c"] {
            let mut tampered: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            tampered[name][2] = if name == "pi_b" {
                serde_json::json!(["0", "0"])
            } else {
                serde_json::json!("0")
            };
            let proof = Proof::from_json(&tampered.to_string()).unwrap();
            assert!(!verify(&vkey, &signals, &proof).unwrap(), "{name}");
        }
        let alias = serde_json::to_string(&[Fr::MODULUS.to_string()]).unwrap();
        assert!(parse_public_signals(&alias).is_err());
    }

    #[test]
    fn rejects_g2_points_outside_the_prime_order_subgroup() {
        let point = (0..100)
            .filter_map(|i| {
                G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::one()), false)
            })
            .find(|p| !p.is_in_correct_subgroup_assuming_on_curve())
            .expect("an on-curve point outside the subgroup");
        assert!(point.is_on_curve());
        let encoded = g2_json(point);
        assert!(g2(&encoded).is_err());
        let (vkey_json, proof_json) = fixture(&[Fr::from(1)]);
        let mut proof: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
        proof["pi_b"] = serde_json::json!(encoded);
        assert!(Proof::from_json(&proof.to_string()).is_err());
        for name in ["vk_beta_2", "vk_gamma_2", "vk_delta_2"] {
            let mut key: serde_json::Value = serde_json::from_str(&vkey_json).unwrap();
            key[name] = serde_json::json!(encoded);
            assert!(VerifyingKey::from_json(&key.to_string()).is_err(), "{name}");
        }
    }
}
