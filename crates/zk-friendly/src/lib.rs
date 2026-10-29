//! Circom / Groth16 prove-verify benchmarks for the credential presentation
//! proof, and its post-quantum credential model.
//!
//! `circom`, `rapidsnark` and the `snarkjs` CLI are external tools driven by
//! [`zk_common`]; the classical credential model ([`credential`]: Poseidon,
//! EdDSA, ElGamal over Baby Jubjub), the witness inputs and the Groth16
//! verifier are native. Groth16 relies on pairings, which a quantum computer
//! breaks, and cannot prove the post-quantum statement, so the benchmarks
//! need the classical build ([`require_classical`]).
//!
//! With the `pq` feature, [`pq`] is the post-quantum credential model:
//! SHAKE256 only, the signature chosen at compile time and threshold
//! Module-LWE encryption, as the post-quantum credential proof of the
//! standard stack. It has no proof system yet.

pub mod circom_codegen;
pub mod credential;
pub mod groth16;
pub mod hash;
pub mod merkle;
pub mod paths;
pub mod poseidon_merkle;
#[cfg(feature = "pq")]
pub mod pq;
pub mod revocation_tree;
pub mod summary;
pub mod zk_common;

/// Fails in the post-quantum build: the Circom/Groth16 benchmarks prove the
/// classical statement only.
pub fn require_classical() -> anyhow::Result<()> {
    anyhow::ensure!(
        !cfg!(feature = "pq"),
        "the Circom/Groth16 benchmarks prove the classical credential (Poseidon, EdDSA, \
         ElGamal): Groth16 cannot prove the post-quantum one (ML-DSA or SLH-DSA, SHAKE256, \
         Module-LWE). Build without the pq feature \
         (cargo build-classical)"
    );
    Ok(())
}
