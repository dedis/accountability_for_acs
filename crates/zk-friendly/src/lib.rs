//! Circom / Groth16 prove-verify benchmarks for the credential presentation
//! proof.
//!
//! `circom`, `rapidsnark` and the `snarkjs` CLI are external tools driven by
//! [`zk_common`]; the credential model, the witness inputs and the Groth16
//! verifier are native.

pub mod circom_codegen;
pub mod credential;
pub mod groth16;
pub mod hash;
pub mod paths;
pub mod poseidon_merkle;
pub mod revocation_tree;
pub mod summary;
pub mod zk_common;
