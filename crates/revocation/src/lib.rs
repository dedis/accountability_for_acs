//! CFT anonymity-revocation benchmarks: direct decryption, link-then-decrypt,
//! and the MP-SPDZ plaintext-equivalence sweep.
//!
//! Without the `pq` feature, the CFT is ElGamal over Baby Jubjub ([`cft`])
//! with an EdDSA-Poseidon C4 ([`c4`]), the tags the zk-friendly
//! `prove_verify.circom` accepts. With it, the CFT is threshold Module-LWE
//! encryption with a post-quantum C4 ([`lwe_cft`]), decrypted in the MPC
//! (`mpc/lwe_decrypt.mpc`); link-then-decrypt and the plaintext-equivalence
//! test need ElGamal and stop with an error.

pub mod c4;
pub mod cft;
pub mod csv;
pub mod env;
pub mod experiment;
pub mod hash;
#[cfg(feature = "pq")]
pub mod lwe_cft;
pub mod mpc_runner;
pub mod paths;
pub mod stats;
