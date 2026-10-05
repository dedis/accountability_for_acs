//! Baby Jubjub CFT anonymity-revocation benchmarks: direct decryption,
//! link-then-decrypt, and the MP-SPDZ plaintext-equivalence sweep.
//!
//! The C4 binding uses the shared `babyjub` crate. Without the `pq` feature,
//! the tags produced here are the ones the zk-friendly `prove_verify.circom`
//! accepts; with it, the C4 message is SHAKE256 (see [`hash`]) while the
//! circuit still uses Poseidon.

pub mod c4;
pub mod cft;
pub mod csv;
pub mod env;
pub mod experiment;
pub mod hash;
pub mod mpc_runner;
pub mod paths;
pub mod stats;
