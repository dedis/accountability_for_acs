//! Baby Jubjub, Poseidon and EdDSA-Poseidon in the circomlib parameterisation,
//! shared by the revocation and zk-friendly stacks so the tags one produces are
//! the tags the other's circuits check.

pub mod curve;
pub mod eddsa;
pub mod poseidon;
