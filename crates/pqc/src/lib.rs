//! Post-quantum primitives shared by the `revocation` and `zk-friendly`
//! stacks:
//!
//! - [`shake`]: SHAKE256, the only hash;
//! - [`sig`]: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), chosen at compile
//!   time;
//! - [`lwe`]: Module-LWE encryption with a key shared by three authorities,
//!   whose shares can be refreshed.
//!
//! The `level-5` feature selects NIST security category 5 in place of 3 for
//! all three.

pub mod lwe;
pub mod shake;
pub mod sig;
