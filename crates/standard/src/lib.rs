//! Longfellow (Google Benchmark) prove-verify benchmarks.
//!
//! The C++ benchmark binaries come from `third_party/longfellow-zk`; this crate
//! drives them and turns their JSON report into summaries.

pub mod cli;
pub mod driver;
pub mod gbench;
pub mod paths;
pub mod runner;

/// The hash in the credential circuits and in Longfellow's proof system:
/// SHA-256, or SHAKE256 (48-byte output) with the `pq` feature.
#[cfg(not(feature = "pq"))]
pub const HASH: &str = "SHA-256";
/// The hash in the credential circuits and in Longfellow's proof system:
/// SHA-256, or SHAKE256 (48-byte output) with the `pq` feature.
#[cfg(feature = "pq")]
pub const HASH: &str = "SHAKE256";

/// Path of an EC credential benchmark binary under the Longfellow build tree:
/// `circuits/tests/ec/<name>_test`, or the SHAKE256 `<name>_pq_test` with the
/// `pq` feature.
#[cfg(not(feature = "pq"))]
#[macro_export]
macro_rules! ec_bench {
    ($name:literal) => {
        concat!("circuits/tests/ec/", $name, "_test")
    };
}

/// Path of an EC credential benchmark binary under the Longfellow build tree:
/// `circuits/tests/ec/<name>_test`, or the SHAKE256 `<name>_pq_test` with the
/// `pq` feature.
#[cfg(feature = "pq")]
#[macro_export]
macro_rules! ec_bench {
    ($name:literal) => {
        concat!("circuits/tests/ec/", $name, "_pq_test")
    };
}
