//! Longfellow (Google Benchmark) prove-verify benchmarks.
//!
//! The C++ benchmark binaries come from `third_party/longfellow-zk`; this crate
//! drives them and turns their JSON report into summaries.

pub mod cli;
pub mod driver;
pub mod gbench;
pub mod paths;
pub mod runner;
