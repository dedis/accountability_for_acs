//! Benchmark plumbing shared by every stack: paths, the `--out` flag, timing,
//! summary statistics and the summary JSON. No cryptography, so the Longfellow
//! stack depends on it without pulling in arkworks.

pub mod cli;
pub mod paths;
pub mod report;
pub mod stats;
pub mod time;
