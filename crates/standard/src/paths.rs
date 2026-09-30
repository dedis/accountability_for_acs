//! Where the standard stack finds Longfellow and writes its outputs.

use std::path::{Path, PathBuf};

use bench_core::paths;

/// The stack name used under `.work/` and `results/`.
pub const STACK: &str = "standard";

/// The vendored Longfellow tree.
pub fn longfellow() -> PathBuf {
    paths::root().join("third_party").join("longfellow-zk")
}

/// Longfellow's CMake build; `LONGFELLOW_BUILD_DIR` overrides it.
pub fn build_dir() -> PathBuf {
    std::env::var_os("LONGFELLOW_BUILD_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(
            || paths::work(STACK).join("longfellow-build"),
            PathBuf::from,
        )
}

/// Where the CMake release build puts a benchmark binary.
pub fn default_bin_path(test_name: &str) -> PathBuf {
    build_dir()
        .join("circuits")
        .join("tests")
        .join("ec")
        .join(test_name)
}

/// The proof-size measurement programs and their build scripts.
pub fn measure() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("measure")
}
