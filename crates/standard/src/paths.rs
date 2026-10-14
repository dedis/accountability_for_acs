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

/// A Longfellow source tree and its CMake build.
#[derive(Clone, Copy, Debug)]
pub enum Tree {
    /// `third_party/longfellow-zk`, built in `LONGFELLOW_BUILD_DIR`.
    Main,
    /// `third_party/longfellow-zk-slh`, the copy with the SLH-DSA proofs,
    /// built in `LONGFELLOW_SLH_BUILD_DIR`.
    Slh,
}

impl Tree {
    pub fn source(self) -> PathBuf {
        match self {
            Tree::Main => longfellow(),
            Tree::Slh => paths::root().join("third_party").join("longfellow-zk-slh"),
        }
    }

    pub fn build_dir(self) -> PathBuf {
        match self {
            Tree::Main => build_dir(),
            Tree::Slh => std::env::var_os("LONGFELLOW_SLH_BUILD_DIR")
                .filter(|v| !v.is_empty())
                .map_or_else(
                    || paths::work(STACK).join("longfellow-slh-build"),
                    PathBuf::from,
                ),
        }
    }
}

/// Where the CMake release build of TREE puts a benchmark binary, given its
/// path relative to the build tree.
pub fn default_bin_path(tree: Tree, test_name: &str) -> PathBuf {
    tree.build_dir().join(test_name)
}

/// The proof-size measurement programs and their build scripts.
pub fn measure() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("measure")
}
