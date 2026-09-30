//! Where things live: the workspace root, and `.work/` for everything a run
//! creates (downloads, generated circuits, builds, per-iteration files, default
//! outputs). `.work/` is disposable: deleting it only costs a rebuild.

use std::path::{Path, PathBuf};

/// `rust/`, the workspace root.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bench-core lives at <root>/crates/bench-core")
        .to_path_buf()
}

/// `<root>/.work`, or `BENCH_WORK_DIR` when set.
pub fn work_dir() -> PathBuf {
    std::env::var_os("BENCH_WORK_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(|| root().join(".work"), PathBuf::from)
}

/// One stack's scratch space, e.g. `.work/zk-friendly`.
pub fn work(stack: &str) -> PathBuf {
    work_dir().join(stack)
}

/// Third-party files fetched by `tools/fetch.py`.
pub fn downloads() -> PathBuf {
    work_dir().join("downloads")
}
