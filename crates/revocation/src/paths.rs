//! Where the revocation stack reads its MP-SPDZ program and writes its CSVs.

use std::path::{Path, PathBuf};

/// The stack name used under `.work/` and `results/`.
pub const STACK: &str = "revocation";

/// The MP-SPDZ program and the sweep scripts, part of the source tree.
pub fn mpc() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("mpc")
}

/// Default folder of the direct/link experiment CSVs.
pub fn experiments() -> PathBuf {
    bench_core::paths::work(STACK)
        .join("out")
        .join("experiments")
}

/// `results/direct-decrypt` + `_runs.csv` -> `results/direct-decrypt_runs.csv`.
pub fn with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
    let mut name = prefix.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    prefix.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_extends_the_file_name() {
        let p = with_suffix(Path::new("/tmp/results/link-decrypt"), "_runs.csv");
        assert_eq!(p, Path::new("/tmp/results/link-decrypt_runs.csv"));
    }
}
