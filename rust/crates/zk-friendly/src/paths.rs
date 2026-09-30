//! Where the zk-friendly stack reads its circuits and writes everything else.

use std::path::{Path, PathBuf};

use bench_core::paths;

/// The stack name used under `.work/` and `results/`.
pub const STACK: &str = "zk-friendly";

/// Powers of Tau file, as listed in `third_party.toml`.
pub const PTAU_FILE: &str = "ppot_0080_19.ptau";

/// Hand-written circuits, part of the source tree.
pub fn circuits() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("circuits")
}

/// `.work/zk-friendly`.
pub fn work() -> PathBuf {
    paths::work(STACK)
}

/// Compiled outputs of one circuit (R1CS, keys, witness generator), and the
/// source of circuits generated at run time.
pub fn generated(circuit: &str) -> PathBuf {
    work().join("generated").join(circuit)
}

/// Per-iteration inputs, witnesses and proofs of one benchmark.
pub fn artifacts(bench: &str) -> PathBuf {
    work().join("artifacts").join(bench)
}

pub fn ptau() -> PathBuf {
    paths::downloads().join(PTAU_FILE)
}

/// The `-l` root holding `circomlib/`; `CIRCOM_LIB_PATH` overrides it.
pub fn circom_lib() -> PathBuf {
    std::env::var_os("CIRCOM_LIB_PATH")
        .filter(|v| !v.is_empty())
        .map_or_else(paths::downloads, PathBuf::from)
}
