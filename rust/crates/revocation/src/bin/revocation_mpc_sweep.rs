//! Thin entry point for the MP-SPDZ sweep, equivalent to `bash mpc/run_sweep.sh`.
//! Needs `MP_SPDZ_PATH`.

use std::process::Command;

use anyhow::{Context, Result};
use revocation::paths;

fn main() -> Result<()> {
    let script = paths::mpc().join("run_sweep.sh");
    let status = Command::new("bash")
        .arg(&script)
        .status()
        .with_context(|| format!("run {}", script.display()))?;
    std::process::exit(status.code().unwrap_or(1));
}
