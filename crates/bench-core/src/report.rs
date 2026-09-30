//! Writing the summary JSON every benchmark produces.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

/// Writes `dir/summary.json` and returns its path.
pub fn write<T: Serialize>(dir: &Path, summary: &T) -> Result<PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("summary.json");
    let mut body = serde_json::to_vec_pretty(summary)?;
    body.push(b'\n');
    std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}
