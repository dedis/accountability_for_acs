//! Environment variables, read the way the JS `process.env` lookups did:
//! an unset or blank variable means "use the default".

use anyhow::{Context, Result};

/// The variable's value, unless it is unset or blank.
pub fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// A positive integer, or `default` when the variable is unset.
pub fn usize_or(name: &str, default: usize) -> Result<usize> {
    var(name).map_or(Ok(default), |raw| {
        raw.trim()
            .parse()
            .with_context(|| format!("{name} must be a positive integer, got {raw:?}"))
    })
}
