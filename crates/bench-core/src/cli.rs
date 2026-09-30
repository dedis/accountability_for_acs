//! The output flag every benchmark binary shares.

use std::path::PathBuf;

use crate::paths;

/// `--out DIR`: where the benchmark writes `summary.json` (or its CSVs).
#[derive(clap::Args, Clone, Debug)]
pub struct Out {
    /// Output directory (default `.work/<stack>/out/<benchmark>`).
    #[arg(long, env = "BENCH_OUT")]
    pub out: Option<PathBuf>,
}

impl Out {
    pub fn dir(&self, stack: &str, bench: &str) -> PathBuf {
        self.out
            .clone()
            .unwrap_or_else(|| paths::work(stack).join("out").join(bench))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_defaults_under_the_stack_work_dir() {
        let unset = Out { out: None };
        assert_eq!(
            unset.dir("standard", "prove_verify"),
            paths::work("standard").join("out/prove_verify")
        );
        let set = Out {
            out: Some(PathBuf::from("/tmp/x")),
        };
        assert_eq!(set.dir("standard", "prove_verify"), PathBuf::from("/tmp/x"));
    }
}
