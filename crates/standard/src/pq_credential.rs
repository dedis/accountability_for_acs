//! The post-quantum credential proof (`third_party/longfellow-zk`,
//! `lib/circuits/tests/pq/credential`) for the signature chosen at compile
//! time: the issuer signature and the hardware (no CFT) or C4 (CFT)
//! signature are ML-DSA or SLH-DSA, every hash is SHAKE256, and the CFT
//! encryption is Module-LWE (`crates/pqc/src/lwe.rs`). Built with the
//! `pq` feature.
//!
//! | Features | Scheme | Program |
//! |---|---|---|
//! | (none) | ML-DSA-65 | `pq_credential_test` |
//! | `level-5` | ML-DSA-87 | `pq_credential_5_test` |
//! | `slh-dsa` | SLH-DSA-SHAKE-192s | `pq_credential_test` |
//! | `slh-dsa`, `level-5` | SLH-DSA-SHAKE-256s | `pq_credential_5_test` |
//! | `slh-dsa-f` | SLH-DSA-SHAKE-192f | `pq_credential_test` |
//! | `slh-dsa-f`, `level-5` | SLH-DSA-SHAKE-256f | `pq_credential_5_test` |

use crate::driver::Bench;

macro_rules! scheme {
    ($name:literal, $tag:literal, $variant:literal, $program:literal) => {
        /// The CFT presentation.
        pub const CFT: Bench = Bench {
            backend: concat!(
                "Longfellow - ",
                $program,
                " (PQ credential with CFT: ",
                $name,
                " issuer and C4 signatures, Module-LWE encryption)"
            ),
            variant: concat!("pq_prove_verify_", $variant),
            default_filter: concat!("BM_Combined_PQCred_", $tag, "_Cft$"),
            test_name: concat!("circuits/tests/pq/credential/", $program),
            bin_env: &["LONGFELLOW_PQ_CREDENTIAL_BENCH_BIN"],
            sign: None,
        };
        /// The presentation without CFT.
        pub const NO_CFT: Bench = Bench {
            backend: concat!(
                "Longfellow - ",
                $program,
                " (PQ credential without CFT: ",
                $name,
                " issuer and hardware-key signatures)"
            ),
            variant: concat!("pq_prove_verify_no_cft_", $variant),
            default_filter: concat!("BM_Combined_PQCred_", $tag, "_NoCft$"),
            test_name: concat!("circuits/tests/pq/credential/", $program),
            bin_env: &["LONGFELLOW_PQ_CREDENTIAL_BENCH_BIN"],
            sign: None,
        };
    };
}

#[cfg(all(not(feature = "slh-dsa"), not(feature = "level-5")))]
scheme!("ML-DSA-65", "MLDSA", "ml_dsa65", "pq_credential_test");
#[cfg(all(not(feature = "slh-dsa"), feature = "level-5"))]
scheme!("ML-DSA-87", "MLDSA", "ml_dsa87", "pq_credential_5_test");
#[cfg(all(
    feature = "slh-dsa",
    not(feature = "slh-dsa-f"),
    not(feature = "level-5")
))]
scheme!(
    "SLH-DSA-SHAKE-192s",
    "SLHs",
    "slh_dsa_shake_192s",
    "pq_credential_test"
);
#[cfg(all(feature = "slh-dsa", not(feature = "slh-dsa-f"), feature = "level-5"))]
scheme!(
    "SLH-DSA-SHAKE-256s",
    "SLHs",
    "slh_dsa_shake_256s",
    "pq_credential_5_test"
);
#[cfg(all(feature = "slh-dsa-f", not(feature = "level-5")))]
scheme!(
    "SLH-DSA-SHAKE-192f",
    "SLHf",
    "slh_dsa_shake_192f",
    "pq_credential_test"
);
#[cfg(all(feature = "slh-dsa-f", feature = "level-5"))]
scheme!(
    "SLH-DSA-SHAKE-256f",
    "SLHf",
    "slh_dsa_shake_256f",
    "pq_credential_5_test"
);

#[cfg(test)]
mod tests {
    // gbench::rollup_combined keeps only the rows named "Combined".
    #[test]
    fn filters_select_combined_rows() {
        assert!(super::CFT.default_filter.starts_with("BM_Combined_"));
        assert!(super::NO_CFT.default_filter.starts_with("BM_Combined_"));
    }
}
