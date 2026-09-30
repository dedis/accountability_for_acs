//! Emits one `prove_verify_revocation_l<log2>.circom` per population scale.
//!
//! The Merkle depth and the bits-per-leaf are compile-time constants of the
//! circuit, so a scale sweep needs one circuit per scale. Its includes resolve
//! through the `circuits/` include root.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::revocation_tree::packed_merkle_depth;

/// What was generated for one scale.
pub struct Generated {
    pub merkle_depth: u32,
    pub path: PathBuf,
}

/// `prove_verify_revocation_l<log2>`, the circuit (and output folder) name.
pub fn circuit_name(revoc_log2: u32) -> String {
    format!("prove_verify_revocation_l{revoc_log2}")
}

fn source(depth: u32, bits_per_leaf: u32, revoc_slot: usize) -> String {
    format!(
        r#"pragma circom 2.0.0;

include "prove_verify_template.circom";
include "revocation_merkle.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template ProveVerifyRevocation() {{
    var DEPTH = {depth};
    var BITS = {bits_per_leaf};
    var REVOC_SLOT = {revoc_slot};

    signal input elgamalPubKey[2];
    signal input issuerPubKey[2];
    signal input t;
    signal input now;
    signal input maxBirthDate;
    signal input idxClaimName;
    signal input idyClaimName;
    signal input bdClaimName;
    signal input vfClaimName;
    signal input vuClaimName;
    signal input revClaimName;
    signal input revocationRoot;

    signal input claimNames[32];
    signal input claimValues[32];
    signal input IDx;
    signal input IDy;
    signal input birthDate;
    signal input validFrom;
    signal input validUntil;
    signal input sig_R[2];
    signal input sig_S;
    signal input c4Sig_R[2];
    signal input c4Sig_S;
    signal input randomVal1;
    signal input randomVal2;

    signal input leafIndex;
    signal input bitIndex;
    signal input leafValue;
    signal input pathElements[DEPTH];
    signal input pathIndices[DEPTH];

    component pv = ProveVerify();
    pv.elgamalPubKey <== elgamalPubKey;
    pv.issuerPubKey <== issuerPubKey;
    pv.t <== t;
    pv.now <== now;
    pv.maxBirthDate <== maxBirthDate;
    pv.idxClaimName <== idxClaimName;
    pv.idyClaimName <== idyClaimName;
    pv.bdClaimName <== bdClaimName;
    pv.vfClaimName <== vfClaimName;
    pv.vuClaimName <== vuClaimName;
    for (var a = 0; a < 32; a++) {{
        pv.claimNames[a] <== claimNames[a];
        pv.claimValues[a] <== claimValues[a];
    }}
    pv.IDx <== IDx;
    pv.IDy <== IDy;
    pv.birthDate <== birthDate;
    pv.validFrom <== validFrom;
    pv.validUntil <== validUntil;
    pv.sig_R[0] <== sig_R[0];
    pv.sig_R[1] <== sig_R[1];
    pv.sig_S <== sig_S;
    pv.c4Sig_R[0] <== c4Sig_R[0];
    pv.c4Sig_R[1] <== c4Sig_R[1];
    pv.c4Sig_S <== c4Sig_S;
    pv.randomVal1 <== randomVal1;
    pv.randomVal2 <== randomVal2;

    // Re-export CFT outputs (same as ProveVerify main) for the verifier wire.
    signal output c1[2];
    signal output c2[2];
    signal output c3[2];
    signal output c4_R[2];
    signal output c4_S;
    for (var c = 0; c < 2; c++) {{
        c1[c] <== pv.c1[c];
        c2[c] <== pv.c2[c];
        c3[c] <== pv.c3[c];
        c4_R[c] <== pv.c4_R[c];
    }}
    c4_S <== pv.c4_S;

    revClaimName === claimNames[REVOC_SLOT];

    signal credentialIndex <== claimValues[REVOC_SLOT];

    component bitBound = LessThan(8);
    bitBound.in[0] <== bitIndex;
    bitBound.in[1] <== BITS;
    bitBound.out === 1;

    signal packedOffset <== leafIndex * BITS;
    credentialIndex === packedOffset + bitIndex;

    component path = RevocationMerklePath(DEPTH);
    path.root <== revocationRoot;
    path.leaf <== leafValue;
    for (var i = 0; i < DEPTH; i++) {{
        path.pathElements[i] <== pathElements[i];
        path.pathIndices[i] <== pathIndices[i];
    }}

    component leafBits = Num2Bits(BITS);
    leafBits.in <== leafValue;

    component eq[BITS];
    signal acc[BITS + 1];
    acc[0] <== 0;
    for (var j = 0; j < BITS; j++) {{
        eq[j] = IsEqual();
        eq[j].in[0] <== bitIndex;
        eq[j].in[1] <== j;
        acc[j + 1] <== acc[j] + eq[j].out * leafBits.out[j];
    }}
    acc[BITS] === 0;
}}

component main {{public [
    elgamalPubKey,
    issuerPubKey,
    t,
    now,
    maxBirthDate,
    idxClaimName,
    idyClaimName,
    bdClaimName,
    vfClaimName,
    vuClaimName,
    revClaimName,
    revocationRoot
]}} = ProveVerifyRevocation();
"#
    )
}

/// Writes `dir/<circuit_name>.circom` for one scale, leaving the file untouched
/// when the content already matches (so the cached R1CS stays valid).
pub fn write_circuit(
    dir: &Path,
    revoc_log2: u32,
    bits_per_leaf: u32,
    revoc_slot: usize,
) -> Result<Generated> {
    let merkle_depth = packed_merkle_depth(1u64 << revoc_log2, bits_per_leaf);
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join(format!("{}.circom", circuit_name(revoc_log2)));
    let content = source(merkle_depth, bits_per_leaf, revoc_slot);

    // Leave the file alone when it already matches, so a cached R1CS stays
    // newer than its source.
    if std::fs::read_to_string(&path).ok().as_deref() != Some(content.as_str()) {
        std::fs::write(&path, &content).with_context(|| format!("write {}", path.display()))?;
    }

    Ok(Generated { merkle_depth, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_carries_the_scale_constants() {
        let text = source(12, 253, 14);
        assert!(text.contains("var DEPTH = 12;"));
        assert!(text.contains("var BITS = 253;"));
        assert!(text.contains("var REVOC_SLOT = 14;"));
        assert!(text.contains("component main {public ["));
    }

    /// Snapshot of the generated circuits at the recorded scales; a change
    /// here changes the circuit the benchmark measures.
    #[test]
    fn reproduces_the_snapshot_circuits() {
        for (log2, depth) in [(12u32, 5u32), (16, 9), (20, 13), (24, 17)] {
            let expected = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures")
                    .join(format!("{}.circom", circuit_name(log2))),
            )
            .expect("checked-in circuit");
            assert_eq!(source(depth, 253, 14), expected, "scale 2^{log2}");
        }
    }

    #[test]
    fn writing_is_idempotent() {
        let dir = std::env::temp_dir().join("zk-friendly-codegen-test");
        std::fs::create_dir_all(&dir).unwrap();

        let first = write_circuit(&dir, 12, 253, 14).unwrap();
        assert_eq!(first.merkle_depth, 5);
        let before = std::fs::read_to_string(&first.path).unwrap();

        let second = write_circuit(&dir, 12, 253, 14).unwrap();
        let after = std::fs::read_to_string(&second.path).unwrap();
        assert_eq!(before, after);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
