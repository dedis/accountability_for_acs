pragma circom 2.0.0;

include "prove_verify_template.circom";
include "revocation_merkle.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

template ProveVerifyRevocation() {
    var DEPTH = 5;
    var BITS = 253;
    var REVOC_SLOT = 14;

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
    for (var a = 0; a < 32; a++) {
        pv.claimNames[a] <== claimNames[a];
        pv.claimValues[a] <== claimValues[a];
    }
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
    for (var c = 0; c < 2; c++) {
        c1[c] <== pv.c1[c];
        c2[c] <== pv.c2[c];
        c3[c] <== pv.c3[c];
        c4_R[c] <== pv.c4_R[c];
    }
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
    for (var i = 0; i < DEPTH; i++) {
        path.pathElements[i] <== pathElements[i];
        path.pathIndices[i] <== pathIndices[i];
    }

    component leafBits = Num2Bits(BITS);
    leafBits.in <== leafValue;

    component eq[BITS];
    signal acc[BITS + 1];
    acc[0] <== 0;
    for (var j = 0; j < BITS; j++) {
        eq[j] = IsEqual();
        eq[j].in[0] <== bitIndex;
        eq[j].in[1] <== j;
        acc[j + 1] <== acc[j] + eq[j].out * leafBits.out[j];
    }
    acc[BITS] === 0;
}

component main {public [
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
]} = ProveVerifyRevocation();
