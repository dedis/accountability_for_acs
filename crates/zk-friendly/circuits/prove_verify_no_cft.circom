pragma circom 2.0.0;

include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Variant of `full_credential_proof_zk_friendly_flat32` with **no CFT claims**:
// - no ID attribute binding (slots 0,1 are not used / not disclosed)
// - no ElGamal-style relations and no outputs `c1,c2,c3,c4`
// - still proves: issuer signature on the flat 32-slot Poseidon fold, timestamp checks,
//   and hardware signature on public message `m`.
//
// 32 attributes, 5 disclosed (indices 4,5,6,14,15). Flat Poseidon fold over
// (claimName, claimValue) for every slot (names from labels in the bench). Public
// *ClaimName for the 5 used slots; credentialHash is internal (not in main.public).

template ProveVerifyNoCft() {
    var NUM_ATTRS = 32;
    var TS_BITS = 43;

    signal input issuerPubKey[2];
    signal input m;
    signal input now;
    signal input maxBirthDate;

    signal input bdClaimName;
    signal input vfClaimName;
    signal input vuClaimName;
    signal input hwPkXClaimName;
    signal input hwPkYClaimName;

    // 6 public inputs constrained to 0. Without these, snarkjs/ffjavascript
    // picks a 1-bit Pippenger window for the verifier MSM (because
    // publicSignals.length < 16), which adds ~1 ms of JS<->WASM dispatch
    // overhead per call and makes this variant look slower than the full one
    // despite doing less cryptographic work. Padding to 16 public signals
    // moves the MSM into the 2-bit window class.
    signal input pad0;
    signal input pad1;
    signal input pad2;
    signal input pad3;
    signal input pad4;
    signal input pad5;
    pad0 === 0;
    pad1 === 0;
    pad2 === 0;
    pad3 === 0;
    pad4 === 0;
    pad5 === 0;

    signal input claimNames[NUM_ATTRS];
    signal input claimValues[NUM_ATTRS];

    signal input birthDate;
    signal input validFrom;
    signal input validUntil;
    signal input hwPk[2];

    signal input sig_R[2];
    signal input sig_S;
    signal input hwSig_R[2];
    signal input hwSig_S;

    // Flat commitment: fold all 32 (name, value) pairs.
    signal acc[NUM_ATTRS + 1];
    acc[0] <== 0;
    component mix[NUM_ATTRS];
    for (var i = 0; i < NUM_ATTRS; i++) {
        mix[i] = Poseidon(3);
        mix[i].inputs[0] <== acc[i];
        mix[i].inputs[1] <== claimNames[i];
        mix[i].inputs[2] <== claimValues[i];
        acc[i + 1] <== mix[i].out;
    }
    signal credentialHash <== acc[NUM_ATTRS];

    // Bind the 5 disclosed attributes to their slots.
    bdClaimName === claimNames[4];
    vfClaimName === claimNames[5];
    vuClaimName === claimNames[6];
    hwPkXClaimName === claimNames[14];
    hwPkYClaimName === claimNames[15];

    birthDate === claimValues[4];
    validFrom === claimValues[5];
    validUntil === claimValues[6];
    hwPk[0] === claimValues[14];
    hwPk[1] === claimValues[15];

    component issuerSigVerifier = EdDSAPoseidonVerifier();
    issuerSigVerifier.enabled <== 1;
    issuerSigVerifier.Ax <== issuerPubKey[0];
    issuerSigVerifier.Ay <== issuerPubKey[1];
    issuerSigVerifier.R8x <== sig_R[0];
    issuerSigVerifier.R8y <== sig_R[1];
    issuerSigVerifier.S <== sig_S;
    issuerSigVerifier.M <== credentialHash;

    component ageCheck = LessThan(TS_BITS);
    ageCheck.in[0] <== birthDate;
    ageCheck.in[1] <== maxBirthDate + 1;
    ageCheck.out === 1;

    component validFromCheck = LessThan(TS_BITS);
    validFromCheck.in[0] <== validFrom;
    validFromCheck.in[1] <== now + 1;
    validFromCheck.out === 1;

    component validUntilCheck = LessThan(TS_BITS);
    validUntilCheck.in[0] <== now;
    validUntilCheck.in[1] <== validUntil + 1;
    validUntilCheck.out === 1;

    component hwSigVerifier = EdDSAPoseidonVerifier();
    hwSigVerifier.enabled <== 1;
    hwSigVerifier.Ax <== hwPk[0];
    hwSigVerifier.Ay <== hwPk[1];
    hwSigVerifier.R8x <== hwSig_R[0];
    hwSigVerifier.R8y <== hwSig_R[1];
    hwSigVerifier.S <== hwSig_S;
    hwSigVerifier.M <== m;
}

component main {public [
    issuerPubKey,
    m,
    now,
    maxBirthDate,
    bdClaimName,
    vfClaimName,
    vuClaimName,
    hwPkXClaimName,
    hwPkYClaimName,
    pad0,
    pad1,
    pad2,
    pad3,
    pad4,
    pad5
]} = ProveVerifyNoCft();

