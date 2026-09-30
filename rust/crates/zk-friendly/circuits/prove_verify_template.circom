pragma circom 2.0.0;

include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

// Shared presentation + CFT template (v2: C4 = EdDSA under IDu in WSCD).
template ProveVerify() {
    var NUM_ATTRS = 32;
    var TS_BITS = 43;

    signal output c1[2];
    signal output c2[2];
    signal output c3[2];
    signal output c4_R[2];
    signal output c4_S;

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

    signal input claimNames[NUM_ATTRS];
    signal input claimValues[NUM_ATTRS];

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

    var BASE8[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

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

    idxClaimName === claimNames[0];
    idyClaimName === claimNames[1];
    bdClaimName === claimNames[4];
    vfClaimName === claimNames[5];
    vuClaimName === claimNames[6];

    IDx === claimValues[0];
    IDy === claimValues[1];
    birthDate === claimValues[4];
    validFrom === claimValues[5];
    validUntil === claimValues[6];

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

    component r1N2B = Num2Bits(253);
    r1N2B.in <== randomVal1;
    signal r1Bits[253];
    for (var i = 0; i < 253; i++) {
        r1Bits[i] <== r1N2B.out[i];
    }

    component r1G = EscalarMulFix(253, BASE8);
    for (var i = 0; i < 253; i++) {
        r1G.e[i] <== r1Bits[i];
    }
    c1[0] <== r1G.out[0];
    c1[1] <== r1G.out[1];

    component r2N2B = Num2Bits(253);
    r2N2B.in <== randomVal2;
    signal r2Bits[253];
    for (var i = 0; i < 253; i++) {
        r2Bits[i] <== r2N2B.out[i];
    }

    component r2G = EscalarMulFix(253, BASE8);
    for (var i = 0; i < 253; i++) {
        r2G.e[i] <== r2Bits[i];
    }
    c2[0] <== r2G.out[0];
    c2[1] <== r2G.out[1];

    component r1Q = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        r1Q.e[i] <== r1Bits[i];
    }
    r1Q.p[0] <== elgamalPubKey[0];
    r1Q.p[1] <== elgamalPubKey[1];

    component enc = BabyAdd();
    enc.x1 <== IDx;
    enc.y1 <== IDy;
    enc.x2 <== r1Q.out[0];
    enc.y2 <== r1Q.out[1];
    c3[0] <== enc.xout;
    c3[1] <== enc.yout;

    component r2Q = EscalarMulAny(253);
    for (var i = 0; i < 253; i++) {
        r2Q.e[i] <== r2Bits[i];
    }
    r2Q.p[0] <== elgamalPubKey[0];
    r2Q.p[1] <== elgamalPubKey[1];

    component tagMsg = Poseidon(3);
    tagMsg.inputs[0] <== t;
    tagMsg.inputs[1] <== r2Q.out[0];
    tagMsg.inputs[2] <== r2Q.out[1];

    component c4SigVerifier = EdDSAPoseidonVerifier();
    c4SigVerifier.enabled <== 1;
    c4SigVerifier.Ax <== IDx;
    c4SigVerifier.Ay <== IDy;
    c4SigVerifier.R8x <== c4Sig_R[0];
    c4SigVerifier.R8y <== c4Sig_R[1];
    c4SigVerifier.S <== c4Sig_S;
    c4SigVerifier.M <== tagMsg.out;

    c4_R[0] <== c4Sig_R[0];
    c4_R[1] <== c4Sig_R[1];
    c4_S <== c4Sig_S;
}
