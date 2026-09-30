pragma circom 2.0.0;

include "prove_verify_template.circom";

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
    vuClaimName
]} = ProveVerify();
