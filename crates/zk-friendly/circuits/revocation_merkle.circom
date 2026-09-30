pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";

// Poseidon(2) Merkle path: leaf is a single field element (bitmap leaf).
template RevocationMerklePath(depth) {
    signal input root;
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    component hashers[depth];
    component switchers[depth];
    signal currentHash[depth + 1];
    currentHash[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        switchers[i] = Switcher();
        switchers[i].sel <== pathIndices[i];
        switchers[i].L <== currentHash[i];
        switchers[i].R <== pathElements[i];

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== switchers[i].outL;
        hashers[i].inputs[1] <== switchers[i].outR;

        currentHash[i + 1] <== hashers[i].out;
    }

    root === currentHash[depth];
}
