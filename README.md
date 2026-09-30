# Frontdoors, Not Backdoors: Accountable Anonymity for National Digital Identity

Companion code for the paper **"Frontdoors, Not Backdoors: Accountable Anonymity
for National Digital Identity"**. This repository contains the benchmarks
reported in the paper.

## Layout

- [`prove-verify/`](prove-verify/) — proof **generation** and **verification**
  benchmarks (zk-friendly Circom/Groth16 backend and Longfellow C++ backend,
  both with a CFT, a no-CFT, and a CFT + non-revocation proof variant).
- [`revocation/`](revocation/) — **anonymity revocation** benchmarks
  (direct decrypt, link decrypt, and MP-SPDZ-based MPC decrypt).
- [`rust/`](rust/) — both suites as one Rust workspace (`crates/`, `results/`, `tools/`).

See the README inside each folder for build, run, and Docker instructions.

## License

Unless noted otherwise, original code in this tree is released under the
**MIT License** (see [`LICENSE`](LICENSE)).

Third-party components keep their own licenses. In particular, the vendored
Longfellow tree at `prove-verify/standard/longfellow-zk/` is **Apache License
2.0** (Copyright © Google LLC; see that directory’s `LICENSE`). Do not treat
Longfellow sources as MIT-licensed.
