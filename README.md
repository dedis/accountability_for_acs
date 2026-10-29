# Frontdoors, Not Backdoors: Accountable Anonymity for National Digital Identity

Companion code for the paper **"Frontdoors, Not Backdoors: Accountable Anonymity
for National Digital Identity"**. This repository contains the benchmarks
reported in the paper, as one Cargo workspace.

## About this fork

This repository is a fork of the initial work at
[roxannecvl/accountability_for_acs](https://github.com/roxannecvl/accountability_for_acs).
It ports the benchmarks from Node.js to a Rust workspace and is the base for
migrating the construction to **post-quantum cryptography**.

## Layout

```
├── Cargo.toml  Cargo.lock      workspace: members, shared dependency versions, one lock
├── third_party.toml            pinned downloads (URL + SHA-256), fetched by tools/fetch.py
├── crates/
│   ├── bench-core/             paths, the --out flag, timing, statistics, summary JSON (no crypto)
│   ├── babyjub/                Baby Jubjub, Poseidon, EdDSA-Poseidon (circomlib parameters)
│   ├── pqc/                    SHAKE256, ML-DSA / SLH-DSA, threshold Module-LWE encryption
│   ├── revocation/             anonymity revocation: direct, link, and MP-SPDZ decrypt
│   ├── zk-friendly/            proof generation/verification: Circom / Groth16 (classical);
│   │                           post-quantum credential model
│   └── standard/               proof generation/verification: Longfellow (P-256 + SHA-256)
├── third_party/longfellow-zk/  vendored Longfellow (Apache 2.0, Google LLC), with experimental
│                               ML-DSA, SLH-DSA and credential proofs (lib/circuits/tests/pq/)
├── tools/                      benchmark.py, plot*.py, fetch.py
├── results/<stack>/<env>/      committed results; plots in results/<stack>/plots/
└── .work/                      gitignored: downloads, generated circuits, builds, per-iteration files, logs
```

The proof benchmarks (`zk-friendly`, `standard`) each come in three variants:
with a CFT, without a CFT, and with a CFT plus a non-revocation proof.
`revocation` and `zk-friendly` depend on `babyjub`, `pqc` and `bench-core`;
`standard` depends on `pqc` and `bench-core`. No stack depends on another.

## Quick start

```bash
cargo build --release && cargo test --release   # Rust 1.89 or newer
python3 tools/fetch.py                           # ptau + circomlib into .work/downloads/
python3 tools/benchmark.py                       # every benchmark in Docker, then the plots
```

The default build is post-quantum (`pq` feature of `standard`, `revocation`
and `zk-friendly`, primitives in `crates/pqc`):

- SHAKE256 replaces SHA-256 and Poseidon;
- ML-DSA or SLH-DSA (chosen at compile time) replaces EdDSA for the C4,
  issuer and hardware-key signatures, and `standard` adds
  `standard_signature`, a proof of that signature's verification;
- the CFT is threshold Module-LWE encryption in place of ElGamal: the police,
  the judge and the NGO share the key additively, refresh their shares without
  changing the public key or stored CFTs, and decrypt in MP-SPDZ.

Link-then-decrypt, the plaintext-equivalence test and the Circom/Groth16
benchmarks need ElGamal or pairings and stop with an error in this build.
`cargo build-classical` builds the classical version. `PQ_MIGRATION.md`
tracks the migration.

The post-quantum signature is chosen at compile time:

```bash
python3 tools/build.py --algorithm=slh-dsa-f --nist-level=5   # extra cargo args after --
```

| `--algorithm`      | `--nist-level=3` (default) | `--nist-level=5`   |
|--------------------|----------------------------|--------------------|
| `ml-dsa` (default) | ML-DSA-65                  | ML-DSA-87          |
| `slh-dsa-s`        | SLH-DSA-SHAKE-192s         | SLH-DSA-SHAKE-256s |
| `slh-dsa-f`        | SLH-DSA-SHAKE-192f         | SLH-DSA-SHAKE-256f |

`tools/build.py` runs `cargo build --release` with the features `pq`,
`slh-dsa`, `slh-dsa-f` and `level-5` of `revocation` and `standard`; `cargo
build --release` alone gives ML-DSA-65. `tools/benchmark.py` takes the same options.

The ML-DSA and SLH-DSA proofs are experimental code in
`third_party/longfellow-zk/lib/circuits/tests/pq`. Every proof has the
soundness of its NIST category: 192 bits at level 3 and 256 bits at level 5.
Measured on one Mac:

| Scheme             | Category | Field, queries, digest   | Soundness  | Signature | Sign     | Prove   | Verify | Proof    | Peak memory |
|--------------------|----------|--------------------------|------------|-----------|----------|---------|--------|----------|-------------|
| ML-DSA-65          | 3        | Fq^12, 274, 48 B         | 192.0 bits | 3,309 B   | 0.28 ms  | 2.06 s  | 0.71 s | 740 KB   | 2.0 GB      |
| ML-DSA-87          | 5        | Fq^12, 362, 64 B         | 256.5 bits | 4,627 B   | 0.30 ms  | 2.62 s  | 0.91 s | 944 KB   | 2.3 GB      |
| SLH-DSA-SHAKE-192s | 3        | GF(2^256), 281, 48 B     | 192.1 bits | 16,224 B  | 1,253 ms | 32.4 s  | 3.42 s | 3.07 MB  | 2.1 GB      |
| SLH-DSA-SHAKE-192f | 3        | GF(2^256), 281, 48 B     | 192.1 bits | 35,664 B  | 56 ms    | 97.9 s  | 10.5 s | 7.40 MB  | 5.7 GB      |
| SLH-DSA-SHAKE-256s | 5        | GF(2^384), 374, 64 B     | 256.4 bits | 29,792 B  | 1,092 ms | 83.2 s  | 8.27 s | 5.87 MB  | 4.5 GB      |
| SLH-DSA-SHAKE-256f | 5        | GF(2^384), 374, 64 B     | 256.4 bits | 49,856 B  | 115 ms   | 175.6 s | 18.5 s | 10.58 MB | 8.9 GB      |

- **Sign**: median native signing with the system's signer (`pqc::sig`); 201
  runs for ML-DSA, 9 for the s variants, 51 for the f variants. These numbers
  were measured on a 32-byte message; `standard_signature` now signs a message
  of the C4 size (`SHAKE256(t ‖ r2)`: 48 bytes, 64 at level 5). ML-DSA signing takes 0.1 to 1.2 ms because of its
  rejection sampling.
- **Prove, Verify, Proof, Peak memory**: the ZK proof of the signature's
  verification. ML-DSA: median of 5 runs. SLH-DSA: one run.
- The s variants sign 9.5 to 22 times slower than the f variants but prove
  2.1 to 3.0 times faster: the proof cost follows the number of hash calls in
  verification.

`lib/zk/zk_soundness.h` in each Longfellow tree computes the soundness bits.

`tools/benchmark.py --help` lists its options (`--only`, `--cpus`,
`--cpus-full`, `--memory`, `--skip-build`, `--classical`, `--signature`). Post-quantum
results go to `-pq` folders (`results/<stack>/local-<N>cpu-pq/`); `--classical`
writes to the folders without the suffix. Each crate's README covers running
its benchmarks directly.

## Conventions

- **Binaries** are named `<stack>_<benchmark>`, e.g. `zkfriendly_prove_verify`.
- **Outputs**: every benchmark takes `--out DIR` (env `BENCH_OUT`) and writes
  `DIR/summary.json` (the revocation experiments write their CSVs there). The
  default is `.work/<stack>/out/<benchmark>/`.
- **Scratch space**: everything a run creates lives under `.work/` (move it with
  `BENCH_WORK_DIR`). Deleting it only costs rebuilds and re-downloads.
- **Results**: `results/<stack>/<env>/<benchmark>.json`, with env `server` and
  `mobile` (recorded), `local-<N>cpu` and `local-<N>cpu-pq` (written by
  `tools/benchmark.py`),
  `sizes` (proof-size reports). See `results/README.md`.

## Comparing with the recorded results

The recorded `server`/`mobile` results come from the earlier Node.js harness.

- `standard` launches the same C++ binaries and reads their JSON, so its
  numbers compare directly.
- `zk-friendly` uses the same witness calculator and rapidsnark prover, but
  witness input preparation and the Groth16 verifier are now native: `witness`
  and `verify` are much faster for that reason, not because of the hardware.
- `revocation` measures native code instead of Node.js.

## License

Unless noted otherwise, original code in this tree is released under the
**MIT License** (see [`LICENSE`](LICENSE)).

Third-party components keep their own licenses. In particular, the vendored
Longfellow tree at `third_party/longfellow-zk/` is **Apache License 2.0**
(Copyright © Google LLC; see that directory's `LICENSE`). Do not treat
Longfellow sources as MIT-licensed.
