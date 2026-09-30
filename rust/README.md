# Benchmarks (Rust workspace)

Three benchmark stacks for the accountable credential presentation, one Cargo
workspace:

```
rust/
├── Cargo.toml  Cargo.lock      workspace: members, shared dependency versions, one lock
├── third_party.toml            pinned downloads (URL + SHA-256), fetched by tools/fetch.py
├── crates/
│   ├── bench-core/             paths, the --out flag, timing, statistics, summary JSON (no crypto)
│   ├── babyjub/                Baby Jubjub, Poseidon, EdDSA-Poseidon (circomlib parameters)
│   ├── revocation/             CFT anonymity revocation (native + MP-SPDZ)
│   ├── zk-friendly/            Circom / Groth16 presentation proofs
│   └── standard/               Longfellow (P-256 + SHA-256) presentation proofs
├── third_party/longfellow-zk/  vendored Longfellow (Apache 2.0, Google LLC)
├── tools/                      benchmark.py, plot*.py, fetch.py
├── results/<stack>/<env>/      committed results; plots in results/<stack>/plots/
└── .work/                      gitignored: downloads, generated circuits, builds, per-iteration files, logs
```

`revocation` and `zk-friendly` depend on `babyjub` and `bench-core`;
`standard` depends on `bench-core` only. No stack depends on another.

## Quick start

```bash
cd rust
cargo build --release && cargo test --release   # Rust 1.89 or newer
python3 tools/fetch.py                           # ptau + circomlib into .work/downloads/
python3 tools/benchmark.py                       # every benchmark in Docker, then the plots
```

`tools/benchmark.py --help` lists its options (`--only`, `--cpus`,
`--cpus-full`, `--memory`, `--skip-build`). Each crate's README covers running
its benchmarks directly.

## Conventions

- **Binaries** are named `<stack>_<benchmark>`, e.g. `zkfriendly_prove_verify`.
- **Outputs**: every benchmark takes `--out DIR` (env `BENCH_OUT`) and writes
  `DIR/summary.json` (the revocation experiments write their CSVs there). The
  default is `.work/<stack>/out/<benchmark>/`.
- **Scratch space**: everything a run creates lives under `.work/` (move it with
  `BENCH_WORK_DIR`). Deleting it only costs rebuilds and re-downloads.
- **Results**: `results/<stack>/<env>/<benchmark>.json`, with env `server` and
  `mobile` (recorded), `local-<N>cpu` (written by `tools/benchmark.py`),
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

Original code here is under the workspace **MIT** license (`../LICENSE`).
