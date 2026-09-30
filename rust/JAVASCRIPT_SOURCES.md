# JavaScript sources

The user-written JavaScript in this repository: **32 files, 6 547 lines**, and
what each became in the Rust port.

Everything under `rust/third_party/longfellow-zk/` is excluded. That
vendored Google tree (Apache 2.0) holds 84 further `.js` files, all belonging to
its Hugo documentation site, and is a dependency rather than code under test.

To regenerate this list:

```bash
git ls-files '*.js' | grep -v '^rust/third_party/longfellow-zk/' | xargs wc -l
```

## `revocation/` — 15 files, 1 778 lines

| File                                     | Lines | Role                                         | Rust counterpart                         |
|------------------------------------------|------:|----------------------------------------------|------------------------------------------|
| `lib/crypto_babyjub.js` | 10 | Baby Jubjub subgroup order | `crates/babyjub/src/curve.rs` |
| `lib/babyjub_noble.js` | 40 | `@noble/curves` wrapper, `Base8` check | `crates/babyjub/src/curve.rs` |
| `lib/crypto_common.js` | 46 | `mod`, `modInv`, `randomScalarMod` | `crates/babyjub/src/curve.rs` (the scalar type) |
| `lib/poseidon_cjs.js` | 50 | `circomlibjs` Poseidon loader | `crates/babyjub/src/poseidon.rs` |
| `lib/c4_binding.js` | 85 | C4 tag sign and verify | `crates/revocation/src/c4.rs`, `crates/babyjub/src/eddsa.rs` |
| `lib/cft_bench_lib.js` | 297 | CFT batches, direct/link decrypt, OLS fit | `crates/revocation/src/cft.rs`, `crates/revocation/src/stats.rs` |
| `lib/run_experiment.js` | 289 | Grid driver, CSV writing | `crates/revocation/src/experiment.rs`, `crates/revocation/src/csv.rs` |
| `lib/run_experiments.js` | 36 | Runs both benchmarks | `crates/revocation/src/bin/revocation_run_experiments.rs` |
| `direct-decrypt/bench_direct_decrypt.js` | 9 | Entry point | `crates/revocation/src/bin/revocation_direct_decrypt.rs` |
| `link-decrypt/bench_link_decrypt.js` | 9 | Entry point | `crates/revocation/src/bin/revocation_link_decrypt.rs` |
| `link-decrypt/verify_link.js` | 54 | Protocol sanity check | `crates/revocation/src/bin/revocation_verify_link.rs` |
| `mpc/bench_mpc.js` | 15 | Entry point for the sweep | `crates/revocation/src/bin/revocation_mpc_sweep.rs` |
| `mpc/mpc_runner.js` | 151 | MP-SPDZ compile/run, stderr parsing | `crates/revocation/src/mpc_runner.rs` |
| `mpc/pet_mpc.js` | 396 | PET phase, predicate matrix, integrity check | `crates/revocation/src/bin/revocation_pet_mpc.rs` |
| `scripts/regenerate_from_runs.js` | 291 | Rebuilds summary and fit CSVs | `crates/revocation/src/bin/revocation_regenerate.rs` |

## `prove-verify/zk-friendly/` — 11 files, 2 813 lines

| File                                                       | Lines | Role                                                 | Rust counterpart                                           |
|------------------------------------------------------------|------:|------------------------------------------------------|------------------------------------------------------------|
| `lib/crypto_babyjub.js` | 10 | Subgroup order (duplicate of the above) | `crates/babyjub/src/curve.rs` |
| `lib/crypto_common.js` | 52 | The above plus `sha256Utf8ToField` | `crates/babyjub/src/curve.rs`, `crates/zk-friendly/src/hash.rs` |
| `lib/poseidon_merkle.js` | 69 | Poseidon leaves, root, proofs | `crates/zk-friendly/src/poseidon_merkle.rs` |
| `lib/zk_common.js` | 447 | circom / snarkjs / rapidsnark driver, macOS patching | `crates/zk-friendly/src/zk_common.rs` |
| `prove-verify/bench_prove_verify.js` | 423 | Credential model plus the CFT benchmark | `crates/zk-friendly/src/bin/zkfriendly_prove_verify.rs`, `crates/zk-friendly/src/credential.rs` |
| `prove-verify-no-cft/bench_prove_verify_no_cft.js` | 416 | No-CFT baseline | `crates/zk-friendly/src/bin/zkfriendly_prove_verify_no_cft.rs` |
| `prove-verify-revocation/bench_prove_verify_revocation.js` | 317 | Population scale sweep | `crates/zk-friendly/src/bin/zkfriendly_prove_verify_revocation.rs` |
| `prove-verify-revocation/lib/circom_codegen.js` | 185 | Per-scale circuit generator | `crates/zk-friendly/src/circom_codegen.rs` |
| `prove-verify-revocation/lib/revocation_tree.js` | 90 | Packed zero-leaf status-list tree | `crates/zk-friendly/src/revocation_tree.rs` |
| `merkle-vs-flat/bench_merkle_vs_flat.js` | 572 | Commitment sweep and its circuit generators | `crates/zk-friendly/src/bin/zkfriendly_merkle_vs_flat.rs` |
| `communication-costs/bench_communication_size.js` | 232 | Wire-size report | `crates/zk-friendly/src/bin/zkfriendly_communication_size.rs` |

The in-process `snarkjs.groth16.verify` call these benchmarks made has no file
of its own; it is replaced by `crates/zk-friendly/src/groth16.rs`.

## `prove-verify/standard/` — 6 files, 1 956 lines

| File                                                       | Lines | Role                          | Rust counterpart                                                                |
|------------------------------------------------------------|------:|-------------------------------|---------------------------------------------------------------------------------|
| `scripts/bench_gbench_common.js` | 137 | Google Benchmark JSON helpers | `crates/standard/src/gbench.rs`, `crates/standard/src/cli.rs`, `crates/standard/src/runner.rs`, `crates/standard/src/driver.rs` |
| `prove-verify/bench_prove_verify.js` | 424 | Longfellow CFT driver | `crates/standard/src/bin/standard_prove_verify.rs` |
| `prove-verify-no-cft/bench_prove_verify_no_cft.js` | 388 | No-CFT driver | `crates/standard/src/bin/standard_prove_verify_no_cft.rs` |
| `prove-verify-revocation/bench_prove_verify_revocation.js` | 248 | Population scale sweep | `crates/standard/src/bin/standard_prove_verify_revocation.rs` |
| `merkle-vs-flat/bench_merkle_vs_flat.js` | 625 | Commitment sweep | `crates/standard/src/bin/standard_merkle_vs_flat.rs` |
| `communication-costs/bench_communication_size.js` | 134 | Runs the C++ measure scripts | `crates/standard/src/bin/standard_communication_size.rs` |

## Duplication in the original

Two patterns account for a large share of the 6 547 lines:

- `lib/crypto_babyjub.js` and `lib/crypto_common.js` are duplicated between
  `revocation/` and `prove-verify/zk-friendly/`, because each stack is a
  standalone npm package.
- The two `prove-verify/standard/` presentation drivers, 812 lines together,
  differ in three strings: the binary name, the default filter and the label.
  `crates/standard/src/driver.rs` holds that shared body once.
