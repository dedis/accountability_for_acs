# revocation (CFT anonymity revocation)

CFT revocation throughput: decrypt every CFT, or link CFTs to pseudonyms and
decrypt only the recurring ones, plus an MP-SPDZ plaintext-equivalence sweep.

- **Classical build** (`--no-default-features`): the CFT is ElGamal over
  Baby Jubjub and C4 is EdDSA-Poseidon (`src/cft.rs`, `src/c4.rs`, the
  shared `babyjub` crate), so its tags are the ones the zk-friendly
  `prove_verify.circom` accepts.
- **Post-quantum build** (`pq`, default; `src/lwe_cft.rs`, the shared `pqc`
  crate): the CFT is the Module-LWE encryption of `ID || r2` under a key the
  police, the judge and the NGO share additively (`pqc::lwe`), with
  `ID = SHAKE256(pk_user, 64 bytes)`, as the post-quantum credential proof of
  the standard stack. Each authority commits to its key contribution before
  any is revealed. `C4 = Sign_user(SHAKE256(t || r2))`, with `t` the event
  tag of the request, is a private input of the proof: ML-DSA and SLH-DSA
  signatures show their public key, so a public C4 would identify the user.
  The proof also binds the public `h = SHAKE256(ID || r2)` to the encrypted
  message. Every authority verifies the stored proof before an opening; after
  it, the opened `ID || r2` must hash to `h`, else an authority changed its
  decryption share, and the honest authorities stop all openings under the
  key. Each MPC run opens one CFT, checked before the next, and no
  ciphertext is opened twice (`OpeningLog`, kept with the key; in a
  deployment, on each authority's node, on disk). A ciphertext a user shows
  again is opened once; that opening names the ID. This crate has no proof:
  it checks `h` and
  that the opened ID is registered. The shares can be
  refreshed without changing the public key or any stored CFT
  (`Authorities::refresh`). Each authority computes its decryption share; the
  MPC adds them and reveals only `ID || r2` (`mpc/lwe_decrypt.mpc`).
  Link-then-decrypt and the plaintext-equivalence test need ElGamal and stop
  with an error.

The signature is chosen at compile time (`pqc::sig`): ML-DSA-65 by default,
ML-DSA-87 with `level-5`, SLH-DSA-SHAKE-192s with `slh-dsa`,
SLH-DSA-SHAKE-256s with both, and the fast SLH-DSA variants (192f, 256f) with
`slh-dsa-f` in place of `slh-dsa` (`tools/build.py --algorithm
--nist-level` sets them); `level-5` also selects the category-5 Module-LWE
parameters and 64-byte digests. The s variants sign in about 1.1 s per CFT and
the f variants in about 0.1 s, so batch building with s is slow at large set
sizes.

## Setup

```bash
cargo build --release -p revocation
./target/release/revocation_verify_link      # optional: protocol sanity check
```

Direct and link decryption batches require at least two CFTs.

## Benchmarks

```bash
cargo run --release --bin revocation_direct_decrypt
cargo run --release --bin revocation_link_decrypt      # classical build only
cargo run --release --bin revocation_run_experiments   # both (direct only under pq)
cargo run --release --bin revocation_regenerate -- direct-decrypt   # rebuild summary/fit from *_runs.csv
```

In the post-quantum build, direct decryption times each authority's
decryption shares; the police phase also combines the three shares natively,
with the arithmetic of the MPC, and finds the registered key
(`revocation_lwe_mpc` times the MPC itself). This is a timing reference only:
K decryption shares of one authority give its key share, so in the protocol
they go only into the MPC.

The experiments write `{direct,link}-decrypt_{runs,summary,fit}.csv` to
`--out DIR` (default `.work/revocation/out/experiments/`);
`revocation_regenerate` reads and rewrites the folder given by `--dir` (same
default).

| Env | Default | Meaning |
|-----|---------|---------|
| `BENCH_OUT` | `.work/revocation/out/experiments` | CSV folder (`--out`) |
| `EXPERIMENT_SIZES` | `10,20,50,100,500,1000,2000,4000,8000` | CFT set sizes |
| `EXPERIMENT_RUNS` | `10` | Runs per (size × recurring %) cell |
| `EXPERIMENT_RECURRING_PCTS` | per benchmark | Recurring rates, in percent |
| `BENCH_WORK_DIR` | `.work` | Scratch root |

Short run:

```bash
EXPERIMENT_SIZES=100,500 EXPERIMENT_RUNS=2 cargo run --release --bin revocation_direct_decrypt
```

## MPC

MP-SPDZ is an install, not a download: build `shamir-party.x` in an MP-SPDZ
checkout (the recorded runs used v0.4.2), create the party certificates with
`Scripts/setup-ssl.sh 3`, and point `MP_SPDZ_PATH` at it. On macOS:

- Homebrew's `gmpxx.h` (GMP 6.3.0) makes clang warn under MP-SPDZ's
  `-Werror`; `CONFIG.mine` with `MY_CFLAGS = -Wno-deprecated-literal-operator`
  builds it.
- The AirPlay receiver holds port 5000, MP-SPDZ's default base port: set
  `MP_SPDZ_PORT` (for example 15000), which the drivers pass as `-pn`.

A run that takes longer than `MP_SPDZ_TIMEOUT_S` seconds (default 3600) is
stopped. A compiled program is reused only with the source it was compiled
from. With Shamir among three parties, any two parties can rebuild the
third's inputs: in the post-quantum opening, its decryption shares, and from
5 of them (7 at category 5) its key share. The key is then safe against one
corrupt authority, not two.

Post-quantum decryption (`pq` build): every run builds a batch and computes
the three authorities' decryption shares. Then, one CFT per MP-SPDZ run, it
gives the shares to `mpc/lwe_decrypt.mpc` as private inputs through the
parties' standard input (never the disk; no memory dump) and checks that
the three parties reveal the same message, that it hashes to the CFT's `h`
and names a registered ID, before the next CFT opens. As a benchmark, it
also compares the message with the native decryption, which needs all three
shares in one process. It appends a
row to `RESULTS_CSV` (default `.work/revocation/out/mpc/lwe_decrypt.csv`),
with times and counters summed over the CFTs. Sizes: `CFT_BENCH_NUMS`
(default `10`); runs per size: `CFT_BENCH_ITERS` (default 1).

```bash
MP_SPDZ_PATH=/path/to/mp-spdz MP_SPDZ_PORT=15000 CFT_BENCH_NUMS=10,100 \
  cargo run --release --bin revocation_lwe_mpc
```

Plaintext-equivalence sweep (classical build):

```bash
MP_SPDZ_PATH=/path/to/mp-spdz bash crates/revocation/mpc/run_sweep.sh
python3 crates/revocation/mpc/summarize.py .work/revocation/mpc-sweep_*/results.csv
```

| Env | Default | Meaning |
|-----|---------|---------|
| `MP_SPDZ_PATH` | — | MP-SPDZ install (**required**) |
| `MP_SPDZ_PORT` | MP-SPDZ's (5000) | Base port of the parties |
| `NUMS` | `10 20 50 100 200 500 1000` | CFT set sizes |
| `ITERATIONS` | `10` | Runs per size |
| `TAU` | `2` | Predicate threshold |
| `OUTDIR` | `.work/revocation/mpc-sweep_<timestamp>` | Raw sweep output |

`summarize.py` writes `mpc-decrypt_{runs,summary,fit}.csv` to its second
argument (default `.work/revocation/out/mpc/`).

| Path | Role |
|------|------|
| `src/` | CFTs (ElGamal, Module-LWE under `pq`), C4 binding, the experiment grid, MP-SPDZ driver, statistics, CSV |
| `src/bin/` | The benchmarks and tools |
| `mpc/` | The MP-SPDZ programs (plaintext-equivalence predicate, Module-LWE decryption), the sweep script and its summarizer |

## Docker

```bash
docker build -t revocation-bench-rs -f crates/revocation/Dockerfile .
docker run --rm --cpus=8 --memory=16g --memory-swap=16g \
  -v "$(pwd)/results/revocation/local:/out" revocation-bench-rs \
  bash -c './target/release/revocation_run_experiments --out /out'
```

## License

Code in this folder is under the workspace **MIT** license (`../../LICENSE`).
