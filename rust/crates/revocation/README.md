# revocation (CFT anonymity revocation)

Baby Jubjub CFT revocation throughput: decrypt every CFT, or link CFTs to
pseudonyms and decrypt only the recurring ones, plus an MP-SPDZ
plaintext-equivalence sweep. The C4 binding uses the shared `babyjub` crate, so
its tags are the ones the zk-friendly `prove_verify.circom` accepts.

## Setup

```bash
cd rust
cargo build --release -p revocation
./target/release/revocation_verify_link      # optional: protocol sanity check
```

Direct and link decryption batches require at least two CFTs.

## Benchmarks

```bash
cargo run --release --bin revocation_direct_decrypt
cargo run --release --bin revocation_link_decrypt
cargo run --release --bin revocation_run_experiments   # both (direct then link)
cargo run --release --bin revocation_regenerate -- direct-decrypt   # rebuild summary/fit from *_runs.csv
```

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
| `BENCH_WORK_DIR` | `rust/.work` | Scratch root |

Short run:

```bash
EXPERIMENT_SIZES=100,500 EXPERIMENT_RUNS=2 cargo run --release --bin revocation_direct_decrypt
```

## MPC sweep

MP-SPDZ is an install, not a download: build `shamir-party.x` in an MP-SPDZ
checkout (the recorded runs used v0.4.2) and point `MP_SPDZ_PATH` at it.

```bash
MP_SPDZ_PATH=/path/to/mp-spdz bash crates/revocation/mpc/run_sweep.sh
python3 crates/revocation/mpc/summarize.py .work/revocation/mpc-sweep_*/results.csv
```

| Env | Default | Meaning |
|-----|---------|---------|
| `MP_SPDZ_PATH` | — | MP-SPDZ install (**required**) |
| `NUMS` | `10 20 50 100 200 500 1000` | CFT set sizes |
| `ITERATIONS` | `10` | Runs per size |
| `TAU` | `2` | Predicate threshold |
| `OUTDIR` | `.work/revocation/mpc-sweep_<timestamp>` | Raw sweep output |

`summarize.py` writes `mpc-decrypt_{runs,summary,fit}.csv` to its second
argument (default `.work/revocation/out/mpc/`).

| Path | Role |
|------|------|
| `src/` | CFTs, C4 binding, the experiment grid, MP-SPDZ driver, statistics, CSV |
| `src/bin/` | The benchmarks and tools |
| `mpc/` | The MP-SPDZ program, the sweep script and its summarizer |

## Docker

```bash
cd rust
docker build -t revocation-bench-rs -f crates/revocation/Dockerfile .
docker run --rm --cpus=8 --memory=16g --memory-swap=16g \
  -v "$(pwd)/results/revocation/local:/out" revocation-bench-rs \
  bash -c './target/release/revocation_run_experiments --out /out'
```

## License

Code in this folder is under the workspace **MIT** license (`../../../LICENSE`).
