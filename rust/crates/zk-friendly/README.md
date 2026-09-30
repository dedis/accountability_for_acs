# zk-friendly (Circom / Groth16)

Age-check presentation benchmarks: circom witness + rapidsnark prove + native
Groth16 verify.

## Setup

Needs `circom`, rapidsnark `prover` and the `snarkjs` CLI on `PATH` (or see the
Docker image), plus the pinned downloads:

```bash
cd rust
python3 tools/fetch.py            # .work/downloads/{ppot_0080_19.ptau,circomlib/}
cargo build --release -p zk-friendly
```

`snarkjs` is used only for the one-off Groth16 setup (`groth16 setup`,
`zkey export verificationkey`). Proving is rapidsnark; verification is this crate.

## Benchmarks

```bash
cargo run --release --bin zkfriendly_prove_verify             # age-check + CFT
cargo run --release --bin zkfriendly_prove_verify_no_cft      # same, no CFT
cargo run --release --bin zkfriendly_prove_verify_revocation  # + non-revocation claim (2^12…2^24)
cargo run --release --bin zkfriendly_merkle_vs_flat           # attribute-commitment sweep
cargo run --release --bin zkfriendly_communication_size       # wire size
```

Each writes `summary.json` to `--out DIR` (default
`.work/zk-friendly/out/<benchmark>/`). Every binary takes `--help`, and each
option also reads its environment variable:

| Env | Flag | Default | Meaning |
|-----|------|---------|---------|
| `BENCH_OUT` | `--out` | `.work/zk-friendly/out/<benchmark>` | Output directory |
| `BENCH_N` | `--n` | `10` | Measured iterations |
| `BENCH_WARMUP` | `--warmup` | `1` | Discarded iterations |
| `BENCH_VERIFY_WARMUP` | `--verify-warmup` | `0` | Extra verify calls on the warm-up iteration |
| `REVOC_LOG2_LIST` / `REVOC_LOG2` | `--revoc-log2` | `12,16,20,24` | Revocation population scales; `REVOC_LOG2_LIST` takes precedence |
| `REVOC_BITS_PER_LEAF` | `--bits-per-leaf` | `253` | Status-list bits per leaf |
| `REVOC_SLOT` | `--revoc-slot` | `14` | Attribute slot holding the revocation index |
| `TOTAL_ATTRS` | `--totals` | `8,16,32,64` | merkle-vs-flat: credential sizes \(n\), powers of two ≥ 2 |
| `USED_ATTRS` | `--used` | `1,2,4,8,16` | merkle-vs-flat: disclosed counts \(k\) (skipped when \(k>n\)) |
| `KEEP_ARTIFACTS` | `--keep-artifacts` | off | Keep per-iteration inputs, witnesses and proofs |
| `CLEAN` | `--clean` | off | merkle-vs-flat: drop its generated circuits first |
| `CIRCOM_BIN` / `CIRCOM` | — | `circom` | circom binary |
| `RAPIDSNARK_BIN` | — | `prover` | rapidsnark binary |
| `SNARKJS_BIN` | — | `snarkjs` | snarkjs CLI |
| `CIRCOM_LIB_PATH` | — | `.work/downloads` | circom `-l` root holding `circomlib/` |
| `BENCH_WORK_DIR` | — | `rust/.work` | Scratch root for everything below |

Boolean options accept `1`/`0` and `true`/`false`.

| Path | Role |
|------|------|
| `circuits/` | Hand-written circuits; also a circom include root |
| `src/` | Credential model, Groth16 verifier, circom/snarkjs/rapidsnark driver, circuit generator |
| `src/bin/` | The five benchmarks |
| `tests/fixtures/` | Snapshot of the generated revocation circuits |
| `.work/zk-friendly/generated/<circuit>/` | Generated circuits, R1CS, keys, witness generators (cached by mtime) |
| `.work/zk-friendly/artifacts/<benchmark>/` | Per-iteration files, deleted unless `--keep-artifacts` |

To start over, delete `rust/.work/zk-friendly/`.

## Docker

```bash
cd rust
python3 tools/fetch.py
docker build -t zk-friendly-bench-rs -f crates/zk-friendly/Dockerfile .
docker run --rm --cpus=2 --memory=16g --memory-swap=16g zk-friendly-bench-rs \
  bash -c './target/release/zkfriendly_prove_verify --out /tmp/out && cat /tmp/out/summary.json'
```

`--cpus` is a CPU-time quota: rapidsnark still sees every core and is
throttled, so `prove` depends strongly on it (see `rust/results/README.md`).

## Timing boundaries

- **`witness`**: in the presentation benchmarks it includes input preparation,
  signing and writing `input.json`, plus the external witness calculator. The
  Merkle-versus-flat sweep prepares inputs before starting that timer.
- **`prove`**: rapidsnark alone.
- **`verify`**: the verification key is parsed once, with `e(α, β)`; the timed
  region is the public-input MSM and the pairing equation. The presentation
  benchmarks parse and validate the proof and public inputs before the timer;
  the Merkle-versus-flat sweep includes that work.

## License

Code in this folder is under the workspace **MIT** license (`../../../LICENSE`).
