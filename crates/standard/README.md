# standard (Longfellow)

Google Benchmark timings for the age-check presentation (P-256 + SHA-256). The
C++ benchmark binaries come from the vendored `third_party/longfellow-zk`;
this crate drives them and turns their JSON report into summaries.

## Setup

```bash
cmake -S third_party/longfellow-zk/lib -B .work/standard/longfellow-build \
  -DCMAKE_BUILD_TYPE=Release
cmake --build .work/standard/longfellow-build -j 8 --target \
  prove_verify_test prove_verify_no_cft_test \
  attr_commitment_experiment_test prove_verify_revocation_test
cargo build --release -p standard
```

On macOS: `brew install googletest google-benchmark zstd`. On Debian/Ubuntu:
`apt install clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev`.

## Benchmarks

```bash
cargo run --release --bin standard_prove_verify
cargo run --release --bin standard_prove_verify_no_cft
cargo run --release --bin standard_prove_verify_revocation
cargo run --release --bin standard_merkle_vs_flat
cargo run --release --bin standard_communication_size
```

Each writes `summary.json` to `--out DIR` (default
`.work/standard/out/<benchmark>/`). Every binary takes `--help`, and each option
also reads its environment variable:

| Env | Flag | Default | Meaning |
|-----|------|---------|---------|
| `BENCH_OUT` | `--out` | `.work/standard/out/<benchmark>` | Output directory |
| `BENCH_N` / `BENCH_REPETITIONS` | `--repetitions` / `--n` | `10` | Outer samples; `BENCH_N` takes precedence |
| `BENCH_ITERATIONS` | `--iterations` | `1` | Inner iterations; `auto`/`0` = adaptive |
| `BENCH_MIN_TIME` | `--min_time` | `0.05s` | Google Benchmark `--benchmark_min_time` |
| `BENCH_FILTER` | `--filter` | per benchmark | Google Benchmark filter regex |
| `BENCH_METRIC` | `--metric` | `both` | `--verbose` timing column |
| `BENCH_WARMUP` | — | on | `0`/`false`/`no` skips the discarded repetition |
| `CLEAN` | `--clean` | off | Empty the output directory first |
| `REVOC_LOG2_LIST` / `REVOC_LOG2` | `--revoc-log2` | `12,16,20,24` | Revocation population scales; `REVOC_LOG2_LIST` takes precedence |
| `TOTAL_ATTRS` | `--total-attrs` / `--attr` | `8,16,32,64` | merkle-vs-flat: credential sizes \(n\) |
| `USED_ATTRS` | `--used-attrs` / `--used-attr` | `1,2,4,8,16` | merkle-vs-flat: disclosed counts \(k\) (skipped when \(k>n\)) |
| `LONGFELLOW_BUILD_DIR` | — | `.work/standard/longfellow-build` | Longfellow CMake build |
| `LONGFELLOW_*_BENCH_BIN` | `--bin` | build path | Benchmark binary |
| `BENCH_WORK_DIR` | — | `.work` | Scratch root |

Boolean options accept `1`/`0` and `true`/`false`. `--quiet` is accepted and
does nothing; quiet output is the default.

| Path | Role |
|------|------|
| `src/` | Google Benchmark runner and report parsing, the shared presentation driver |
| `src/bin/` | The five benchmarks |
| `measure/` | Proof-size programs (C++) and their build scripts, run by `standard_communication_size` |

The merkle-vs-flat sweep needs more than 7 GB of memory at \(n = 64\).

Longfellow's benchmark `main` returns the number of benchmarks it matched as its
exit code, so a non-zero code after a successful run is expected; the drivers
report it as a note.

## Docker

```bash
docker build -t standard-bench-rs -f crates/standard/Dockerfile .
docker run --rm --cpus=2 --memory=16g --memory-swap=16g standard-bench-rs \
  bash -c './target/release/standard_prove_verify --out /tmp/out && cat /tmp/out/summary.json'
```

## License

The benchmark harness here is under the workspace **MIT** license
(`../../LICENSE`). The vendored `third_party/longfellow-zk/` tree remains
**Apache 2.0** (Google LLC).
