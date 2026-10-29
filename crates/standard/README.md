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
  attr_commitment_experiment_test prove_verify_revocation_test \
  prove_verify_pq_test prove_verify_no_cft_pq_test \
  attr_commitment_experiment_pq_test prove_verify_revocation_pq_test \
  ml_dsa_65_zk_test ml_dsa_87_zk_test slh_dsa_zk_test slh_dsa_zk_5_test \
  pq_credential_test pq_credential_5_test
cargo build --release -p standard
```

`slh_dsa_zk_test` proves the level-3 sets (192s, 192f) and `slh_dsa_zk_5_test`
the level-5 sets (256s, 256f), built with 64-byte SHAKE256 digests.

The `pq` feature (on by default) runs the `*_pq_test` binaries, which use
SHAKE256 (48-byte output) in place of SHA-256 inside the circuits and for the
native witnesses (`third_party/longfellow-zk/lib/circuits/tests/ec/shake256_hash.h`,
compile definition `PROOFS_EC_SHAKE256`), and adds `standard_signature`. These
binaries and the signature benchmarks also use SHAKE256 in the proof system: Merkle
commitments, Fiat-Shamir transcript, circuit ID, and a SHAKE256 PRF in place of
AES-256 (`third_party/longfellow-zk/lib/util/crypto.h`, compile definition
`PROOFS_SHAKE256`). Each
benchmark binary also contains a test that the proof verifies and fails after a
change to a public input: run it without arguments. Without `pq`, only the
classical `*_test` targets are needed:

```bash
cargo build --release -p standard --no-default-features
```

On macOS: `brew install googletest google-benchmark zstd`. On Debian/Ubuntu:
`apt install clang cmake libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev`.

## Benchmarks

`standard_signature` proves the verification of the signature chosen at
compile time with `tools/build.py --algorithm --nist-level` (see the root
README; features `slh-dsa`, `slh-dsa-f`, `level-5`): ML-DSA-65 (default),
ML-DSA-87, or SLH-DSA-SHAKE-192s, 256s, 192f or 256f. Every proof
has the soundness of its NIST category (192 bits at level 3, 256 bits at
level 5). SLH-DSA needs 2.1 GB (192s), 4.5 GB (256s), 5.7 GB (192f) or
8.9 GB (256f) of memory. Its summary also has the native signing time of
the same scheme (`statsMs.sign`, `avgMs.sign`), measured with the C4 signer
of `pqc` (fips204 / fips205) once per repetition.

```bash
cargo run --release --bin standard_prove_verify
cargo run --release --bin standard_prove_verify_no_cft
cargo run --release --bin standard_prove_verify_revocation
cargo run --release --bin standard_merkle_vs_flat
cargo run --release --bin standard_communication_size
cargo run --release --bin standard_signature           # pq feature
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
| `PQ_CIRCUIT_CACHE` | — | `.work/standard/pq-circuits` | Compiled circuits of the post-quantum proofs: the warm-up stores them, the measured run loads them. Trusted, so the directory must belong to the user and not be writable by others (created with mode 0700) |
| `CLEAN` | `--clean` | off | Empty the output directory first |
| `REVOC_LOG2_LIST` / `REVOC_LOG2` | `--revoc-log2` | `12,16,20,24` | Revocation population scales; `REVOC_LOG2_LIST` takes precedence |
| `TOTAL_ATTRS` | `--total-attrs` / `--attr` | `8,16,32,64` | merkle-vs-flat: credential sizes \(n\) |
| `USED_ATTRS` | `--used-attrs` / `--used-attr` | `1,2,4,8,16` | merkle-vs-flat: disclosed counts \(k\) (skipped when \(k>n\)) |
| `LONGFELLOW_BUILD_DIR` | — | `.work/standard/longfellow-build` | Longfellow CMake build |
| `LONGFELLOW_HASH` | — | set by `standard_communication_size` | `measure/` scripts: `sha256` (classical targets) or `shake256` (`*_pq_test`) |
| `LONGFELLOW_*_BENCH_BIN` | `--bin` | build path | Benchmark binary |
| `BENCH_WORK_DIR` | — | `.work` | Scratch root |

Boolean options accept `1`/`0` and `true`/`false`. `--quiet` is accepted and
does nothing; quiet output is the default.

| Path | Role |
|------|------|
| `src/` | Google Benchmark runner and report parsing, the shared presentation driver |
| `src/bin/` | The six benchmarks (`standard_signature` needs the `pq` feature) |
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
