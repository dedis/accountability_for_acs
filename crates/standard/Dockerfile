# Build from the repository root:
#   docker build -t standard-bench-rs -f crates/standard/Dockerfile .
#
#   docker run --rm --cpus=2 --memory=16g --memory-swap=16g standard-bench-rs \
#     bash -c './target/release/standard_prove_verify --out /tmp/out \
#       && cat /tmp/out/summary.json'
#
# Binaries: standard_prove_verify | standard_prove_verify_no_cft
#         | standard_prove_verify_revocation | standard_merkle_vs_flat
#         | standard_communication_size
#
FROM rust:1-bookworm

WORKDIR /bench

ENV DEBIAN_FRONTEND=noninteractive

# C++ toolchain + Google Test / Benchmark (same stack as the Longfellow README).
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates \
    clang cmake git make \
    libssl-dev libzstd-dev libgtest-dev libbenchmark-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

ENV CXX=clang++

# Longfellow builds into the default .work/standard/longfellow-build.
COPY third_party/longfellow-zk/lib/ ./third_party/longfellow-zk/lib/
RUN cmake -S third_party/longfellow-zk/lib -B .work/standard/longfellow-build \
      -DCMAKE_BUILD_TYPE=Release \
 && cmake --build .work/standard/longfellow-build -j"$(nproc)" \
      --target prove_verify_test prove_verify_no_cft_test \
               attr_commitment_experiment_test prove_verify_revocation_test \
               ml_dsa_65_zk_test

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release --locked -p standard && cargo test --release --locked -p standard

CMD ["bash"]
