# Build from the repository root:
#   docker build -t standard-bench-rs -f crates/standard/Dockerfile .
#
#   docker run --rm --cpus=2 --memory=16g --memory-swap=16g standard-bench-rs \
#     bash -c './target/release/standard_prove_verify --out /tmp/out \
#       && cat /tmp/out/summary.json'
#
# Binaries: standard_prove_verify | standard_prove_verify_no_cft
#         | standard_prove_verify_revocation | standard_merkle_vs_flat
#         | standard_communication_size | standard_signature (pq)
#         | standard_pq_prove_verify | standard_pq_prove_verify_no_cft (pq)
#
# Debian 13: OpenSSL 3.5, which signs with ML-DSA and SLH-DSA for the
# post-quantum credential proofs.
FROM rust:1-trixie

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
               prove_verify_pq_test prove_verify_no_cft_pq_test \
               attr_commitment_experiment_pq_test prove_verify_revocation_pq_test \
               ml_dsa_65_zk_test ml_dsa_87_zk_test

# The copy with the SLH-DSA proofs (standard_signature with slh-dsa) and
# the post-quantum credential proofs (standard_pq_prove_verify*).
COPY third_party/longfellow-zk-slh/lib/ ./third_party/longfellow-zk-slh/lib/
RUN cmake -S third_party/longfellow-zk-slh/lib -B .work/standard/longfellow-slh-build \
      -DCMAKE_BUILD_TYPE=Release \
 && cmake --build .work/standard/longfellow-slh-build -j"$(nproc)" \
      --target slh_dsa_zk_test slh_dsa_zk_5_test \
               pq_credential_test pq_credential_5_test

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
# CARGO_FEATURES: empty for the default post-quantum (pq) build with ML-DSA-65;
# --build-arg CARGO_FEATURES=--no-default-features builds the classical one;
# "--features level-5", "--features slh-dsa", "--features slh-dsa-f", each
# with ",level-5" for category 5, choose the signature of standard_signature
# and of the post-quantum credential proofs.
ARG CARGO_FEATURES=""
RUN cargo build --release --locked -p standard $CARGO_FEATURES \
 && cargo test --release --locked -p standard $CARGO_FEATURES

CMD ["bash"]
