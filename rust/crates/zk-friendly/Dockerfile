# Build from rust/ (the workspace root; fetch the downloads first):
#   python3 tools/fetch.py
#   docker build -t zk-friendly-bench-rs -f crates/zk-friendly/Dockerfile .
#
#   docker run --rm --cpus=2 --memory=16g --memory-swap=16g zk-friendly-bench-rs \
#     bash -c './target/release/zkfriendly_prove_verify --out /tmp/out \
#       && cat /tmp/out/summary.json'
#
# Binaries: zkfriendly_prove_verify | zkfriendly_prove_verify_no_cft
#         | zkfriendly_prove_verify_revocation | zkfriendly_merkle_vs_flat
#         | zkfriendly_communication_size
#
# On Apple Silicon, Docker builds linux/arm64 natively and rapidsnark is compiled
# with ARM assembly (same class of optimizations as a phone wallet prover).
# On amd64, the x86_64 host build is used (also USE_ASM=ON by default).
FROM rust:1-bookworm

WORKDIR /bench

# System deps for circom + rapidsnark (see iden3/rapidsnark README)
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates curl git \
    build-essential cmake pkg-config m4 nasm \
    libgmp-dev libsodium-dev nlohmann-json3-dev \
    nodejs npm python3 \
 && rm -rf /var/lib/apt/lists/*

# snarkjs provides the Groth16 trusted setup CLI. Proving and verifying are
# native: rapidsnark proves, this crate verifies.
RUN npm install -g snarkjs@0.7.5

# Install circom (build from source)
RUN git clone --depth 1 https://github.com/iden3/circom.git /tmp/circom \
 && cd /tmp/circom \
 && cargo build --release \
 && install -m 0755 target/release/circom /usr/local/bin/circom \
 && rm -rf /tmp/circom

# Build rapidsnark (provides `prover`). Architecture-specific:
#   arm64  → ./build_gmp.sh aarch64 && make host_arm64  (ARM asm, USE_ASM=ON)
#   amd64  → ./build_gmp.sh host     && make host       (x86 asm, USE_ASM=ON)
# Fallback on unknown arch: host_noasm (portable C++, slower).
ARG TARGETARCH
RUN set -eux; \
  git clone --depth 1 https://github.com/iden3/rapidsnark.git /tmp/rapidsnark; \
  cd /tmp/rapidsnark; \
  git submodule update --init --recursive; \
  ARCH="${TARGETARCH:-$(uname -m)}"; \
  case "$ARCH" in \
    arm64|aarch64) \
      ./build_gmp.sh aarch64; \
      make host_arm64; \
      install -m 0755 package_arm64/bin/prover /usr/local/bin/prover; \
      ;; \
    amd64|x86_64) \
      ./build_gmp.sh host; \
      make host; \
      install -m 0755 package/bin/prover /usr/local/bin/prover; \
      ;; \
    *) \
      ./build_gmp.sh host_noasm; \
      make host_noasm; \
      install -m 0755 package_noasm/bin/prover /usr/local/bin/prover; \
      ;; \
  esac; \
  rm -rf /tmp/rapidsnark

# Build context: rust/. The ptau file and circomlib come from tools/fetch.py.
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
COPY .work/downloads/ ./.work/downloads/

RUN test -f .work/downloads/ppot_0080_19.ptau \
 && test -d .work/downloads/circomlib/circuits \
 && cargo build --release --locked -p zk-friendly \
 && cargo test --release --locked -p zk-friendly \
 && command -v circom \
 && command -v prover \
 && command -v snarkjs

ENV PATH="/bench/target/release:${PATH}"

CMD ["bash"]
