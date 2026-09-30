# Build from the repository root:
#   docker build -t revocation-bench-rs -f crates/revocation/Dockerfile .
#
#   docker run --rm --cpus=8 --memory=16g --memory-swap=16g \
#     -v "$(pwd)/results/revocation/local:/out" revocation-bench-rs \
#     bash -c './target/release/revocation_run_experiments --out /out'
#
FROM rust:1-bookworm

WORKDIR /bench

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

RUN cargo build --release --locked -p revocation \
 && cargo test --release --locked -p revocation \
 && ./target/release/revocation_verify_link

CMD ["bash"]
