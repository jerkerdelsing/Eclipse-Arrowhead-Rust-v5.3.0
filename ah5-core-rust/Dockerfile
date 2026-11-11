# Build context is the workspace root: docker build -f ah5-core-rust/Dockerfile .
# SOS-16 (2026-11-10): Rust 1.99 on Debian 13; the runtime moved from Debian 12, whose zlib1g has a CRITICAL
# vulnerability (CVE-2023-45853) that Debian 12 does not fix.
FROM rust:1.99-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p arrowhead-core-rust --bin arrowhead-core \
    && cp /src/target/release/arrowhead-core /arrowhead-core

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
COPY --from=build /arrowhead-core /usr/local/bin/arrowhead-core
ENTRYPOINT ["/usr/local/bin/arrowhead-core"]
