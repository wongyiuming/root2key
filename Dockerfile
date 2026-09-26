FROM rust:1.90-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev libssh2-1-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml ./
RUN mkdir src && printf 'fn main() {}\n' > src/main.rs && cargo build --release && rm -rf src
COPY src ./src
RUN touch src/main.rs src/bootstrap.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 libssh2-1 ca-certificates && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 65532 root2key
COPY --from=build /src/target/release/root2key /usr/local/bin/root2key
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/root2key"]
