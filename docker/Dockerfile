FROM rust:1.88-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY static ./static
RUN cargo build --release

FROM debian:bookworm-slim

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/rust-multi-tenant-auth-template /usr/local/bin/rust-multi-tenant-auth-template
COPY .env.example ./.env.example

EXPOSE 8000
CMD ["/usr/local/bin/rust-multi-tenant-auth-template"]
