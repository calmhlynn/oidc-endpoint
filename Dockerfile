FROM rust:latest AS builder
WORKDIR /usr/src/app

COPY . .

RUN cargo build --release

FROM debian:buster-slim

RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY --from=builder /usr/src/app/target/release/openapi .

CMD ["./openapi"]
