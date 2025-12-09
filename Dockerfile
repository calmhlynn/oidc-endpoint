FROM rust:1.91-bullseye AS builder
WORKDIR /usr/src/app

COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/target/release/api-gateway .

CMD ["./api-gateway"]
