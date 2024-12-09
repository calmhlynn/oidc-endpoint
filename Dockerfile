FROM rust:latest AS builder
WORKDIR /usr/src/app

COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apk --no-cache add libssl3
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/target/release/openapi .

CMD ["./openapi"]
