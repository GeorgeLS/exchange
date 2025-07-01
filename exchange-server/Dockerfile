FROM rust:alpine
RUN apk add --update build-base cmake # For compiling aws-lc-rs
RUN USER=root cargo new --bin exchange-server

WORKDIR /exchange-server

COPY ./Cargo.toml ./Cargo.toml
RUN cargo build --release
RUN rm src/*.rs ./target/release/deps/exchange_server*
ADD . ./
RUN cargo build --release
