#!/usr/bin/env bash

# Build a static version of exchange-server using Docker + Alpine

# First, build the image
docker build -t exchange-server -f Dockerfile --platform linux/amd64 .

# Second, start a container in the background
docker run -d --name exchange-server --platform linux/amd64 exchange-server

# Copy the resulting binary from the container to host
mkdir -p build
docker cp exchange-server:/exchange-server/target/release/exchange-server ./build

# Remove the container
docker rm exchange-server