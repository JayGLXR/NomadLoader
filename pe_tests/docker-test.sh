#!/bin/bash
set -e

echo "Building Docker image for testing..."
docker build -t pe-tests -f - . << EOF
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:\${PATH}"

# Create workspace
WORKDIR /app
EOF

echo "Creating container..."
docker create --name pe-test-container pe-tests
docker cp . pe-test-container:/app/
docker start -a pe-test-container

echo "Running tests..."
docker exec pe-test-container sh -c "cd /app && cargo test && cargo run"

echo "Cleaning up..."
docker rm -f pe-test-container

echo "Tests completed."