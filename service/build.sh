#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

# set current working directory to script directory to run script from everywhere
cd "$(dirname "$0")"

# build trust-graph.wasm
cargo update
marine build --release

# copy .wasm to artifacts
rm -f artifacts/*
mkdir -p artifacts
cp ../target/wasm32-wasi/release/trust-graph.wasm artifacts/
