#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

# set current working directory to script directory to run script from everywhere
cd "$(dirname "$0")"

# build trust-graph.wasm
marine build --release

# copy .wasm to artifacts
rm -f artifacts/*
mkdir -p artifacts
cp ../target/wasm32-wasi/release/trust-graph.wasm artifacts/

# download SQLite 3 to use in tests
curl -sS -L https://github.com/fluencelabs/sqlite/releases/download/sqlite-wasm-v0.18.1/sqlite3.wasm -o artifacts/sqlite3.wasm

# generate Aqua bindings
marine aqua artifacts/trust-graph.wasm -s TrustGraph -i trust-graph > ../aqua/trust-graph.aqua
