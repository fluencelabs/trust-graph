#!/usr/bin/env bash
set -euo pipefail

fce build

rm artifacts/trust-graph.wasm
mv -f target/wasm32-wasi/debug/trust-graph.wasm artifacts/
RUST_LOG="info" fce-repl Config.toml
