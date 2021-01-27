#!/bin/bash

fce build
mv target/wasm32-wasi/debug/trust-graph.wasm artifacts/
RUST_LOG="info" fce-repl Config.toml
