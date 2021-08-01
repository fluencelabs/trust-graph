#!/usr/bin/env bash
set -euo pipefail

./build.sh
RUST_LOG="info" fce-repl Config.toml
