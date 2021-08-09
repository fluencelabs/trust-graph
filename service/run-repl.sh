#!/usr/bin/env bash
set -euo pipefail

./build.sh
RUST_LOG="info" mrepl Config.toml
