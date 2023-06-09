#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

# set current working directory to script directory to run script from everywhere
cd "$(dirname "$0")"

./service/build.sh

TARGET="distro/trust-graph-service/"

mkdir -p "$TARGET"
cp -v ./distro/on_start.json service/artifacts/trust-graph.wasm service/artifacts/sqlite3.wasm service/Config.toml "$TARGET"

cd distro
cargo build
