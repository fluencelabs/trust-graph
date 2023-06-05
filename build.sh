#!/usr/bin/env bash
set -o errexit -o nounset -o pipefail

# set current working directory to script directory to run script from everywhere
cd "$(dirname "$0")"

./service/build.sh

mkdir -p ../distro/trust-graph-service
cp -v ./distro/on_start.json service/artifacts/trust-graph.wasm service/artifacts/sqlite3.wasm service/Config.toml ../distro/trust-graph-service/

cd distro
cargo build
