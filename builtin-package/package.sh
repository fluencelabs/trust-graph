#!/usr/bin/env bash
set -o pipefail -o nounset -o errexit

# set current working directory to script directory to run script from everywhere
cd "$(dirname "$0")"
PACKAGE_DIR="$(pwd)/../package"

(
    rm -rf $PACKAGE_DIR
    mkdir -p $PACKAGE_DIR
)

(
    echo "*** copy wasm files ***"
    cd ../service
    cp artifacts/*.wasm "$PACKAGE_DIR"
)

(
    echo "*** copy on_start script ***"
    cp on_start.json "$PACKAGE_DIR"
    cp on_start.air "$PACKAGE_DIR"
)

TRUST_GRAPH_CID=$(ipfs add -q --only-hash --cid-version=1 --chunker=size-262144 $PACKAGE_DIR/trust-graph.wasm)
SQLITE_CID=$(ipfs add -q --only-hash --cid-version=1 --chunker=size-262144 $PACKAGE_DIR/sqlite3.wasm)
mv $PACKAGE_DIR/trust-graph.wasm "$PACKAGE_DIR"/"$TRUST_GRAPH_CID".wasm
mv $PACKAGE_DIR/sqlite3.wasm "$PACKAGE_DIR"/"$SQLITE_CID".wasm
cp trust-graph_config.json "$PACKAGE_DIR"/"$TRUST_GRAPH_CID"_config.json
cp sqlite3_config.json "$PACKAGE_DIR"/"$SQLITE_CID"_config.json

# write blueprint.json
echo "{}" | jq --arg trust_graph_cid "$TRUST_GRAPH_CID" --arg sqlite_cid "$SQLITE_CID" '{"name": "trust-graph", "dependencies":[{"/":$sqlite_cid},{"/":$trust_graph_cid}]}' > "$PACKAGE_DIR/blueprint.json"

(
    echo "*** create builtin distribution package ***"
    cd ..

    if [[ "$OSTYPE" == "darwin"* ]]; then
        tar -czvf trust-graph.tar.gz -s '|package|trust-graph|' package
    else
        tar -czvf trust-graph.tar.gz --transform 's|package|trust-graph|' package
    fi
)

echo "*** done ***"
