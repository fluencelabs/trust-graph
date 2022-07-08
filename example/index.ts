/*
 * Copyright 2021 Fluence Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { trusted_computation } from "./generated/computation";
import * as tg from "./generated/export";
import { Fluence, FluencePeer, KeyPair } from "@fluencelabs/fluence";
import { krasnodar, Node, testNet, stage } from "@fluencelabs/fluence-network-environment";
import assert from "assert";
const bs58 = require('bs58');

let local: Node[] = [
    {
        peerId: "12D3KooWHBG9oaVx4i3vi6c1rSBUm7MLBmyGmmbHoZ23pmjDCnvK",
        multiaddr:
            "/ip4/127.0.0.1/tcp/9990/ws/p2p/12D3KooWHBG9oaVx4i3vi6c1rSBUm7MLBmyGmmbHoZ23pmjDCnvK",
    },
    {
        peerId: "12D3KooWRABanQHUn28dxavN9ZS1zZghqoZVAYtFpoN7FdtoGTFv",
        multiaddr:
            "/ip4/127.0.0.1/tcp/9991/ws/p2p/12D3KooWRABanQHUn28dxavN9ZS1zZghqoZVAYtFpoN7FdtoGTFv",
    },
    {
        peerId: "12D3KooWFpQ7LHxcC9FEBUh3k4nSCC12jBhijJv3gJbi7wsNYzJ5",
        multiaddr:
            "/ip4/127.0.0.1/tcp/9992/ws/p2p/12D3KooWFpQ7LHxcC9FEBUh3k4nSCC12jBhijJv3gJbi7wsNYzJ5",
    },
];

async function revoke_all(relay: string, revoked_by: string, nodes: Node[]) {
    for (var node of nodes) {
        let error = await tg.revoke(relay, revoked_by, node.peerId);
        if (error !== null) {
            console.log(error)
        }
    }
}

async function add_new_trust_checked(relay: string, issuer: string, issued_for_peer_id: string, expires_at_sec: number) {
    let error = await tg.add_trust(relay, issuer, issued_for_peer_id, expires_at_sec);
    if (error !== null) {
        console.error("%s", error);
    } else {
        console.log("Trust issued for %s successfully added", issued_for_peer_id)
    }
}

async function revoke_checked(relay: string, revoked_by: string, revoked_peer_id: string) {
    let error = await tg.revoke(relay, revoked_by, revoked_peer_id);
    if (error !== null) {
        console.log("%s", error);
    } else {
        console.log("Trust issued for %s revoked", revoked_peer_id)
    }
}

async function exec_trusted_computation(node: string) {
    let [result, error] = await trusted_computation(node)

    if (result !== null) {
        console.log("📗 Trusted computation on node %s successful, result is %s", node, result)
    } else {
        console.log("📕 Trusted computation on node %s failed, error:", node, error)
    }
}

async function main(nodes: Node[]) {
    // example_secret_key.ed25519
    let sk = bs58.decode("E5ay3731i4HN8XjJozouV92RDMGAn3qSnb9dKSnujiWv");

    let builtins_keypair = await KeyPair.fromEd25519SK(sk);

    let relay = nodes[0];
    await Fluence.start({ connectTo: relay, KeyPair: builtins_keypair });
    console.log(
        "📗 created a fluence peer %s with relay %s",
        Fluence.getStatus().peerId,
        Fluence.getStatus().relayPeerId
    );
    let local_peer_id = Fluence.getStatus().peerId;
    assert(local_peer_id !== null);

    let current_time = await tg.timestamp_sec();
    let far_future = current_time + 9999999;

    // clear all trusts from our peer id on relay
    await revoke_all(relay.peerId, local_peer_id, nodes.slice(0, 3));

    // wait to be sure that last revocation will be older than future trusts at least on 1 second (because timestamp in secs)
    await new Promise(f => setTimeout(f, 1000));

    let nodeA = nodes[0].peerId
    let nodeB = nodes[1].peerId
    let nodeC = nodes[2].peerId

    console.log();
    // try to exec computation on every node, will fail
    await exec_trusted_computation(nodeA); // fail
    await exec_trusted_computation(nodeB); // fail
    await exec_trusted_computation(nodeC); // fail

    console.log();
    console.log("🌀 Issue trust to nodeB %s and nodeC: %s", nodeB, nodeC);
    await add_new_trust_checked(relay.peerId, local_peer_id, nodeB, far_future);
    await add_new_trust_checked(relay.peerId, local_peer_id, nodeC, far_future);

    console.log();
    await exec_trusted_computation(nodeA); // fail
    await exec_trusted_computation(nodeB); // success
    await exec_trusted_computation(nodeC); // success
    console.log();

    await new Promise(f => setTimeout(f, 1000));
    console.log("🚫 Revoke trust to nodeB");
    await revoke_checked(relay.peerId, local_peer_id, nodeB);

    console.log();
    await exec_trusted_computation(nodeA); // fail
    await exec_trusted_computation(nodeB); // fail
    await exec_trusted_computation(nodeC); // success
    return;
}

console.log("In this example we try to execute some trusted computations based on trusts");
let args = process.argv.slice(2);
var environment: Node[];
if (args.length >= 1 && args[0] == "local") {
  environment = local;
  console.log("📘 Will connect to local nodes");
} else {
  environment = testNet;
  console.log("📘 Will connect to testNet");
}

main(environment)
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
