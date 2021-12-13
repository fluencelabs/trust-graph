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

import * as tg from "./generated/export";
import { Fluence, KeyPair } from "@fluencelabs/fluence";
import { krasnodar, Node } from "@fluencelabs/fluence-network-environment";
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
];

async function is_fluence_peer(relay: string) {
   let result =  await tg.isFluencePeer(relay);

    if (result) {
        console.log("Current relay %s identified as Fluence Labs' peer", relay)
    } else {
        console.log("Current relay %s is not Fluence Labs' peer", relay)
    }

}

async function add_trust_helper(relay: string, issuer_kp: KeyPair, issuer_peer_id: string, issued_for_peer_id: string, expires_at_sec: number, issued_at_sec: number) {
    let trust_metadata = await tg.get_trust_bytes(relay, issued_for_peer_id, expires_at_sec, issued_at_sec);
    const signed_metadata = await issuer_kp.Libp2pPeerId.privKey.sign(Uint8Array.from(trust_metadata.result));

    let trust = await tg.issue_trust(relay, issued_for_peer_id, expires_at_sec, issued_at_sec, Array.from(signed_metadata));
    assert(trust.success)

    let result = await tg.verify_trust(relay, trust.trust, issuer_peer_id);
    assert(result.success)

    let result_add = await tg.add_trust(relay, trust.trust, issuer_peer_id);
    assert(result_add.success)
}

async function revoke_helper(node: string, issuer_kp: KeyPair, revoked_by_peer_id: string, revoked_peer_id: string, revoked_at_sec: number) {
    let trust_metadata = await tg.get_revoke_bytes(node, revoked_peer_id, revoked_at_sec);
    const signed_metadata = await issuer_kp.Libp2pPeerId.privKey.sign(Uint8Array.from(trust_metadata.result));

    let revocation = await tg.issue_revocation(node, revoked_peer_id, revoked_by_peer_id, revoked_at_sec, Array.from(signed_metadata));
    assert(revocation.success)

    let result_add = await tg.revoke(node, revocation.revocation);
    assert(result_add.success)
}

async function main() {
    console.log("📘 Will connect to local nodes");
    // key from local-network/builtins_secret_key.ed25519 to connect as builtins owner
    let sk = bs58.decode("5FwE32bDcphFzuMca7Y2qW1gdR64fTBYoRNvD4MLE1hecDGhCMQGKn8aseMr5wRo4Xo2CRFdrEAawUNLYkgQD78K").slice(0, 32); // first 32 bytes - secret key, second - public key
    let builtins_keypair = await KeyPair.fromEd25519SK(sk);

    await Fluence.start({ connectTo: local[0], KeyPair: builtins_keypair});
    console.log(
        "📗 created a fluence peer %s with relay %s",
        Fluence.getStatus().peerId,
        Fluence.getStatus().relayPeerId
    );
    let relay = local[0].peerId
    let nodeA = local[0].peerId
    let nodeB = local[1].peerId

    // keypair if nodeA specified in local-network/docker-compose.yml
    const issuer_kp = await KeyPair.fromEd25519SK(bs58.decode("29Apzfedhw2Jxh94Jj4rNSmavQ1TkNe8ALYRA7bMegobwp423aLrURxLk32WtXgXHDqoSz7GAT9fQfoMhVd1e5Ww"));

    // set nodeA as a root
    let add_root_result = await tg.add_root(relay, nodeA, 2);
    assert(add_root_result.success)

    // add self-signed root trust
    const issued_timestamp_sec = await tg.timestamp_sec(relay);
    const expires_at_sec = issued_timestamp_sec + 999999999;
    await add_trust_helper(relay, issuer_kp, nodeA, nodeB, expires_at_sec, issued_timestamp_sec);

    let root_weight_result = await tg.get_weight(relay, nodeA);
    assert(root_weight_result.success)
    console.log("Root weight (nodeA) is: %s", root_weight_result.weight);

    // issue trust by nodeA to nodeB and add to tg
    await add_trust_helper(relay, issuer_kp, nodeA, nodeB, expires_at_sec, issued_timestamp_sec);
    let weight_result = await tg.get_weight(relay, nodeB);
    console.log("Weight of nodeB: is %s", weight_result.weight);

    assert(root_weight_result.weight / 2 === weight_result.weight);

    let certs = await tg.get_all_certs(relay, nodeB);
    assert(certs.certificates.length === 1);
    console.log("There is one cert for nodeB with chain len %s", certs.certificates[0].chain.length);
    console.log("It contains self-signed nodeA root trust and nodeA->nodeB trust");

    // wait to create revoke after trust (because timestamp in secs)
    await new Promise(f => setTimeout(f, 1000));

    console.log("Now we will revoke trust for nodeB")
    // revoke nodeB by nodeA
    await revoke_helper(relay, issuer_kp, nodeA, nodeB, await tg.timestamp_sec(relay));

    let empty_certs = await tg.get_all_certs(relay, nodeB);
    assert(empty_certs.certificates.length === 0);
    console.log("Now there is no certs for nodeB");

    console.log("Let's check if our node is Fluence Labs peer");
    await is_fluence_peer(relay);

    console.log("Now let's check some krasnodar's node");
    await is_fluence_peer(krasnodar[0].peerId);

    return;
}


main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
