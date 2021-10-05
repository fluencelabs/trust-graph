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

import {
    get_trust_bytes,
    issue_trust,
    verify_trust,
    add_trust,
    add_root,
    get_weight,
    timestamp_sec,
    get_all_certs,
    get_revoke_bytes,
    issue_revocation,
    revoke
} from "./generated/export";
import { Fluence, KeyPair } from "@fluencelabs/fluence";
import { Node } from "@fluencelabs/fluence-network-environment";
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

async function add_trust_helper(node: string, issuer_kp: KeyPair, issuer_peer_id: string, issued_for_peer_id: string, expires_at_sec: number, issued_at_sec: number) {
    let trust_metadata = await get_trust_bytes(node, issued_for_peer_id, expires_at_sec, issued_at_sec);
    const signed_metadata = await issuer_kp.Libp2pPeerId.privKey.sign(Uint8Array.from(trust_metadata.result));

    let trust = await issue_trust(node, issued_for_peer_id, expires_at_sec, issued_at_sec, Array.from(signed_metadata));
    console.log("Issued trust %s", trust.trust);

    let result = await verify_trust(node, trust.trust, issuer_peer_id);
    console.log("Verify trust result: %s", result);

    let result_add = await add_trust(node, trust.trust, issuer_peer_id);
    console.log("Add trust result: %s", result_add);
}

async function revoke_helper(node: string, issuer_kp: KeyPair, revoked_by_peer_id: string, revoked_peer_id: string, revoked_at_sec: number) {
    let trust_metadata = await get_revoke_bytes(node, revoked_peer_id, revoked_at_sec);
    const signed_metadata = await issuer_kp.Libp2pPeerId.privKey.sign(Uint8Array.from(trust_metadata.result));

    let revocation = await issue_revocation(node, revoked_peer_id, revoked_by_peer_id, revoked_at_sec, Array.from(signed_metadata));
    console.log("Issued revocation %s", revocation.revoke);

    let result_add = await revoke(node, revocation.revoke);
    console.log("Revoke result: %s", result_add);
}

async function main(environment: Node[]) {
    // key from local-network/builtins_secret_key.ed25519 to connect as builtins owner
    let sk = bs58.decode("5FwE32bDcphFzuMca7Y2qW1gdR64fTBYoRNvD4MLE1hecDGhCMQGKn8aseMr5wRo4Xo2CRFdrEAawUNLYkgQD78K").slice(0, 32); // first 32 bytes - secret key, second - public key
    let builtins_keypair = await KeyPair.fromBytes(sk);
    await Fluence.start({ connectTo: environment[0], KeyPair: builtins_keypair});
    console.log(
        "📗 created a fluence peer %s with relay %s",
        Fluence.getStatus().peerId,
        Fluence.getStatus().relayPeerId
    );
    const issued_timestamp_sec = await timestamp_sec(local[0].peerId);
    const expires_at_sec = issued_timestamp_sec + 999999999;
    const issuer_kp = await KeyPair.fromBytes(bs58.decode("29Apzfedhw2Jxh94Jj4rNSmavQ1TkNe8ALYRA7bMegobwp423aLrURxLk32WtXgXHDqoSz7GAT9fQfoMhVd1e5Ww"));

    let add_root_result = await add_root(local[0].peerId, local[0].peerId, 2);
    console.log("Add root weight result: %s", add_root_result);

    // add root trust
    await add_trust_helper(local[0].peerId, issuer_kp, local[0].peerId, local[0].peerId, expires_at_sec, issued_timestamp_sec);

    let root_weight_result = await get_weight(local[0].peerId, local[0].peerId);
    console.log("Root weight: %s", root_weight_result);

    // issue trust by local[0].peerId for local[1].peerId and add to tg
    await add_trust_helper(local[0].peerId, issuer_kp, local[0].peerId, local[1].peerId, expires_at_sec, issued_timestamp_sec);
    let weight_result = await get_weight(local[0].peerId, local[1].peerId);
    console.log("Trust weight: %s", weight_result);

    assert(root_weight_result.weight / 2 === weight_result.weight);

    let certs = await get_all_certs(local[0].peerId, local[1].peerId);
    console.log("Certs: %s", JSON.stringify(certs.certificates));


    // wait to create revoke after trust (because timestamp in secs)
    await new Promise(f => setTimeout(f, 1000));

    // revoke local[1].peerId trust
    await revoke_helper(local[0].peerId, issuer_kp, local[0].peerId, local[1].peerId, await timestamp_sec(local[0].peerId));

    let empty_certs = await get_all_certs(local[0].peerId, local[1].peerId);
    assert(empty_certs.certificates.length === 0);

    return;
}

let environment: Node[];
environment = local;
console.log("📘 Will connect to local nodes");

main(environment)
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
