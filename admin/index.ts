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
import { Node, krasnodar } from "@fluencelabs/fluence-network-environment";
import assert from "assert";
import * as fs from "fs";
const bs58 = require('bs58');

let local: Node[] = [
    {
        peerId: "12D3KooWHBG9oaVx4i3vi6c1rSBUm7MLBmyGmmbHoZ23pmjDCnvK",
        multiaddr:
            "/ip4/127.0.0.1/tcp/9990/ws/p2p/12D3KooWHBG9oaVx4i3vi6c1rSBUm7MLBmyGmmbHoZ23pmjDCnvK",
    }
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

    let root_sk_b58 = fs.readFileSync("./root_secret_key.ed25519").toString();
    let issuer_sk_b58 = fs.readFileSync("./issuer_secret_key.ed25519").toString();
    let root_kp = await KeyPair.fromBytes(bs58.decode(root_sk_b58));
    let issuer_kp = await KeyPair.fromBytes(bs58.decode(issuer_sk_b58));
    console.log("Root private key: %s", root_sk_b58);
    console.log("Root peer id: %s", root_kp.Libp2pPeerId.toB58String());
    console.log("Issuer private key: %s", issuer_sk_b58);

    let node = local[0].peerId;
    let add_root_result = await add_root(node, root_kp.Libp2pPeerId.toB58String(), 2);
    console.log("Add root weight result: %s", add_root_result);

    let cur_time = await timestamp_sec(node);
    let expires_at = cur_time + 60 * 60 * 24 * 365;
    // self-signed root trust
    await add_trust_helper(node, root_kp,  root_kp.Libp2pPeerId.toB58String(), root_kp.Libp2pPeerId.toB58String(), expires_at, cur_time);
    // from root to issuer
    await add_trust_helper(node, root_kp, root_kp.Libp2pPeerId.toB58String(), issuer_kp.Libp2pPeerId.toB58String(), expires_at, cur_time);

    let certificates = [];
    for (let i = 0; i < krasnodar.length; i++)  {
        await add_trust_helper(node, issuer_kp, issuer_kp.Libp2pPeerId.toB58String(), krasnodar[i].peerId, expires_at, cur_time);
        let certs = await get_all_certs(node, krasnodar[i].peerId);
        certificates.push(certs.certificates[0]);
    }

    fs.writeFileSync("../builtin-package/on_start.json", JSON.stringify({certs: certificates}));

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
