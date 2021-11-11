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
    timestamp_sec,

} from "./generated/export";
import { Fluence, KeyPair } from "@fluencelabs/fluence";
import { Node, krasnodar, stage, testNet } from "@fluencelabs/fluence-network-environment";
import * as fs from "fs";
const bs58 = require('bs58');

let local: Node[] = [
    {
        peerId: "12D3KooWHBG9oaVx4i3vi6c1rSBUm7MLBmyGmmbHoZ23pmjDCnvK",
        multiaddr:
            "/ip4/127.0.0.1/tcp/9990/ws/p2p/12D3KooWHBG9oaVx4i3vi6c1rSBUm7MLBmyGmmbHoZ23pmjDCnvK",
    }
];

async function issue_trust_helper(node: string, issuer_kp: KeyPair, issuer_peer_id: string, issued_for_peer_id: string, expires_at_sec: number, issued_at_sec: number) {
    let trust_metadata = await get_trust_bytes(node, issued_for_peer_id, expires_at_sec, issued_at_sec);
    const signed_metadata = await issuer_kp.Libp2pPeerId.privKey.sign(Uint8Array.from(trust_metadata.result));

    let trust = await issue_trust(node, issued_for_peer_id, expires_at_sec, issued_at_sec, Array.from(signed_metadata));
    return trust.trust
}

async function main(environment: Node[]) {
    let node = environment[0].peerId;
    await Fluence.start({ connectTo: environment[0]});
    console.log(
        "📗 created a fluence peer %s with relay %s",
        Fluence.getStatus().peerId,
        Fluence.getStatus().relayPeerId
    );

    let root_sk_b58 = fs.readFileSync("./root_secret_key.ed25519").toString();
    let issuer_sk_b58 = fs.readFileSync("./issuer_secret_key.ed25519").toString();
    let root_kp = await KeyPair.fromEd25519SK(bs58.decode(root_sk_b58));
    let issuer_kp = await KeyPair.fromEd25519SK(bs58.decode(issuer_sk_b58));
    console.log("Root private key: %s", root_sk_b58);
    console.log("Root peer id: %s", root_kp.Libp2pPeerId.toB58String());
    console.log("Issuer private key: %s", issuer_sk_b58);

    let cur_time = await timestamp_sec(node);
    let expires_at = cur_time + 60 * 60 * 24 * 365;
    let common_chain = [] as any;
    // self-signed root trust
    common_chain.push(await issue_trust_helper(node, root_kp,  root_kp.Libp2pPeerId.toB58String(), root_kp.Libp2pPeerId.toB58String(), expires_at, cur_time));
    // from root to issuer
    common_chain.push(await issue_trust_helper(node, root_kp, root_kp.Libp2pPeerId.toB58String(), issuer_kp.Libp2pPeerId.toB58String(), expires_at, cur_time));

    let certificates = [];
    for (let i = 0; i < krasnodar.length; i++)  {
        // from issuer to node
        let trust = await issue_trust_helper(node, issuer_kp, issuer_kp.Libp2pPeerId.toB58String(), krasnodar[i].peerId, expires_at, cur_time);
        let cert = {chain: [...common_chain, trust]};
        certificates.push(cert);
    }

    fs.writeFileSync("../builtin-package/on_start.json", JSON.stringify({certs: certificates}));

    return;
}

let args = process.argv.slice(2);
let environment: Node[];
if (args.length >= 1 && args[0] == "testnet") {
    environment = testNet;
    console.log("📘 Will connect to testNet");
} else if (args[0] == "stage") {
    environment = stage;
    console.log("📘 Will connect to stage");
} else if (args[0] == "krasnodar") {
    environment = krasnodar;
    console.log("📘 Will connect to krasnodar");
} else if (args[0] == "testnet") {
    environment = testNet;
    console.log("📘 Will connect to testNet");
} else {
    throw "Specify environment";
}

main(environment)
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });
