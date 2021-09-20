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

import { get_trust_metadata, issue_trust, verify_trust } from "./generated/export";
import { Fluence, KeyPair } from "@fluencelabs/fluence";
import { Node } from "@fluencelabs/fluence-network-environment";
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

async function main(environment: Node[]) {
    await Fluence.start({ connectTo: environment[0] });
    console.log(
        "📗 created a fluence peer %s with relay %s",
        Fluence.getStatus().peerId,
        Fluence.getStatus().relayPeerId
    );


    let trust_metadata = await get_trust_metadata(local[0].peerId, local[1].peerId, 99999999999, 0);
    const issuer_kp = await KeyPair.fromBytes(bs58.decode("29Apzfedhw2Jxh94Jj4rNSmavQ1TkNe8ALYRA7bMegobwp423aLrURxLk32WtXgXHDqoSz7GAT9fQfoMhVd1e5Ww"));
    console.log("Issuer peer id: %", issuer_kp.Libp2pPeerId.toB58String());
    const signed_metadata = await issuer_kp.Libp2pPeerId.privKey.sign(Uint8Array.from(trust_metadata.result));
    let trust = await issue_trust(local[0].peerId, local[1].peerId, 99999999999, 0, Array.from(signed_metadata));
    console.log("Trust %s", trust.trust);
    let result = await verify_trust(local[0].peerId, trust.trust, local[0].peerId);
    console.log("Verify trust result: %s", result);
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
