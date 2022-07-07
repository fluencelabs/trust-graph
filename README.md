# Trust Graph

## Overview
In web2 problem of access control and permissions is solved with centralized CAs (Certificate Authority). In distributed nature this problem is actual and even more challenging. TrustGraph is our view on the solution for this challenge.

TrustGraph is a bottom layer of trust for open p2p networks: every peer may be provided with SSL-like certificates, promote over the network. Service providers and other peers can then treat certificate-holders differently, based on the certificate set they have.

## Why is it important?

Problem of peer choice and prioritization is very urgent in p2p networks. Without trust to any network participant we can't use the network reliably and predictably. Also we should mark and avoid malicious peers. In addition we need to control our application access and permissions in runtime so it performs continiously without interruption and redeployment.

## What is it?

TrustGraph is basically a directed graph with at least one root, vertices are peer ids, edges are one of the two types of cryptographic relations: trust and revocation.

**Root** is a peer id that we unconditionally trust, until it is removed, defined by node owner. Every root have characteristics that represent maximum length for chain of trusts.

**Trust** is a cryptographic relation representing that peer A trusts peer B until this trust expires or is revoked.

**Revocation** is a cryptographic relation representing that peer A considers peer B malicious or unreliable.

**Certificate** is a chain of trusts, started with self-signed root trust.

So peerA is trusted by peerB if there is a path between them in this instance of TrustGraph. The selection of certificates is subjective and defined by node owner by choice of roots and maximum chain lengths.

Every peer has a **weight**

## How to Use it in Aqua


## How to Use it in TypeScript

See [example](./example):
- How to call [`trust-graph`](./example/index.ts) functions in TS/JS
- Step-by-step description [`README`](./example/README.md)

## API

High-level API is defined in the [trust-graph-api.aqua](./aqua/trust-graph-api.aqua) module.

## Directory structure

- [`src`](./src) is the main project with all trust graph logic

- [`keypair`](./keypair) directory is an abstracted cryptographical layer (key pairs, public keys, signatures, etc.)

- [`service`](./service) is a package that provides `marine` API and could be compiled to a Wasm file. It is uses `SQLite` as storage

- [`example`](./example) is a `js` script that shows how to use Trust Graph to label peers

- [`builtin-package`](./builtin-package) contains blueprint, configs and scripts for generation builtin package locally or via CI

- [`admin`](./admin) is a `js` script used to generate `builtin-package/on_start.json` which contains certificates for Fluence Labs nodes

## Learn Aqua

* [Aqua Book](https://fluence.dev/aqua-book/)
* [Aqua Playground](https://github.com/fluencelabs/aqua-playground)
* [Aqua repo](https://github.com/fluencelabs/aqua)

## How to use in Aqua

```
import "@fluencelabs/trust-graph/trust-graph-api.aqua"
import "@fluencelabs/trust-graph/trust-graph.aqua"

func my_function(peer_id: string) -> u32:
    on HOST_PEER_ID:
        result <- get_weight(peer_id)
    <- result
```

## How to use it in JS
1. Add the following to your dependencies
    - `@fluencelabs/trust-graph`
    - `@fluencelabs/aqua`
    - `@fluencelabs/aqua-lib`
    - `@fluencelabs/fluence`
    - `@fluencelabs/fluence-network-environment`

2. Import dependencies
   ```typescript
   import * as tg from "./generated/export";
   import { Fluence, KeyPair } from "@fluencelabs/fluence";
   import { krasnodar, Node } from "@fluencelabs/fluence-network-environment";
   ```
3. Create client (specify keypair if you are node owner
[link](https://github.com/fluencelabs/node-distro/blob/main/fluence/Config.default.toml#L9))

   ```typescript
   await Fluence.start({ connectTo: relay /*, KeyPair: builtins_keypair*/});
   ```
4. Add root and issue root trust.
   ```typescript
   let peer_id = Fluence.getStatus().peerId;
   let relay = Fluence.getStatus().relayPeerId;
   assert(peer_id !== null);
   assert(relay !== null);
   let max_chain_len = 2;
   let far_future = tg.timestamp_sec() + 9999999999;
   let error = await tg.add_root_trust(relay, peer_id, max_chain_len, far_future);
   if (error !== null) {
    console.log(error);
   }
   ```
5. For now, trusts/revocations can only be signed with the client's private key.
   Keypair specification will be available soon.
   ```typescript
   // issue signed trust
   let error = await tg.issue_trust(relay, peer_id, issued_for_peer_id, expires_at_sec);
   if (error !== null) {
    console.log(error);
   }
   ```

## Use cases


## FAQ

- Can weight changes during time?
  - if shortest path to root changed (trust expired or added)

- How we can interpret certificate and/or peer weight?

- What is zero weight mean?
   - There is no trust and path from any roots to target peer

a) how are scores calculated based on what feedback
 - this is out-of-scope for this project and until we have no metrics all trust/revocation are responsibility of the user.

b) how do i set all weights to untrusted and then over time increase trust in a peer? again, what is measured?
- all peers are untrusted by default. trust is unmeasured, weight represents how far this peer from root, the bigger weight -- the closer to the root.

c) how do i know that other peers are using the same processes to update weights? can i check that? do i need to blindly trust it?
- weights calculated locally based on certificates which contain signed trusts, write about signature checking

d) can i start my own instance of a trust graph or is there only a global version available? if so, how?
-  yes, you can change any service you want if you're node owner