# Trust Graph

Trust Graph is network-wide peer relationship layer. It's designed to be used to prioritize resources and control permissions in open networks. Being a decentralized graph of relationships, basically a Web of Trust, Trust Graph is distributed among all network peers. 

Specifically, Trust Graph is used to prioritize connections from known peers to counteract Sybil attacks while still keeping network open by reserving resources for unknown peers. 

At the same time, Trust Graph can be used at the application level in various ways such as prioritization of service execution on authorized peers or to define an interconnected subnetwork among peers of a single protocol.

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

## How to use is js
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
