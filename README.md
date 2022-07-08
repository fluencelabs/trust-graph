# Trust Graph

- [Trust Graph](#trust-graph)
  - [Overview](#overview)
  - [Why is it important?](#why-is-it-important)
  - [What is it?](#what-is-it)
  - [How to Use it in Aqua](#how-to-use-it-in-aqua)
    - [How to import](#how-to-import)
    - [How to add roots](#how-to-add-roots)
    - [How to issue and add trust](#how-to-issue-and-add-trust)
    - [How to revoke trust](#how-to-revoke-trust)
    - [How to get certificates](#how-to-get-certificates)
    - [How to get weights](#how-to-get-weights)
  - [How to use it in TS/JS](#how-to-use-it-in-tsjs)
  - [Use cases](#use-cases)
    - [Label trusted peers and execute computation only on this peers](#label-trusted-peers-and-execute-computation-only-on-this-peers)
  - [FAQ](#faq)
  - [API](#api)
  - [Directory structure](#directory-structure)
  - [Learn Aqua](#learn-aqua)

## Overview
In web2 problem of access control and permissions is solved with centralized CAs (Certificate Authority). In distributed nature this problem is actual and even more challenging. TrustGraph is our view on the solution for this challenge.

TrustGraph is a bottom layer of trust for open p2p networks: every peer may be provided with SSL-like certificates, promoted over the network. Service providers and other peers can then treat certificate-holders differently, based on the certificate set they have.

For now TrustGraph is a basic component which allows to store and manage certificates without any logics about how to decide whom to trust to and whom to treat as unreliable.

## Why is it important?

Problem of peer choice and prioritization is very urgent in p2p networks. Without trust to any network participant we can't use the network reliably and predictably. Also we should mark and avoid malicious peers. In addition we need to control our application access and permissions in runtime so it performs continiously without interruption and redeployment.

## What is it?

TrustGraph is basically a directed graph with at least one root, vertices are peer ids, edges are one of the two types of cryptographic relations: trust and revocation.

**Root** is a peer id that we unconditionally trust, until it is removed, defined by node owner. Every root have characteristics that represent maximum length for chain of trusts.

As a **path to the root** we consider path with only trust edges, given this rule: chain `R -> A -> ...-> C` is not a path if A revoked C.

**Trust** is a cryptographic relation representing that peer A trusts peer B until this trust expires or is revoked. Trust relation is transitive. If peer A trusts peer B and peer B trusts peer C so it results that peer A trusts peer C transitively.

**Certificate** is a chain of trusts, started with self-signed root trust.

So peerA is trusted by peerB if there is a path between them in this instance of TrustGraph. The selection of certificates is subjective and defined by node owner by choice of roots and maximum chain lengths.

**Revocation** is a cryptographic relation representing that peer A considers peer B malicious or unreliable. All chains containing paths from A to B will not be treated as valid. So if A trusts some peer C and C trusts B, peer A has no trust to B transitively it would has otherwise.

Every peer has a **weight**. Weight is a power of 2 or zero. If there is no path from any root to this peer, given revocations, weight equals zero. The closer to the root — the bigger the weight. Weights are subjective and

TrustGraph is a builtin and every node is bundled with TrustGraph instance and predefined certificates.

## How to Use it in Aqua
### How to import
```
import "@fluencelabs/trust-graph/trust-graph-api.aqua"
import "@fluencelabs/trust-graph/trust-graph.aqua"

func my_function(peer_id: string) -> u32:
    on HOST_PEER_ID:
        result <- get_weight(peer_id)
    <- result
```

### How to add roots
- `set_root(peer_id: PeerId, max_chain_len: u32) -> SetRootResult`
- `add_root_trust(node: PeerId, peer_id: PeerId, max_chain_len: u32) -> ?Error`

Let's set our peer id as a root on our relay and add self-signed trust:
```rust
func set_me_as_root(max_chain_len):
   result <- add_root_trust(HOST_PEER_ID, INIT_PEER_ID, max_chain_len)

   -- if you use peer_id different from INIT_PEER_ID
   -- you should add keypair in your Sig service
   if result.success:
      -- do smth
      Op.noop()
   else:
      -- handle failure
      Op.noop()
```
- also you can use `set_root` + `add_trust` to achieve same goal
- [how to add keypair to Sig service](https://doc.fluence.dev/docs/fluence-js/3_in_depth#signing-service)
- roots can be added only by service owner
- `max_chain_len` specifies the number of trusts in chain for this root. Zero for chains that contain only root trust.

### How to issue and add trust

- `issue_trust(issuer: PeerId, issued_for: PeerId, expires_at_sec: u64) -> ?Trust, ?Error`
- `import_trust(trust: Trust, issuer: PeerId) -> ?Error`
- `add_trust(node: PeerId, issuer: PeerId, issued_for: PeerId, expires_at_sec: u64) -> ?Error`

Let's issue trust and import it to our relay:
```rust
func issue_trust_by_me(issued_for: PeerId, expires_at_sec: u64):
   trust, error <- issue_trust(INIT_PEER_ID, issued_for, expires_at_sec)
   if trust == nil:
      -- handle failure
      Op.noop()
   else:
      on HOST_PEER_ID:
         error <- import_trust(trust!, INIT_PEER_ID)
         -- handle error
```


- `add_trust` is a combination of `issue_trust` and `import_trust`
- if you want to issue trust not by `INIT_PEER_ID` check Sig service [docs](https://doc.fluence.dev/docs/fluence-js/3_in_depth#signing-service)

### How to revoke trust

- `issue_revocation(revoked_by: PeerId, revoked: PeerId) -> ?Revocation, ?Error`
- `import_revocation(revocation: Revocation) -> ?Error`
- `revoke(node: PeerId, revoked_by: PeerId, revoked: PeerId) -> ?Error`

Let's revoke some peer by our peer id:
```rust
func revoke_peer(revoked: PeerId):
   revocation, error <- issue_revocation(INIT_PEER_ID, revoked)
   if revocation == nil:
      -- handle failure
      Op.noop()
   else:
      on HOST_PEER_ID:
         error <- import_revocation(revocation!)
         -- handle error
```

- `revoke` is a combination of `issue_revocation` and `import_revocation`
- if you want to issue revocation not by `INIT_PEER_ID` check Sig service [docs](https://doc.fluence.dev/docs/fluence-js/3_in_depth#signing-service)


### How to get certificates

- `get_all_certs(issued_for: PeerId) -> AllCertsResult`
- `get_all_certs_from(issued_for: PeerId, issuer: PeerId) -> AllCertsResult`
- `get_host_certs() -> AllCertsResult`
- `get_host_certs_from(issuer: PeerId) -> AllCertsResult`

Let's get all certificates issued by us to our relay peer id (HOST_PEER_ID):
```rust
func get_certs_issued_by_me() -> AllCertsResult:
   on HOST_PEER_ID:
      result <- get_host_certs_from(INIT_PEER_ID)
   <- result
```
- `get_host_certs` is just alias for `get_all_certs(HOST_PEER_ID)`
- `_from` calls results contain only certificates with trust issued by `issuer`

### How to get weights
- `get_weight(peer_id: PeerId) -> WeightResult`
- `get_weight_from(peer_id: PeerId, issuer: PeerId) -> WeightResult`

Let's get our weight for certificates which contain trust by our relay
```rust
func get_our_weight() -> ?u32, ?string:
   weight: ?u32
   error: ?string
   on HOST_PEER_ID:
      result <- get_weight_from(INIT_PEER_ID, HOST_PEER_ID)
      if result.success:
         weight <<- result.weight
      else:
         error <<- result.error
   <- weight, error
```

- `get_weight` return result among all the certificates, on the other hand `get_weight_from` given only certificates containing trust by issuer

## How to use it in TS/JS
1. Add `export.aqua` as in Aqua [documentation](https://doc.fluence.dev/aqua-book/libraries#in-typescript-and-javascript)
2. Add the following to your dependencies
    - `@fluencelabs/trust-graph`
    - `@fluencelabs/aqua`
    - `@fluencelabs/aqua-lib`
    - `@fluencelabs/fluence`
    - `@fluencelabs/fluence-network-environment`

3. Import dependencies
   ```typescript
   import * as tg from "./generated/export";
   import { Fluence, KeyPair } from "@fluencelabs/fluence";
   import { krasnodar, Node } from "@fluencelabs/fluence-network-environment";
   ```
4. Create client (specify keypair if you are node owner
[link](https://github.com/fluencelabs/node-distro/blob/main/fluence/Config.default.toml#L9))

   ```typescript
   await Fluence.start({ connectTo: relay /*, KeyPair: builtins_keypair*/});
   ```
5. Add root and issue root trust.
   ```typescript
   let peer_id = Fluence.getStatus().peerId;
   let relay = Fluence.getStatus().relayPeerId;
   assert(peer_id !== null);
   assert(relay !== null);
   let max_chain_len = 2;
   let far_future = 99999999999999;
   let error = await tg.add_root_trust(relay, peer_id, max_chain_len, far_future);
   if (error !== null) {
    console.log(error);
   }
   ```
6. By default, trusts/revocations signed with the client's private key. To sign with different keys see Sig service [documentation](https://doc.fluence.dev/docs/fluence-js/3_in_depth#signing-service).
   ```typescript
   // issue signed trust
   let error = await tg.issue_trust(relay, peer_id, issued_for_peer_id, expires_at_sec);
   if (error !== null) {
    console.log(error);
   }
   ```

## Use cases

### Label trusted peers and execute computation only on this peers

See [example](./example):
- How to call [`trust-graph`](./example/index.ts) functions in TS/JS
- Step-by-step description [`README`](./example/README.md)


## FAQ

- Can weight changes during time?
  - If the shortest path to root changed, in case of trust expiration, importing or revocation, weight also changes.

- What is zero weight mean?
   - Zero weight means there is no trust and path from any roots to the target peer.

- How we can interpret certificate and/or peer weight?
  - Certificate contains path from the root to the target peer we are looking for. Weight represents presence of these certificates and peer closeness to the root.


- How are weights calculated and based on what feedback?
  - Weights are calculated based on existence of chain of trusts from the roots. For example, if we have root with maximum chain length equals 4 and have a chain R -> A -> B -> C, so the corresponding weights of peers are 8, 4, 2, 1. Weights are the same if there is no changes in the paths.
  Until we have no metrics all trust/revocation logics is a responsibility of the user.

- How do I set all weights to untrusted and then over time increase trust in a peer?
  - All peers are untrusted by default. Trust is unmeasured, weight represents how far this peer from root, the bigger weight -- the closer to the root, so if you want to increase weight of the target peer you should obtain trust from the root or peers which are closer to the root than this peer.

- How do I know that other peers are using the same processes to update weights?
  - Weights calculated **locally** based on certificates which contain immutable signed trusts. Weights are subjective and have a sense only locally to this exact peer.

-  Can I start my own instance of a trust graph or is there only a global version available?
   - Every Fluence node bundled with builtin TrustGraph instance, but you can change or remove any service you want if you're node owner.

## API

High-level API is defined in the [trust-graph-api.aqua](./aqua/trust-graph-api.aqua) module. API Reference soon will be available in the documentation.

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
