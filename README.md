# Trust Graph

The network-wide peer relationship layer is used to manage connectivity and permissions. Peers keep the distributed graph of relationships, basically a Web of Trust. That graph is used is used to prioritize connections from known peers and avoid Sybil attacks. Also, TrustGraph may be used at the application level in various ways such as prioritization of service execution on authorized peers or a tighter connection of a single company’s peers.

## How to Use it in TypeScript

See [example](./example):
- How to call [`trust-graph`](./example/index.ts) functions in TS/JS 
- Step-by-step description [`README`](./example/README.md)

## API

Low-level API is defined in the [trust-graph-api.aqua](./aqua/trust-graph-api.aqua) module.

## Directory structure

- [`src`](./src) is the main project with all trust graph logic

- [`keypair`](./keypair) directory is an abstracted cryptographical layer (key pairs, public keys, signatures, etc.)

- [`service`](./service) is a package that provides `marine` API and could be compiled to a Wasm file. It is uses `SQLite` as storage.

- [`example`](./example) is a `js` script that shows how to issue, sign trusts/revocations, export certificates and distinguish Fluence nodes

- [`builtin-package`](./builtin-package) contains blueprint, configs and scripts for generation builtin package locally or via CI

- [`admin`](./admin) is a `js` script used to generate `builtin-package/on_start.json` which contains certificates for Fluence Labs nodes

## Learn Aqua

* [Aqua Book](https://fluence.dev/aqua-book/)
* [Aqua Playground](https://github.com/fluencelabs/aqua-playground)
* [Aqua repo](https://github.com/fluencelabs/aqua)
