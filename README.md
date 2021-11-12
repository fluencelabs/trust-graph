### Trust Graph

The network-wide peer relationship layer is used to manage connectivity and permissions. Peers keep the distributed graph of relationships, basically a Web of Trust. That graph is used is used to prioritize connections from known peers and avoid Sybil attacks. Also, TrustGraph may be used at the application level in various ways such as prioritization of service execution on authorized peers or a tighter connection of a single company’s peers.

### Project structure

`/.` is the main project with all trust graph logic and in-memory storage as a default

`keypair` directory is an abstracted cryptographical layer (key pairs, public keys, signatures, etc.)

`service` is a package that provides `marine` API and could be compiled to a Wasm file. It is uses `SQLite` as storage.

`example` is a `js` script that shows how to issue, sign trusts/revokes, get certificates
