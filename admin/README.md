# How to generate export certificates
1. Go to `local-network` if you want to use local node
   - Run `docker compose up -d` to start Fluence node
   - Go back to `../admin`
2. Put `root_secret_key.ed25519` and `issuer_secret_key.ed25519` to folder
3. Run `npm i`
4. Run `npm run start {env}` where `{env}` should be `testnet`/`krasnodar`/`stage` or `local`

`root_secret_key.ed25519` and `issuer_secret_key.ed25519` are secret and owned by Fluence Labs team. Root key is for
all Fluence Labs relations. Trust from issuer key to any peer id means that this peer is official Fluence Labs peer.
isFluencePeer method from [trust-graph-api.aqua](./aqua/trust-graph-api.aqua) module checks these relations. You can build your own
structure of peers similarly.

`example_secret_key.ed25519` publicly available and used for test purposes.
