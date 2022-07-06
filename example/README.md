## Description
This example shows how to use Trust Graph to label peers. There are some `trusted_computation` which can only be executed
on labeled peer. The label is determined by the presence of certificate from `%init_peer_id` to this peer.


## Run example on network
4. Run `npm i`
5. Run `npm run start`

## Run example locally
1. Go to `local-network`
2. Run `docker compose up -d` to start Fluence node
3. It takes some time depending on your machine for node to start and builtin services deployed. Wait for this log line: `[2022-07-06T11:33:50.782054Z INFO  particle_node] Fluence has been successfully started.`
4. Go back to `../example`
5. Run `npm i`
6. Run `npm run start local`
