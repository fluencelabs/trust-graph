## Description
This example shows how to use Trust Graph to label peers. There are some `trusted_computation` which can only be executed 
on labeled peer. The label is determined by the presence of certificate from `%init_peer_id` to this peer.

## Run example locally
1. Go to `local-network`
2. Run `docker compose up -d` to start Fluence node
3. Go back to `../example`
4. Run `npm i`
5. Run `npm run start`
