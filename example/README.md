## Description
This example shows how to use Trust Graph for code execution only on trusted peers. There are some `trusted_computation` which can only be performed on a trusted peer. The label is determined by the presence of the certificate from `INIT_PEER_ID` to this peer. We use peer id from [`example_secret_key.ed25519`](../example_secret_key.ed25519) as `INIT_PEER_ID` since every node bundled with the certificate issued to this key, it should be used only for test purposes.

## Run example on network

1. Run `npm i`
2. Run `npm run start`

## Run example locally

1. Go to `local-network`
2. Run `docker compose up -d` to start Fluence node
3. It takes some time depending on your machine for node to start and builtin services deployed. Wait for this log line: `[2022-07-06T11:33:50.782054Z INFO  particle_node] Fluence has been successfully started.`
4. Go back to `../example`
5. Run `npm i`
6. Run `npm run start local`

## Expected output

After successful execution you will get this result:
```
In this example we try to execute some trusted computations based on trusts
📘 Will connect to testNet
📗 created a fluence peer 12D3KooWD2vAZva1u3TQgoxebBUBsaGMNawKjVkp57M6UcwNwXNv with relay 12D3KooWEXNUbCXooUwHrHBbrmjsrpHXoEphPwbjQXEGyzbqKnE9

📕 Trusted computation on node 12D3KooWEXNUbCXooUwHrHBbrmjsrpHXoEphPwbjQXEGyzbqKnE9 failed, error: there is no certs for this peer
📕 Trusted computation on node 12D3KooWMhVpgfQxBLkQkJed8VFNvgN4iE6MD7xCybb1ZYWW2Gtz failed, error: there is no certs for this peer
📕 Trusted computation on node 12D3KooWHk9BjDQBUqnavciRPhAYFvqKBe4ZiPPvde7vDaqgn5er failed, error: there is no certs for this peer

🌀 Issue trust to nodeB 12D3KooWMhVpgfQxBLkQkJed8VFNvgN4iE6MD7xCybb1ZYWW2Gtz and nodeC: 12D3KooWHk9BjDQBUqnavciRPhAYFvqKBe4ZiPPvde7vDaqgn5er
Trust issued for 12D3KooWMhVpgfQxBLkQkJed8VFNvgN4iE6MD7xCybb1ZYWW2Gtz successfully added
Trust issued for 12D3KooWHk9BjDQBUqnavciRPhAYFvqKBe4ZiPPvde7vDaqgn5er successfully added

📕 Trusted computation on node 12D3KooWEXNUbCXooUwHrHBbrmjsrpHXoEphPwbjQXEGyzbqKnE9 failed, error: there is no certs for this peer
📗 Trusted computation on node 12D3KooWMhVpgfQxBLkQkJed8VFNvgN4iE6MD7xCybb1ZYWW2Gtz successful, result is 5
📗 Trusted computation on node 12D3KooWHk9BjDQBUqnavciRPhAYFvqKBe4ZiPPvde7vDaqgn5er successful, result is 5

🚫 Revoke trust to nodeB
Trust issued for 12D3KooWMhVpgfQxBLkQkJed8VFNvgN4iE6MD7xCybb1ZYWW2Gtz revoked

📕 Trusted computation on node 12D3KooWEXNUbCXooUwHrHBbrmjsrpHXoEphPwbjQXEGyzbqKnE9 failed, error: there is no certs for this peer
📕 Trusted computation on node 12D3KooWMhVpgfQxBLkQkJed8VFNvgN4iE6MD7xCybb1ZYWW2Gtz failed, error: there is no certs for this peer
📗 Trusted computation on node 12D3KooWHk9BjDQBUqnavciRPhAYFvqKBe4ZiPPvde7vDaqgn5er successful, result is 5
```