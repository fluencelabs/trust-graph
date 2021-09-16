### Trust Graph

The network-wide peer relationship layer is used to manage connectivity and permissions. Peers keep the distributed graph of relationships, basically a Web of Trust. That graph is used is used to prioritize connections from known peers and avoid Sybil attacks. Also, TrustGraph may be used at the application level in various ways such as prioritization of service execution on authorized peers or a tighter connection of a single company’s peers.

### Project structure

`/.` is the main project with all trust graph logic and in-memory storage as a default

`identity` directory is an abstracted cryptographical layer (key pairs, signature, etc.)

`wasm` is a package that provides `fce` API and could be compiled to a Wasm file. It is used `SQLite` as storage and could be used only with `SQLite` Wasm file near.

`js` is a `npm` package that allows you to create and serialize certificates


### Use trust-graph as a library


```
// Generate a new key pair
let root_kp = KeyPair::generate();

// Generate a key for which a certificate will be issued
let issued_for = KeyPair::generate();

// A time when the certificate will be issued and whet it will be expired
let now = Duration::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u64)
let expires_at = Duration::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u64 + 10000)

// Create a certificate
let mut cert = Certificate::issue_root(&root_kp, issued_for.public_key(), expires_at, now);

// We can add more keys to extend created certificate
// The method requires current_time to check if the old certificate is valid
let new_key = KeyPair::generate();
let new_cert = Certificate::issue(
                &issued_for,
                new_key.public_key(),
                &cert,
                expires_at,               
                now,
                current_time(),
            )?;

// Create new trust graph instance
let st = Box::new(InMemoryStorage::new());
let mut graph = TrustGraph::new(st);

// Add root weights. Basic keys that certificates should start with
graph.add_root_weight(root_kp.public_key().into(), 1);

// Add the certificate to a trust graph
// current_time is to check if certificate is still valid
// Could throw an error if the certificate is expired or malformed
graph.add(new_cert, current_time()).unwrap();

// We can check a weight of a key based on certificates we added and root weights
// If one public key have multiple trusts, we will get the maximum
let w = graph.weight(new_key.public_key()).unwrap().unwrap();

// Every trust or chain of trusts could be revoked by owners of keys in certificates

let revoke = Revoke::create(&issued_for, new_key.public_key(), current_time());
graph.revoke(revoke).unwrap();
```

