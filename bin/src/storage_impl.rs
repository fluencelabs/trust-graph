// store list of trusts
// check if trust is already in list before adding
// if there is an older trust - don't add received trust

use trust_graph::{Storage, TrustGraph, PublicKeyHashable, TrustNode, Weight, Auth, Revoke};
use fluence_identity::public_key::PublicKey;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::time::Duration;
use fce_sqlite_connector;
use fce_sqlite_connector::{State, Connection};

static INSTANCE: OnceCell<Mutex<TrustGraph>> = OnceCell::new();

fn get_data() -> &'static Mutex<TrustGraph> {
    INSTANCE.get_or_init(|| {
        let db_path = "/var/folders/ww/v__xg0cj17x7h7sf3bgwpx8h0000gn/T/4589ab6f-5440-4933-ace5-a62714784142/tmp/users.sqlite";
        let connection = fce_sqlite_connector::open(db_path).unwrap();
        Mutex::new(TrustGraph::new(Box::new(SqliteStorage {connection})))
    })
}

struct SqliteStorage {
    connection: Connection,
}

impl SqliteStorage {
    pub fn init(&self) {
        let init_sql = "CREATE TABLE IF NOT EXISTS trusts(\
        peer_id TEXT PRIMARY KEY,\
        relay TEXT NOT NULL,\
        sig TEXT NOT NULL,\
        name TEXT NOT NULL\
        );";
    }
}

impl Storage for SqliteStorage {
    fn get(&self, pk: &PublicKeyHashable) -> Option<&TrustNode> {
        None
    }
    fn insert(&mut self, pk: PublicKeyHashable, node: TrustNode) {

    }

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Option<&Weight> {
        None
    }
    fn add_root_weight(&mut self, pk: PublicKeyHashable, weight: Weight) {

    }
    fn root_keys(&self) -> Vec<PublicKeyHashable> {
        vec![]
    }
    fn revoke(&mut self, pk: &PublicKeyHashable, revoke: Revoke) -> Result<(), String> {
        Err("not implemented".to_string())
    }
    fn update_auth(
        &mut self,
        pk: &PublicKeyHashable,
        auth: Auth,
        issued_for: &PublicKey,
        cur_time: Duration,
    ) {

    }
}