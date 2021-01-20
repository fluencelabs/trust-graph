// store list of trusts
// check if trust is already in list before adding
// if there is an older trust - don't add received trust

use fce_sqlite_connector;
use fce_sqlite_connector::Value;
use fce_sqlite_connector::{Connection, State};
use fluence_identity::public_key::PublicKey;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::time::Duration;
use trust_graph::{Auth, PublicKeyHashable, Revoke, Storage, TrustGraph, TrustNode, Weight};

static INSTANCE: OnceCell<Mutex<TrustGraph>> = OnceCell::new();

pub fn get_data() -> &'static Mutex<TrustGraph> {
    INSTANCE.get_or_init(|| {
        let db_path = "/tmp/users.sqlite";
        let connection = fce_sqlite_connector::open(db_path).unwrap();

        let init_sql = "CREATE TABLE IF NOT EXISTS trustnodes(\
        public_key TEXT PRIMARY KEY,\
        trustnode TEXT NOT NULL,\
        );";

        connection.execute(init_sql).expect("cannot connect to db");

        Mutex::new(TrustGraph::new(Box::new(SqliteStorage { connection })))
    })
}

struct SqliteStorage {
    connection: Connection,
}

impl SqliteStorage {}

impl Storage for SqliteStorage {
    fn get(&self, pk: &PublicKeyHashable) -> Option<TrustNode> {
        let mut cursor = self
            .connection
            .prepare("SELECT trustnode FROM trustnodes WHERE public_key = ?")
            .expect("unexpected: 'get' request should be correct")
            .cursor();

        cursor
            .bind(&[Value::String(format!("{}", pk))])
            .expect("unexpected: 'public_key' field should be string");

        match cursor.next().unwrap() {
            Some(r) => {
                let tn_str = r[0]
                    .as_string()
                    .expect("unexpected: 'trustnode' in a table should be as string");
                let trust_node: TrustNode = serde_json::from_str(tn_str)
                    .expect("unexpected: 'trustnode' should be as correct json");
                Some(trust_node)
            }

            None => None,
        }
    }

    fn insert(&mut self, pk: PublicKeyHashable, node: TrustNode) {
        let mut cursor = self
            .connection
            .prepare("INSERT INTO trustnodes VALUES (?, ?)")
            .unwrap()
            .cursor();

        let tn_str = serde_json::to_string(&node).unwrap();

        cursor.bind(&[Value::String(format!("{}", pk))]).unwrap();
        cursor
            .bind(&[Value::String(format!("{}", tn_str))])
            .unwrap();

        cursor.next().unwrap();
    }

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Option<&Weight> {
        None
    }

    fn add_root_weight(&mut self, pk: PublicKeyHashable, weight: Weight) {}

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
