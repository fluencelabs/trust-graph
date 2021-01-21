// store list of trusts
// check if trust is already in list before adding
// if there is an older trust - don't add received trust

use core::convert::TryFrom;
use fce_sqlite_connector;
use fce_sqlite_connector::Value;
use fce_sqlite_connector::{Connection, State};
use fluence_identity::public_key::PublicKey;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::str::FromStr;
use std::time::Duration;
use trust_graph::{Auth, PublicKeyHashable, Revoke, Storage, TrustGraph, TrustNode, Weight};

static INSTANCE: OnceCell<Mutex<TrustGraph>> = OnceCell::new();

pub fn get_data() -> &'static Mutex<TrustGraph> {
    INSTANCE.get_or_init(|| {
        let db_path = "/tmp/users.sqlite";
        let connection = fce_sqlite_connector::open(db_path).unwrap();

        let init_sql = "CREATE TABLE IF NOT EXISTS trustnodes(
        public_key TEXT PRIMARY KEY,
        trustnode BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS roots(
        public_key TEXT,
        weight INTEGER
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
                let tn_bin = r[0]
                    .as_binary()
                    .expect("unexpected: 'trustnode' in a table should be as string");

                let trust_node: TrustNode = bincode::deserialize(tn_bin)
                    .expect("unexpected: 'trustnode' should be as correct json");

                log::info!("trustnode: {:?}", trust_node);

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

        let tn_vec = bincode::serialize(&node).unwrap();

        cursor
            .bind(&[Value::String(format!("{}", pk)), Value::Binary(tn_vec)])
            .unwrap();

        cursor.next().unwrap();
    }

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Option<Weight> {
        let mut cursor = self
            .connection
            .prepare("SELECT public_key,weight FROM roots WHERE public_key = ?")
            .unwrap()
            .cursor();

        cursor.bind(&[Value::String(format!("{}", pk))]).unwrap();

        if let Some(row) = cursor.next().unwrap() {
            log::info!("row: {:?}", row);

            let w = u32::try_from(row[1].as_integer().unwrap()).unwrap();

            Some(w)
        } else {
            None
        }
    }

    fn add_root_weight(&mut self, pk: PublicKeyHashable, weight: Weight) {
        log::info!("add root: {} weight: {}", pk, weight);
        let mut cursor = self
            .connection
            .prepare("INSERT INTO roots VALUES (?, ?)")
            .unwrap()
            .cursor();

        cursor
            .bind(&[
                Value::String(format!("{}", pk)),
                Value::Integer(i64::from(weight)),
            ])
            .unwrap();

        cursor.next().unwrap();
    }

    fn root_keys(&self) -> Vec<PublicKeyHashable> {
        let mut cursor = self
            .connection
            .prepare("SELECT public_key,weight FROM roots")
            .unwrap()
            .cursor();

        let mut roots = vec![];

        while let Some(row) = cursor.next().unwrap() {
            log::info!("row: {:?}", row);
            let pk: PublicKeyHashable =
                PublicKeyHashable::from_str(row[0].as_string().unwrap()).unwrap();

            roots.push(pk)
        }

        roots
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
        match self.get(&pk) {
            Some(mut trust_node) => {
                trust_node.update_auth(auth);
                self.insert(pk.clone(), trust_node)
            }
            None => {
                let mut trust_node = TrustNode::new(issued_for.clone(), cur_time);
                trust_node.update_auth(auth);
                self.insert(pk.clone(), trust_node);
            }
        }
    }
}
