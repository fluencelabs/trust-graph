// store list of trusts
// check if trust is already in list before adding
// if there is an older trust - don't add received trust

use crate::storage_impl::SQLiteStorageError::{
    PublcKeyNotFound, PublicKeyConversion, PublicKeyFromStr, TrustNodeConversion,
    WeightConversionDB,
};
use core::convert::TryFrom;
use fce_sqlite_connector;
use fce_sqlite_connector::Connection;
use fce_sqlite_connector::Error as InternalSqliteError;
use fce_sqlite_connector::Value;
use fluence_identity::public_key::PublicKey;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use rmp_serde::decode::Error as RmpDecodeError;
use rmp_serde::encode::Error as RmpEncodeError;
use std::convert::From;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;
use trust_graph::{
    Auth, PublicKeyHashable as PK, Revoke, Storage, StorageError, TrustGraph, TrustNode, Weight,
};

static INSTANCE: OnceCell<Mutex<TrustGraph<SQLiteStorage>>> = OnceCell::new();

pub fn get_data() -> &'static Mutex<TrustGraph<SQLiteStorage>> {
    INSTANCE.get_or_init(|| {
        let db_path = "/tmp/users123123.sqlite";
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

        Mutex::new(TrustGraph::new(SQLiteStorage::new(connection)))
    })
}

pub struct SQLiteStorage {
    connection: Connection,
}

impl SQLiteStorage {
    pub fn new(connection: Connection) -> SQLiteStorage {
        SQLiteStorage { connection }
    }
}

#[derive(ThisError, Debug)]
pub enum SQLiteStorageError {
    #[error("{0}")]
    SQLiteError(
        #[from]
        #[source]
        InternalSqliteError,
    ),
    #[error("{0}")]
    PublicKeyFromStr(String),
    #[error("{0}")]
    EncodeError(
        #[from]
        #[source]
        RmpEncodeError,
    ),
    #[error("{0}")]
    DecodeError(
        #[from]
        #[source]
        RmpDecodeError,
    ),
    #[error("Cannot convert weight as integer from DB")]
    WeightConversionDB,
    #[error("Cannot convert public key as binary from DB")]
    PublicKeyConversion,
    #[error("Cannot convert trust node as binary from DB")]
    TrustNodeConversion,
    #[error("Cannot revoke. There is no trust with such PublicKey")]
    PublcKeyNotFound,
}

impl From<SQLiteStorageError> for String {
    fn from(err: SQLiteStorageError) -> Self {
        err.into()
    }
}

impl StorageError for SQLiteStorageError {}

impl Storage for SQLiteStorage {
    type Error = SQLiteStorageError;

    fn get(&self, pk: &PK) -> Result<Option<TrustNode>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare("SELECT trustnode FROM trustnodes WHERE public_key = ?")?
            .cursor();

        cursor.bind(&[Value::String(format!("{}", pk))])?;

        match cursor.next().unwrap() {
            Some(r) => {
                log::info!("row: {:?}", r);
                let tn_bin: &[u8] = r[0].as_binary().ok_or(TrustNodeConversion)?;

                log::info!("binary: {:?}", tn_bin);

                let trust_node: TrustNode = rmp_serde::from_read_ref(tn_bin)?;

                log::info!("trustnode: {:?}", trust_node);

                Ok(Some(trust_node))
            }

            None => Ok(None),
        }
    }

    fn insert(&mut self, pk: PK, node: TrustNode) -> Result<(), Self::Error> {
        let mut cursor = self
            .connection
            .prepare("INSERT OR REPLACE INTO trustnodes VALUES (?, ?)")?
            .cursor();

        let tn_vec = rmp_serde::to_vec(&node)?;

        log::info!("insert: {:?}", tn_vec);

        cursor.bind(&[Value::String(format!("{}", pk)), Value::Binary(tn_vec)])?;

        cursor.next()?;
        Ok({})
    }

    fn get_root_weight(&self, pk: &PK) -> Result<Option<Weight>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare("SELECT public_key,weight FROM roots WHERE public_key = ?")?
            .cursor();

        cursor.bind(&[Value::String(format!("{}", pk))])?;

        if let Some(row) = cursor.next()? {
            log::info!("row: {:?}", row);

            let w = u32::try_from(row[1].as_integer().ok_or(WeightConversionDB)?)
                .map_err(|_e| WeightConversionDB)?;

            Ok(Some(w))
        } else {
            Ok(None)
        }
    }

    fn add_root_weight(&mut self, pk: PK, weight: Weight) -> Result<(), Self::Error> {
        log::info!("add root: {} weight: {}", pk, weight);
        let mut cursor = self
            .connection
            .prepare("INSERT OR REPLACE INTO roots VALUES (?, ?)")?
            .cursor();

        cursor.bind(&[
            Value::String(format!("{}", pk)),
            Value::Integer(i64::from(weight)),
        ])?;

        cursor.next()?;
        Ok({})
    }

    fn root_keys(&self) -> Result<Vec<PK>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare("SELECT public_key,weight FROM roots")?
            .cursor();

        let mut roots = vec![];

        while let Some(row) = cursor.next()? {
            log::info!("row: {:?}", row);
            let pk = row[0].as_string().ok_or(PublicKeyConversion)?;
            let pk: PK = PK::from_str(pk).map_err(|e| PublicKeyFromStr(e.to_string()))?;

            roots.push(pk)
        }

        Ok(roots)
    }

    fn revoke(&mut self, pk: &PK, revoke: Revoke) -> Result<(), Self::Error> {
        match self.get(&pk)? {
            Some(mut trust_node) => {
                trust_node.update_revoke(revoke);
                self.insert(pk.clone(), trust_node)?;
                Ok(())
            }
            None => Err(PublcKeyNotFound),
        }
    }

    fn update_auth(
        &mut self,
        pk: &PK,
        auth: Auth,
        issued_for: &PublicKey,
        cur_time: Duration,
    ) -> Result<(), Self::Error> {
        match self.get(&pk)? {
            Some(mut trust_node) => {
                trust_node.update_auth(auth);
                self.insert(pk.clone(), trust_node)
            }
            None => {
                let mut trust_node = TrustNode::new(issued_for.clone(), cur_time);
                trust_node.update_auth(auth);
                self.insert(pk.clone(), trust_node)
            }
        }
    }
}
