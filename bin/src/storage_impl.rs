// store list of trusts
// check if trust is already in list before adding
// if there is an older trust - don't add received trust

use core::convert::TryFrom;
use fluence_identity::public_key::PublicKey;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use fce_sqlite_connector;
use fce_sqlite_connector::Connection;
use fce_sqlite_connector::Value;
use fce_sqlite_connector::Error as InternalSqliteError;
use std::str::FromStr;
use std::time::Duration;
use trust_graph::{Auth, PublicKeyHashable, Revoke, Storage, TrustGraph, TrustNode, Weight, StorageError};
use thiserror::Error as ThisError;
use crate::storage_impl::SqliteStorageError::{SqliteError, EncodeError, ConvertionError, DecodeError, Unexpected, RevokeError};
use rmp_serde::encode::Error as RmpEncodeError;
use rmp_serde::decode::Error as RmpDecodeError;
use std::convert::From;

static INSTANCE: OnceCell<Mutex<TrustGraph<SqliteStorage>>> = OnceCell::new();

pub fn get_data() -> &'static Mutex<TrustGraph<SqliteStorage>> {
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

        Mutex::new(TrustGraph::new(Box::new(SqliteStorage::new(connection))))
    })
}

pub struct SqliteStorage {
    connection: Connection,
}

impl SqliteStorage {
    pub fn new(connection: Connection) -> SqliteStorage {
        SqliteStorage { connection }
    }
}

#[derive(ThisError, Debug)]
pub enum SqliteStorageError {
    #[error("Unexpected: {0}")]
    Unexpected(String),
    #[error("{0}")]
    SqliteError(InternalSqliteError),
    #[error("{0}")]
    EncodeError(String),
    #[error("{0}")]
    DecodeError(String),
    #[error("There is no entry for {0}")]
    ConvertionError(String),
    #[error("Cannot revoke a trust: {0}")]
    RevokeError(String)
}

impl From<InternalSqliteError> for SqliteStorageError {
    fn from(err: InternalSqliteError) -> Self {
        SqliteError(err)
    }
}

impl From<RmpEncodeError> for SqliteStorageError {
    fn from(err: RmpEncodeError) -> Self {
        EncodeError(format!("{}", err))
    }
}

impl From<RmpDecodeError> for SqliteStorageError {
    fn from(err: RmpDecodeError) -> Self {
        DecodeError(format!("{}", err))
    }
}

impl From<SqliteStorageError> for String {
    fn from(err: SqliteStorageError) -> Self {
        err.into()
    }
}

impl StorageError for SqliteStorageError {}

impl Storage for SqliteStorage {

    type Error = SqliteStorageError;

    fn get(&self, pk: &PublicKeyHashable) -> Result<Option<TrustNode>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare("SELECT trustnode FROM trustnodes WHERE public_key = ?")?
            .cursor();

        cursor
            .bind(&[Value::String(format!("{}", pk))])?;

        match cursor.next().unwrap() {
            Some(r) => {
                log::info!("row: {:?}", r);
                let tn_bin: &[u8] = r[0]
                    .as_binary().ok_or(ConvertionError("cannot get trustnode as binary".to_string()))?;

                log::info!("binary: {:?}", tn_bin);

                let trust_node: TrustNode = rmp_serde::from_read_ref(tn_bin)?;

                log::info!("trustnode: {:?}", trust_node);

                Ok(Some(trust_node))
            }

            None => Ok(None),
        }
    }

    fn insert(&mut self, pk: PublicKeyHashable, node: TrustNode) -> Result<(), Self::Error> {
        let mut cursor = self
            .connection
            .prepare("INSERT OR REPLACE INTO trustnodes VALUES (?, ?)")?
            .cursor();

        let tn_vec = rmp_serde::to_vec(&node)?;

        log::info!("insert: {:?}", tn_vec);

        cursor
            .bind(&[Value::String(format!("{}", pk)), Value::Binary(tn_vec)])?;

        cursor.next()?;
        Ok({})
    }

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Result<Option<Weight>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare("SELECT public_key,weight FROM roots WHERE public_key = ?")?
            .cursor();

        cursor.bind(&[Value::String(format!("{}", pk))])?;

        if let Some(row) = cursor.next()? {
            log::info!("row: {:?}", row);

            let w = u32::try_from(row[1].as_integer().ok_or(ConvertionError("cannot get weight as integer".to_string()))?)
                .map_err(|e| Unexpected(format!("Unexpected. Cannot convert weight to u32: {}", e)))?;

            Ok(Some(w))
        } else {
            Ok(None)
        }
    }

    fn add_root_weight(&mut self, pk: PublicKeyHashable, weight: Weight) -> Result<(), Self::Error> {
        log::info!("add root: {} weight: {}", pk, weight);
        let mut cursor = self
            .connection
            .prepare("INSERT OR REPLACE INTO roots VALUES (?, ?)")?
            .cursor();

        cursor
            .bind(&[
                Value::String(format!("{}", pk)),
                Value::Integer(i64::from(weight)),
            ])?;

        cursor.next()?;
        Ok({})
    }

    fn root_keys(&self) -> Result<Vec<PublicKeyHashable>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare("SELECT public_key,weight FROM roots")?
            .cursor();

        let mut roots = vec![];

        while let Some(row) = cursor.next()? {
            log::info!("row: {:?}", row);
            let pk = row[0].as_string()
                .ok_or(ConvertionError("cannot get public key as binary".to_string()))?;
            let pk: PublicKeyHashable =
                PublicKeyHashable::from_str(pk).map_err(|e| DecodeError(e.to_string()))?;

            roots.push(pk)
        }

        Ok(roots)
    }

    fn revoke(&mut self, pk: &PublicKeyHashable, revoke: Revoke) -> Result<(), Self::Error> {
        match self.get(&pk)? {
            Some(mut trust_node) => {
                trust_node.update_revoke(revoke);
                self.insert(pk.clone(), trust_node)?;
                Ok(())
            }
            None => Err(RevokeError("There is no trust with such PublicKey".to_string())),
        }
    }

    fn update_auth(
        &mut self,
        pk: &PublicKeyHashable,
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
