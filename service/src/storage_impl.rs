// store list of trusts
// check if trust is already in list before adding
// if there is an older trust - don't add received trust

use crate::storage_impl::SQLiteStorageError::{
    FieldConversionDB, PublicKeyConversion, PublicKeyFromStr, PublicKeyNotFound,
    TrustNodeConversion, WeightConversionDB,
};

use core::convert::TryFrom;
use fluence_keypair::error::DecodingError;
use fluence_keypair::Signature;
use marine_sqlite_connector;
use marine_sqlite_connector::Connection;
use marine_sqlite_connector::Error as InternalSqliteError;
use marine_sqlite_connector::Value;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use rmp_serde::decode::Error as RmpDecodeError;
use rmp_serde::encode::Error as RmpEncodeError;
use std::convert::From;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;
use trust_graph::{
    Auth, PublicKeyHashable as PK, PublicKeyHashable, Revoke, Storage, StorageError, Trust,
    TrustGraph, TrustNode, TrustRelation, WeightFactor,
};

static INSTANCE: OnceCell<Mutex<TrustGraph<SQLiteStorage>>> = OnceCell::new();

static AUTH_TYPE: i64 = 0;
static REVOKE_TYPE: i64 = 1;

pub fn get_data() -> &'static Mutex<TrustGraph<SQLiteStorage>> {
    INSTANCE.get_or_init(|| {
        let db_path = "/tmp/users123123.sqlite";
        let connection = marine_sqlite_connector::open(db_path).unwrap();

        let init_sql = "CREATE TABLE IF NOT EXISTS trust_relations(
        relation_type INTEGER,
        issued_for TEXT,
        issued_by TEXT,
        issued_at INTEGER,
        expires_at INTEGER,
        signature TEXT,
        PRIMARY KEY(issued_for, issued_by)
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

    fn update_relation(
        &mut self,
        issued_for: &PK,
        relation: TrustRelation,
    ) -> Result<(), SQLiteStorageError> {
        match self.get_relation(issued_for, relation.issued_by().as_ref())? {
            Some(TrustRelation::Auth(auth)) => {
                if auth.trust.issued_at < relation.issued_at() {
                    self.insert(relation);
                }
            }

            Some(TrustRelation::Revoke(revoke)) => {
                if revoke.revoked_at < relation.issued_at() {
                    self.insert(relation);
                }
            }

            None => {
                self.insert(relation);
            }
        }

        Ok(())
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
    #[error("Cannot convert field  from DB")]
    FieldConversionDB,
    #[error("Cannot convert weight as integer from DB")]
    WeightConversionDB,
    #[error("Cannot convert public key as binary from DB")]
    PublicKeyConversion,
    #[error("Cannot convert trust node as binary from DB")]
    TrustNodeConversion,
    #[error("Cannot revoke. There is no trust with such PublicKey")]
    PublicKeyNotFound,
    #[error("Cannot decode signature from DB: {0}")]
    SignatureDecodeError(
        #[from]
        #[source]
        DecodingError,
    ),
}
fn parse_relation(row: &[Value]) -> Result<TrustRelation, SQLiteStorageError> {
    let relation_type = row[0].as_integer().ok_or(FieldConversionDB)?;
    let issued_for = PK::from_str(row[1].as_string().ok_or(FieldConversionDB)?)?;
    let issued_by = PK::from_str(row[2].as_string().ok_or(FieldConversionDB)?)?;
    let issued_at = Duration::from_secs(row[1].as_integer().ok_or(FieldConversionDB)? as u64);
    let expires_at = Duration::from_secs(row[2].as_integer().ok_or(FieldConversionDB)? as u64);
    let signature = Signature::decode(row[3].as_binary().ok_or(FieldConversionDB)?.to_vec())?;

    if relation_type == AUTH_TYPE {
        Ok(TrustRelation::Auth(Auth {
            trust: Trust {
                issued_for: issued_for.into(),
                expires_at,
                signature,
                issued_at,
            },
            issued_by: issued_by.into(),
        }))
    } else {
        Ok(TrustRelation::Revoke(Revoke {
            pk: issued_for.into(),
            revoked_at: issued_at,
            revoked_by: issued_by.into(),
            signature,
        }))
    }
}

impl From<SQLiteStorageError> for String {
    fn from(err: SQLiteStorageError) -> Self {
        err.into()
    }
}

impl StorageError for SQLiteStorageError {}

impl Storage for SQLiteStorage {
    type Error = SQLiteStorageError;

    fn get_relation(
        &self,
        issued_for: &PK,
        issued_by: &PK,
    ) -> Result<Option<TrustRelation>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare(
                "SELECT relation_type, issued_for, issued_by, issued_at, issued_at, expires_at, signature \
             FROM trust_relations WHERE issued_by = ? AND issued_for = ?",
            )?
            .cursor();

        cursor.bind(&[Value::String(format!("{}", issued_by))])?;
        cursor.bind(&[Value::String(format!("{}", issued_for))])?;

        if let Some(row) = cursor.next()? {
            parse_relation(row).map(Some)
        } else {
            Ok(None)
        }
    }

    /// return all auths issued for or by pk
    fn get_authorizations(&self, pk: &PublicKeyHashable) -> Result<Vec<Auth>, Self::Error> {
        let mut cursor = self
            .connection
            .prepare(
                "SELECT relation_type, issued_by, issued_for, issued_at, expires_at, signature \
             FROM trust_relations WHERE (issued_by = ? OR issued_for = ?) and relation_type = ?",
            )?
            .cursor();

        cursor.bind(&[Value::String(format!("{}", pk))])?;
        cursor.bind(&[Value::String(format!("{}", pk))])?;
        cursor.bind(&[Value::Integer(AUTH_TYPE)])?;

        let mut auths: Vec<Auth> = vec![];

        while let Some(row) = cursor.next()? {
            if let TrustRelation::Auth(auth) = parse_relation(row)? {
                auths.push(auth);
            }
        }

        Ok(auths)
    }

    fn insert(&mut self, relation: TrustRelation) -> Result<(), Self::Error> {
        let mut cursor = self
            .connection
            .prepare("INSERT OR REPLACE INTO trust_relations VALUES (?, ?, ?, ?, ?, ?)")?;

        let relation_type = match relation {
            TrustRelation::Auth(_) => AUTH_TYPE,
            TrustRelation::Revoke(_) => REVOKE_TYPE,
        };

        cursor.bind(1, &Value::Integer(relation_type))?;
        cursor.bind(
            2,
            &Value::String(format!("{}", relation.issued_for().as_ref())),
        )?;
        cursor.bind(
            3,
            &Value::String(format!("{}", relation.issued_by().as_ref())),
        )?;
        cursor.bind(4, &Value::Integer(relation.issued_at().as_secs() as i64))?;
        cursor.bind(5, &Value::Integer(relation.expires_at().as_secs() as i64))?;
        cursor.bind(6, &Value::Binary(relation.signature().encode()))?;

        cursor.next()?;
        Ok({})
    }

    fn get_root_weight_factor(&self, pk: &PK) -> Result<Option<WeightFactor>, Self::Error> {
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

    fn add_root_weight_factor(&mut self, pk: PK, weight: WeightFactor) -> Result<(), Self::Error> {
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
        self.update_relation(pk, TrustRelation::Revoke(revoke))
    }

    fn update_auth(
        &mut self,
        issued_for_pk: &PK,
        auth: Auth,
        _cur_time: Duration,
    ) -> Result<(), Self::Error> {
        self.update_relation(issued_for_pk, TrustRelation::Auth(auth))
    }

    fn remove_expired(&mut self, cur_time: Duration) -> Result<(), Self::Error> {
        let mut cursor = self
            .connection
            .prepare("DELETE FROM trust_relations WHERE expires_at < ?")?
            .cursor();

        cursor.bind(&[Value::Integer(cur_time.as_secs() as i64)])?;

        cursor.next()?;

        Ok(())
    }
}
