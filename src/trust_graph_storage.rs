use crate::public_key_hashable::PublicKeyHashable;
use crate::revoke::Revoke;
use crate::trust_graph::Weight;
use crate::trust_graph_storage::InMemoryStorageError::RevokeError;
use crate::trust_node::{Auth, TrustNode};
use fluence_identity::public_key::PublicKey;
use std::collections::HashMap;
use std::time::Duration;
use thiserror::Error as ThisError;

pub trait StorageError: std::error::Error {}

pub trait Storage {
    type Error: StorageError + Into<String>;

    fn get(&self, pk: &PublicKeyHashable) -> Result<Option<TrustNode>, Self::Error>;
    fn insert(&mut self, pk: PublicKeyHashable, node: TrustNode) -> Result<(), Self::Error>;

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Result<Option<Weight>, Self::Error>;
    fn add_root_weight(&mut self, pk: PublicKeyHashable, weight: Weight)
        -> Result<(), Self::Error>;
    fn root_keys(&self) -> Result<Vec<PublicKeyHashable>, Self::Error>;
    fn revoke(&mut self, pk: &PublicKeyHashable, revoke: Revoke) -> Result<(), Self::Error>;
    fn update_auth(
        &mut self,
        pk: &PublicKeyHashable,
        auth: Auth,
        issued_for: &PublicKey,
        cur_time: Duration,
    ) -> Result<(), Self::Error>;
}

#[derive(Debug, Default)]
pub struct InMemoryStorage {
    nodes: HashMap<PublicKeyHashable, TrustNode>,
    root_weights: HashMap<PublicKeyHashable, Weight>,
}

impl InMemoryStorage {
    #[allow(dead_code)]
    pub fn new_in_memory(root_weights: Vec<(PublicKey, Weight)>) -> Self {
        let root_weights = root_weights
            .into_iter()
            .map(|(k, w)| (k.into(), w))
            .collect();
        Self {
            nodes: HashMap::new(),
            root_weights: root_weights,
        }
    }

    #[allow(dead_code)]
    pub fn new() -> Self {
        InMemoryStorage {
            nodes: HashMap::new(),
            root_weights: HashMap::new(),
        }
    }
}

#[derive(ThisError, Debug)]
pub enum InMemoryStorageError {
    #[error("InMemoryStorageError::RevokeError {0:?}")]
    RevokeError(String),
}

impl From<InMemoryStorageError> for String {
    fn from(err: InMemoryStorageError) -> Self {
        err.into()
    }
}

impl StorageError for InMemoryStorageError {}

impl Storage for InMemoryStorage {
    type Error = InMemoryStorageError;

    fn get(&self, pk: &PublicKeyHashable) -> Result<Option<TrustNode>, Self::Error> {
        Ok(self.nodes.get(pk).cloned())
    }

    fn insert(&mut self, pk: PublicKeyHashable, node: TrustNode) -> Result<(), Self::Error> {
        &self.nodes.insert(pk, node);
        Ok(())
    }

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Result<Option<Weight>, Self::Error> {
        Ok(self.root_weights.get(pk).cloned())
    }

    fn add_root_weight(
        &mut self,
        pk: PublicKeyHashable,
        weight: Weight,
    ) -> Result<(), Self::Error> {
        &self.root_weights.insert(pk, weight);
        Ok({})
    }

    fn root_keys(&self) -> Result<Vec<PublicKeyHashable>, Self::Error> {
        Ok(self.root_weights.keys().cloned().map(Into::into).collect())
    }

    fn revoke(&mut self, pk: &PublicKeyHashable, revoke: Revoke) -> Result<(), Self::Error> {
        match self.nodes.get_mut(&pk) {
            Some(trust_node) => {
                trust_node.update_revoke(revoke);
                Ok(())
            }
            None => Err(RevokeError(
                "There is no trust with such PublicKey".to_string(),
            )),
        }
    }

    fn update_auth(
        &mut self,
        pk: &PublicKeyHashable,
        auth: Auth,
        issued_for: &PublicKey,
        cur_time: Duration,
    ) -> Result<(), InMemoryStorageError> {
        match self.nodes.get_mut(&pk) {
            Some(trust_node) => {
                trust_node.update_auth(auth);
                Ok({})
            }
            None => {
                let mut trust_node = TrustNode::new(issued_for.clone(), cur_time);
                trust_node.update_auth(auth);
                self.nodes.insert(pk.clone(), trust_node);
                Ok({})
            }
        }
    }
}
