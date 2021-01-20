use crate::public_key_hashable::PublicKeyHashable;
use crate::revoke::Revoke;
use crate::trust_graph::Weight;
use crate::trust_node::{Auth, TrustNode};
use fluence_identity::public_key::PublicKey;
use std::collections::HashMap;
use std::time::Duration;

pub trait Storage {
    fn get(&self, pk: &PublicKeyHashable) -> Option<TrustNode>;
    fn insert(&mut self, pk: PublicKeyHashable, node: TrustNode);

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Option<&Weight>;
    fn add_root_weight(&mut self, pk: PublicKeyHashable, weight: Weight);
    fn root_keys(&self) -> Vec<PublicKeyHashable>;
    fn revoke(&mut self, pk: &PublicKeyHashable, revoke: Revoke) -> Result<(), String>;
    fn update_auth(
        &mut self,
        pk: &PublicKeyHashable,
        auth: Auth,
        issued_for: &PublicKey,
        cur_time: Duration,
    );
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

impl Storage for InMemoryStorage {
    fn get(&self, pk: &PublicKeyHashable) -> Option<TrustNode> {
        self.nodes.get(pk).cloned()
    }

    fn insert(&mut self, pk: PublicKeyHashable, node: TrustNode) {
        &self.nodes.insert(pk, node);
    }

    fn get_root_weight(&self, pk: &PublicKeyHashable) -> Option<&Weight> {
        self.root_weights.get(pk)
    }

    fn add_root_weight(&mut self, pk: PublicKeyHashable, weight: Weight) {
        &self.root_weights.insert(pk, weight);
    }

    fn root_keys(&self) -> Vec<PublicKeyHashable> {
        self.root_weights.keys().cloned().map(Into::into).collect()
    }

    fn revoke(&mut self, pk: &PublicKeyHashable, revoke: Revoke) -> Result<(), String> {
        match self.nodes.get_mut(&pk) {
            Some(trust_node) => {
                trust_node.update_revoke(revoke);
                Ok(())
            }
            None => Err("There is no trust with such PublicKey".to_string()),
        }
    }

    fn update_auth(
        &mut self,
        pk: &PublicKeyHashable,
        auth: Auth,
        issued_for: &PublicKey,
        cur_time: Duration,
    ) {
        match self.nodes.get_mut(&pk) {
            Some(trust_node) => {
                trust_node.update_auth(auth);
            }
            None => {
                let mut trust_node = TrustNode::new(issued_for.clone(), cur_time);
                trust_node.update_auth(auth);
                self.nodes.insert(pk.clone(), trust_node);
            }
        }
    }
}
