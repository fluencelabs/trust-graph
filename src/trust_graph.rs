/*
 * Copyright 2020 Fluence Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::certificate::CertificateError::{CertificateLengthError, Unexpected};
use crate::certificate::{Certificate, CertificateError};
use crate::public_key_hashable::PublicKeyHashable as PK;
use crate::revoke::Revoke;
use crate::revoke::RevokeError;
use crate::trust::Trust;
use crate::trust_graph::TrustGraphError::{
    CertificateCheckError, EmptyChain, InternalStorageError, NoRoot,
};
use crate::trust_graph_storage::Storage;
use crate::trust_node::{Auth, TrustNode};
use crate::{StorageError, TrustError};
use fluence_keypair::public_key::PublicKey;
use std::borrow::Borrow;
use std::collections::{HashSet, VecDeque};
use std::convert::{From, Into};
use std::result::Result;
use std::time::Duration;
use thiserror::Error as ThisError;

/// for simplicity, we store `n` where Weight = 1/n^2
pub type WeightFactor = u32;

pub static MAX_WEIGHT_FACTOR: u32 = 16;

/// Graph to efficiently calculate weights of certificates and get chains of certificates.
/// TODO serialization/deserialization
/// TODO export a certificate from graph
#[allow(dead_code)]
pub struct TrustGraph<S>
where
    S: Storage,
{
    storage: S,
}

#[derive(ThisError, Debug)]
pub enum TrustGraphError {
    #[error("Internal storage error: {0}")]
    InternalStorageError(Box<dyn StorageError>),
    #[error("There is no root for this certificate.")]
    NoRoot,
    #[error("Chain is empty")]
    EmptyChain,
    #[error("Certificate check error: {0}")]
    CertificateCheckError(
        #[from]
        #[source]
        CertificateError,
    ),
    #[error("Error on revoking a trust: {0}")]
    RevokeCheckError(
        #[from]
        #[source]
        RevokeError,
    ),
    #[error("Path to {0} not found")]
    AddTrustError(String),
    #[error("Trust verification error: {0}")]
    TrustVerificationError(
        #[from]
        #[source]
        TrustError,
    ),
}

impl<T: StorageError + 'static> From<T> for TrustGraphError {
    fn from(err: T) -> Self {
        InternalStorageError(Box::new(err))
    }
}

impl From<TrustGraphError> for String {
    fn from(err: TrustGraphError) -> Self {
        format!("{}", err)
    }
}

pub fn get_weight_from_factor(wf: WeightFactor) -> u32 {
    2u32.pow(MAX_WEIGHT_FACTOR - wf)
}

#[allow(dead_code)]
impl<S> TrustGraph<S>
where
    S: Storage,
{
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Insert new root weight
    pub fn add_root_weight_factor(
        &mut self,
        pk: PublicKey,
        weight: WeightFactor,
    ) -> Result<(), TrustGraphError> {
        Ok(self.storage.add_root_weight_factor(pk.into(), weight)?)
    }

    /// Get trust by public key
    pub fn get(&self, pk: PublicKey) -> Result<Option<TrustNode>, TrustGraphError> {
        Ok(self.storage.get(&pk.into())?)
    }

    pub fn add_trust<T, P>(
        &mut self,
        trust: T,
        issued_by: P,
        cur_time: Duration,
    ) -> Result<u32, TrustGraphError>
    where
        T: Borrow<Trust>,
        P: Borrow<PublicKey>,
    {
        Trust::verify(trust.borrow(), issued_by.borrow(), cur_time)?;

        let issued_by_weight = self.weight(issued_by.borrow().clone().borrow(), cur_time)?;

        if issued_by_weight == 0u32 {
            return Ok(0u32);
        }

        let pk = trust.borrow().issued_for.clone().into();

        let auth = Auth {
            trust: trust.borrow().clone(),
            issued_by: issued_by.borrow().clone(),
        };

        self.storage.update_auth(&pk, auth, cur_time)?;

        Ok(issued_by_weight / 2)
    }

    /// Certificate is a chain of trusts, add this chain to graph
    pub fn add<C>(&mut self, cert: C, cur_time: Duration) -> Result<(), TrustGraphError>
    where
        C: Borrow<Certificate>,
    {
        let chain = &cert.borrow().chain;
        let mut issued_by = chain.get(0).ok_or(EmptyChain)?.issued_for.clone();

        for trust in chain {
            self.add_trust(trust, issued_by, cur_time)?;
            issued_by = trust.issued_for.clone();
        }

        Ok(())
    }

    /// Get the maximum weight of trust for one public key.
    pub fn weight<P>(&mut self, pk: P, cur_time: Duration) -> Result<u32, TrustGraphError>
    where
        P: Borrow<PublicKey>,
    {
        if let Some(weight_factor) = self.storage.get_root_weight_factor(pk.borrow().as_ref())? {
            return Ok(get_weight_from_factor(weight_factor));
        }

        // get all possible certificates from the given public key to all roots in the graph
        let certs = self.get_all_certs(pk, cur_time)?;
        self.certificates_weight_factor(certs)
            .map(|wf| wf.map(get_weight_from_factor).unwrap_or(0u32))
    }

    /// Calculate weight from given certificates
    /// Returns None if there is no such public key
    /// or some trust between this key and a root key is revoked.
    /// TODO handle non-direct revocations
    pub fn certificates_weight_factor<C, I>(
        &self,
        certs: I,
    ) -> Result<Option<WeightFactor>, TrustGraphError>
    where
        C: Borrow<Certificate>,
        I: IntoIterator<Item = C>,
    {
        let mut certs = certs.into_iter().peekable();
        // if there are no certificates for the given public key, there is no info about this public key
        // or some elements of possible certificate chains was revoked
        if certs.peek().is_none() {
            return Ok(None);
        }

        let mut weight_factor = u32::MAX;

        for cert in certs {
            let c = cert.borrow();

            let first = c
                .chain
                .first()
                .ok_or(CertificateCheckError(CertificateLengthError))?;

            let root_weight = self
                .storage
                .get_root_weight_factor(first.issued_for.as_ref())?
                .ok_or(NoRoot)?;

            // certificate weight = root weight + 1 * every other element in the chain
            // (except root, so the formula is `root weight + chain length - 1`)
            weight_factor = std::cmp::min(weight_factor, root_weight + c.chain.len() as u32 - 1)
        }

        Ok(Some(weight_factor))
    }

    /// BF search for all converging paths (chains) in the graph
    /// TODO could be optimized with closure, that will calculate the weight on the fly
    /// TODO or store auths to build certificates
    fn bf_search_paths(
        &self,
        node: &TrustNode,
        roots: HashSet<&PK>,
        cur_time: Duration,
    ) -> Result<Vec<Vec<Auth>>, TrustGraphError> {
        // queue to collect all chains in the trust graph (each chain is a path in the trust graph)
        let mut chains_queue: VecDeque<Vec<Auth>> = VecDeque::new();

        let node_auths: Vec<Auth> = node
            .authorizations()
            .cloned()
            .filter(|auth| auth.trust.expires_at > cur_time)
            .collect();
        // put all auth in the queue as the first possible paths through the graph
        for auth in node_auths {
            chains_queue.push_back(vec![auth]);
        }

        // List of all chains that converge (terminate) to known roots
        let mut terminated_chains: Vec<Vec<Auth>> = Vec::new();

        while !chains_queue.is_empty() {
            let cur_chain = chains_queue
                .pop_front()
                .expect("`chains_queue` always has at least one element");

            let last = cur_chain
                .last()
                .expect("`cur_chain` always has at least one element");

            let auths: Vec<Auth> = self
                .storage
                .get(&last.issued_by.clone().into())?
                .ok_or(CertificateCheckError(Unexpected))?
                .authorizations()
                .cloned()
                .filter(|auth| auth.trust.expires_at > cur_time)
                .collect();

            for auth in auths {
                // if there is auth, that we not visited in the current chain, copy chain and append this auth
                if !cur_chain
                    .iter()
                    .any(|a| a.trust.issued_for == auth.issued_by)
                {
                    let mut new_chain = cur_chain.clone();
                    new_chain.push(auth);
                    chains_queue.push_back(new_chain);
                }
            }

            // to be considered a valid chain, the chain must:
            // - end with a self-signed trust
            // - that trust must converge to one of the root weights
            // - there should be more than 1 trust in the chain
            let self_signed = last.issued_by == last.trust.issued_for;
            let issued_by: &PK = last.issued_by.as_ref();
            let converges_to_root = roots.contains(issued_by);

            if self_signed && converges_to_root && cur_chain.len() > 1 {
                terminated_chains.push(cur_chain);
            }
        }

        Ok(terminated_chains)
    }

    /// Get all possible certificates where `issued_for` will be the last element of the chain
    /// and one of the destinations is the root of this chain.
    pub fn get_all_certs<P>(
        &mut self,
        issued_for: P,
        cur_time: Duration,
    ) -> Result<Vec<Certificate>, TrustGraphError>
    where
        P: Borrow<PublicKey>,
    {
        self.storage.remove_expired(cur_time)?;
        // get all auths (edges) for issued public key
        let issued_for_node = self.storage.get(issued_for.borrow().as_ref())?;

        let keys = self.storage.root_keys()?;
        let roots = keys.iter().collect();

        match issued_for_node {
            Some(node) => Ok(self
                .bf_search_paths(&node, roots, cur_time)?
                .iter()
                .map(|auths| {
                    // TODO: can avoid cloning here by returning &Certificate
                    let trusts: Vec<Trust> =
                        auths.iter().map(|auth| auth.trust.clone()).rev().collect();
                    Certificate::new_unverified(trusts)
                })
                .filter(|c| {
                    // Certificate with one trust means nothing, gotta be a bug. Checking for it here.
                    debug_assert!(
                        c.chain.len() > 1,
                        "certificate with chain of len 1 arose: {:#?}",
                        c
                    );
                    c.chain.len() > 1
                })
                .collect()),
            None => Ok(Vec::new()),
        }
    }

    /// Mark public key as revoked.
    pub fn revoke(&mut self, revoke: Revoke) -> Result<(), TrustGraphError> {
        Revoke::verify(&revoke)?;

        let pk: PK = revoke.pk.clone().into();

        Ok(self.storage.revoke(&pk, revoke)?)
    }

    /// Check information about new certificates and about revoked certificates.
    /// Do it once per some time
    // TODO
    fn maintain() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::misc::current_time;
    use crate::trust_graph_storage::InMemoryStorage;
    use failure::_core::time::Duration;
    use fluence_keypair::key_pair::KeyPair;
    use std::collections::HashMap;

    pub fn one_minute() -> Duration {
        Duration::new(60, 0)
    }

    fn generate_root_cert() -> (KeyPair, KeyPair, Certificate) {
        let root_kp = KeyPair::generate_ed25519();
        let second_kp = KeyPair::generate_ed25519();

        let cur_time = current_time();

        (
            root_kp.clone(),
            second_kp.clone(),
            Certificate::issue_root(
                &root_kp,
                second_kp.public(),
                cur_time.checked_add(one_minute()).unwrap(),
                cur_time,
            ),
        )
    }

    fn generate_cert_with(
        len: usize,
        // Map of index to keypair. These key pairs will be used in trust chains at the given indexes
        keys: HashMap<usize, KeyPair>,
        expires_at: Duration,
        issued_at: Duration,
    ) -> Result<(Vec<KeyPair>, Certificate), TrustGraphError> {
        assert!(len > 2);

        let root_kp = KeyPair::generate_ed25519();
        let second_kp = KeyPair::generate_ed25519();

        let mut cert = Certificate::issue_root(&root_kp, second_kp.public(), expires_at, issued_at);

        let mut key_pairs = vec![root_kp, second_kp];

        for idx in 2..len {
            let kp = keys
                .get(&idx)
                .unwrap_or(&KeyPair::generate_ed25519())
                .clone();
            let previous_kp = &key_pairs[idx - 1];
            cert = Certificate::issue(
                &previous_kp,
                kp.public(),
                &cert,
                expires_at,
                issued_at,
                current_time(),
            )?;
            key_pairs.push(kp);
        }

        Ok((key_pairs, cert))
    }

    fn generate_cert_with_len(
        len: usize,
        keys: HashMap<usize, KeyPair>,
    ) -> Result<(Vec<KeyPair>, Certificate), TrustGraphError> {
        let cur_time = current_time();
        let far_future = cur_time.checked_add(one_minute()).unwrap();

        generate_cert_with(len, keys, far_future, cur_time)
    }

    #[test]
    fn test_add_cert() {
        let (root, _, cert) = generate_root_cert();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        graph
            .add_root_weight_factor(root.public().into(), 0)
            .unwrap();

        let addition = graph.add(cert, current_time());
        assert_eq!(addition.is_ok(), true);
    }

    #[test]
    fn test_add_certs_with_same_trusts_and_different_expirations_ed25519() {
        let cur_time = current_time();
        let far_future = cur_time + Duration::from_secs(10);
        let far_far_future = cur_time + Duration::from_secs(900);
        let key_pair1 = KeyPair::generate_ed25519();
        let key_pair2 = KeyPair::generate_ed25519();

        // Use key_pair1 and key_pair2 for 5th and 6th trust in the cert chain
        let mut chain_keys = HashMap::new();
        chain_keys.insert(5, key_pair1.clone());
        chain_keys.insert(6, key_pair2.clone());

        let (key_pairs1, cert1) =
            generate_cert_with(10, chain_keys, far_future * 2, far_future).expect("");

        // Use key_pair1 and key_pair2 for 7th and 8th trust in the cert chain
        let mut chain_keys = HashMap::new();
        chain_keys.insert(7, key_pair1.clone());
        chain_keys.insert(8, key_pair2.clone());

        let (key_pairs2, cert2) =
            generate_cert_with(10, chain_keys, far_far_future * 2, far_far_future).unwrap();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root1_pk = key_pairs1[0].public();
        let root2_pk = key_pairs2[0].public();
        graph.add_root_weight_factor(root1_pk.into(), 1).unwrap();
        graph.add_root_weight_factor(root2_pk.into(), 0).unwrap();
        graph.add(cert1, cur_time).unwrap();

        let node2 = graph.get(key_pair2.public()).unwrap().unwrap();
        let auth_by_kp1 = node2
            .authorizations()
            .find(|a| a.issued_by == key_pair1.public())
            .unwrap();

        assert_eq!(auth_by_kp1.trust.expires_at, far_future * 2);

        graph.add(cert2, cur_time).unwrap();

        let node2 = graph.get(key_pair2.public()).unwrap().unwrap();
        let auth_by_kp1 = node2
            .authorizations()
            .find(|a| a.issued_by == key_pair1.public())
            .unwrap();

        assert_eq!(auth_by_kp1.trust.expires_at, far_far_future * 2);
    }

    #[test]
    fn test_one_cert_in_graph() {
        let (key_pairs, cert1) = generate_cert_with_len(10, HashMap::new()).unwrap();
        let last_trust = cert1.chain[9].clone();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);

        let root_pk = key_pairs[0].public();
        graph.add_root_weight_factor(root_pk.into(), 1).unwrap();

        graph.add(cert1, current_time()).unwrap();

        let root_weight = get_weight_from_factor(1);
        let w1 = graph.weight(key_pairs[0].public(), current_time()).unwrap();
        assert_eq!(w1, root_weight * 2u32.pow(0));

        let w2 = graph.weight(key_pairs[1].public(), current_time()).unwrap();
        assert_eq!(w2, root_weight / 2u32.pow(1));

        let w3 = graph.weight(key_pairs[9].public(), current_time()).unwrap();
        assert_eq!(w3, root_weight / 2u32.pow(9));

        let node = graph.get(key_pairs[9].public()).unwrap().unwrap();
        let auths: Vec<&Auth> = node.authorizations().collect();

        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0].trust, last_trust);
    }

    #[test]
    fn test_cycles_in_graph() {
        let key_pair1 = KeyPair::generate_ed25519();
        let key_pair2 = KeyPair::generate_ed25519();
        let key_pair3 = KeyPair::generate_ed25519();

        let mut chain_keys = HashMap::new();
        chain_keys.insert(3, key_pair1.clone());
        chain_keys.insert(5, key_pair2.clone());
        chain_keys.insert(7, key_pair3.clone());

        let (key_pairs1, cert1) = generate_cert_with_len(10, chain_keys).unwrap();

        let mut chain_keys = HashMap::new();
        chain_keys.insert(7, key_pair1.clone());
        chain_keys.insert(6, key_pair2.clone());
        chain_keys.insert(5, key_pair3.clone());

        let (key_pairs2, cert2) = generate_cert_with_len(10, chain_keys).unwrap();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root1_pk = key_pairs1[0].public();
        let root2_pk = key_pairs2[0].public();
        graph.add_root_weight_factor(root1_pk.into(), 1).unwrap();
        graph.add_root_weight_factor(root2_pk.into(), 0).unwrap();

        let last_pk1 = cert1.chain[9].issued_for.clone();
        let last_pk2 = cert2.chain[9].issued_for.clone();

        graph.add(cert1, current_time()).unwrap();
        graph.add(cert2, current_time()).unwrap();

        let revoke1 = Revoke::create(
            &key_pairs1[3],
            key_pairs1[4].public(),
            current_time().checked_add(one_minute()).unwrap(),
        );
        graph.revoke(revoke1).unwrap();
        let revoke2 = Revoke::create(
            &key_pairs2[5],
            key_pairs2[6].public(),
            current_time().checked_add(one_minute()).unwrap(),
        );
        graph.revoke(revoke2).unwrap();

        let w1 = graph.weight(key_pair1.public(), current_time()).unwrap();
        // all upper trusts are revoked for this public key
        let w2 = graph.weight(key_pair2.public(), current_time()).unwrap();
        let w3 = graph.weight(key_pair3.public(), current_time()).unwrap();
        let w_last1 = graph.weight(last_pk1, current_time()).unwrap();
        let w_last2 = graph.weight(last_pk2, current_time()).unwrap();

        assert_eq!(w1, get_weight_from_factor(4));
        assert_eq!(w2, 0); // revoked
        assert_eq!(w3, get_weight_from_factor(5));
        assert_eq!(w_last1, get_weight_from_factor(7));
        assert_eq!(w_last2, get_weight_from_factor(6));
    }

    #[test]
    fn test_get_one_cert() {
        let (key_pairs, cert) = generate_cert_with_len(5, HashMap::new()).unwrap();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root1_pk = key_pairs[0].public();
        graph
            .add_root_weight_factor(root1_pk.clone().into(), 1)
            .unwrap();

        graph.add(cert.clone(), current_time()).unwrap();

        let certs = graph
            .get_all_certs(key_pairs.last().unwrap().public(), current_time())
            .unwrap();

        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert);
    }

    #[test]
    fn test_chain_from_root_to_another_root() {
        let (_, cert) = generate_cert_with_len(6, HashMap::new()).unwrap();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        // add first and last trusts as roots
        graph
            .add_root_weight_factor(cert.chain[0].clone().issued_for.into(), 1)
            .unwrap();
        graph
            .add_root_weight_factor(cert.chain[3].clone().issued_for.into(), 1)
            .unwrap();
        graph
            .add_root_weight_factor(cert.chain[5].clone().issued_for.into(), 1)
            .unwrap();

        graph.add(cert.clone(), current_time()).unwrap();

        let t = cert.chain[5].clone();
        let certs = graph.get_all_certs(t.issued_for, current_time()).unwrap();

        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_find_certs() {
        let key_pair1 = KeyPair::generate_ed25519();
        let key_pair2 = KeyPair::generate_ed25519();
        let key_pair3 = KeyPair::generate_ed25519();

        let mut chain_keys = HashMap::new();
        chain_keys.insert(2, key_pair1.clone());
        chain_keys.insert(3, key_pair2.clone());
        chain_keys.insert(4, key_pair3.clone());

        let (key_pairs1, cert1) = generate_cert_with_len(5, chain_keys).unwrap();

        let mut chain_keys = HashMap::new();
        chain_keys.insert(4, key_pair1.clone());
        chain_keys.insert(3, key_pair2.clone());
        chain_keys.insert(2, key_pair3.clone());

        let (key_pairs2, cert2) = generate_cert_with_len(5, chain_keys).unwrap();

        let mut chain_keys = HashMap::new();
        chain_keys.insert(3, key_pair1.clone());
        chain_keys.insert(4, key_pair2.clone());
        chain_keys.insert(2, key_pair3.clone());

        let (key_pairs3, cert3) = generate_cert_with_len(5, chain_keys).unwrap();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root1_pk = key_pairs1[0].public();
        let root2_pk = key_pairs2[0].public();
        let root3_pk = key_pairs3[0].public();
        graph
            .add_root_weight_factor(root1_pk.clone().into(), 1)
            .unwrap();
        graph
            .add_root_weight_factor(root2_pk.clone().into(), 0)
            .unwrap();
        graph
            .add_root_weight_factor(root3_pk.clone().into(), 0)
            .unwrap();

        graph.add(cert1, current_time()).unwrap();
        graph.add(cert2, current_time()).unwrap();
        graph.add(cert3, current_time()).unwrap();

        let certs1 = graph
            .get_all_certs(key_pair1.public(), current_time())
            .unwrap();
        let lenghts1: Vec<usize> = certs1.iter().map(|c| c.chain.len()).collect();
        let check_lenghts1: Vec<usize> = vec![3, 4, 4, 5, 5];
        assert_eq!(lenghts1, check_lenghts1);

        let certs2 = graph
            .get_all_certs(key_pair2.public(), current_time())
            .unwrap();
        let lenghts2: Vec<usize> = certs2.iter().map(|c| c.chain.len()).collect();
        let check_lenghts2: Vec<usize> = vec![4, 4, 4, 5, 5];
        assert_eq!(lenghts2, check_lenghts2);

        let certs3 = graph
            .get_all_certs(key_pair3.public(), current_time())
            .unwrap();
        let lenghts3: Vec<usize> = certs3.iter().map(|c| c.chain.len()).collect();
        let check_lenghts3: Vec<usize> = vec![3, 3, 5];
        assert_eq!(lenghts3, check_lenghts3);
    }

    #[test]
    fn test_add_one_trust_to_cert_last() {
        let (key_pairs, mut cert) = generate_cert_with_len(5, HashMap::new()).unwrap();
        let cur_time = current_time();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root_pk = key_pairs[0].public();
        graph
            .add_root_weight_factor(root_pk.clone().into(), 2)
            .unwrap();
        graph.add(cert.clone(), cur_time).unwrap();

        let issued_by = key_pairs.last().unwrap();
        let trust_kp = KeyPair::generate_ed25519();
        let trust = Trust::create(
            issued_by,
            trust_kp.public(),
            cur_time.checked_add(one_minute()).unwrap(),
            cur_time,
        );

        let weight = graph
            .add_trust(trust.clone(), issued_by.public(), cur_time)
            .unwrap();
        assert_eq!(
            weight,
            graph.weight(issued_by.public(), current_time()).unwrap() / 2
        );

        cert.chain.push(trust);

        let certs = graph
            .get_all_certs(trust_kp.public(), current_time())
            .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert);
    }

    #[test]
    fn test_add_one_trust_to_cert_after_root() {
        let (key_pairs, cert) = generate_cert_with_len(5, HashMap::new()).unwrap();
        let cur_time = current_time();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root1_pk = key_pairs[0].public();
        graph
            .add_root_weight_factor(root1_pk.clone().into(), 2)
            .unwrap();
        graph.add(cert.clone(), cur_time).unwrap();

        let issued_by = key_pairs.first().unwrap();
        let trust_kp = KeyPair::generate_ed25519();
        let trust = Trust::create(
            issued_by,
            trust_kp.public(),
            cur_time.checked_add(one_minute()).unwrap(),
            cur_time,
        );

        let weight = graph
            .add_trust(trust.clone(), issued_by.public(), cur_time)
            .unwrap();
        assert_eq!(
            weight,
            graph.weight(issued_by.public(), current_time()).unwrap() / 2
        );

        let target_cert = Certificate {
            chain: vec![cert.chain[0].clone(), trust],
        };

        let certs = graph
            .get_all_certs(trust_kp.public(), current_time())
            .unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], target_cert);
    }

    #[test]
    fn test_revoke_weight() {
        let (key_pairs, cert) = generate_cert_with_len(5, HashMap::new()).unwrap();
        let cur_time = current_time();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root_pk = key_pairs[0].public();
        graph
            .add_root_weight_factor(root_pk.clone().into(), 2)
            .unwrap();
        graph.add(cert.clone(), cur_time).unwrap();

        let revoked_by = &key_pairs[3];
        let revoked = &key_pairs[4];
        let revoke = Revoke::create(
            revoked_by,
            revoked.public(),
            cur_time.checked_add(one_minute()).unwrap(),
        );

        graph.revoke(revoke.clone()).unwrap();
        assert_eq!(0, graph.weight(revoked.public(), current_time()).unwrap());
    }

    #[test]
    fn test_expired_trust() {
        let (key_pairs, mut cert) = generate_cert_with_len(5, HashMap::new()).unwrap();
        let cur_time = current_time();

        let st = InMemoryStorage::new();
        let mut graph = TrustGraph::new(st);
        let root1_pk = key_pairs[0].public();
        graph
            .add_root_weight_factor(root1_pk.clone().into(), 2)
            .unwrap();
        graph.add(cert.clone(), cur_time).unwrap();

        let issued_by = key_pairs.last().unwrap();
        let trust_kp = KeyPair::generate_ed25519();
        let expired_time = cur_time.checked_add(one_minute()).unwrap();
        let trust = Trust::create(issued_by, trust_kp.public(), expired_time, cur_time);

        let weight = graph
            .add_trust(trust.clone(), issued_by.public(), cur_time)
            .unwrap();
        assert_eq!(
            weight,
            graph.weight(issued_by.public(), cur_time).unwrap() / 2
        );

        cert.chain.push(trust);

        let certs = graph.get_all_certs(trust_kp.public(), cur_time).unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0], cert);

        let certs = graph
            .get_all_certs(trust_kp.public(), expired_time)
            .unwrap();
        assert_eq!(certs.len(), 0);
    }
}
