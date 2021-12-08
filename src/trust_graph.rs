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

use crate::certificate::CertificateError::CertificateLengthError;
use crate::certificate::{Certificate, CertificateError};
use crate::chain::Chain;
use crate::public_key_hashable::PublicKeyHashable as PK;
use crate::revoke::Revocation;
use crate::revoke::RevokeError;
use crate::trust::Trust;
use crate::trust_graph::TrustGraphError::{
    CertificateCheckError, EmptyChain, InternalStorageError, NoRoot,
};
use crate::trust_graph_storage::Storage;
use crate::trust_relation::Auth;
use crate::{StorageError, TrustError};
use fluence_keypair::public_key::PublicKey;
use nonempty::NonEmpty;
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
    2u32.pow(MAX_WEIGHT_FACTOR.saturating_sub(wf))
}

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
        let next_weight = self.get_next_weight(
            issued_by.borrow().as_ref(),
            trust.borrow().issued_for.as_ref(),
            cur_time,
        )?;

        if next_weight == 0u32 {
            return Ok(0u32);
        }

        let auth = Auth {
            trust: trust.borrow().clone(),
            issued_by: issued_by.borrow().clone(),
        };

        self.storage.update_auth(auth, cur_time)?;

        Ok(next_weight)
    }

    /// Certificate is a chain of trusts, add this chain to graph
    pub fn add<C>(&mut self, cert: C, cur_time: Duration) -> Result<(), TrustGraphError>
    where
        C: Borrow<Certificate>,
    {
        let chain = &cert.borrow().chain;
        let mut issued_by = chain.get(0).ok_or(EmptyChain)?.issued_for.clone();

        // TODO: optimize to check only root weight
        for trust in chain {
            self.add_trust(trust, issued_by, cur_time)?;
            issued_by = trust.issued_for.clone();
        }

        Ok(())
    }

    fn get_next_weight(
        &mut self,
        issued_by: &PK,
        issued_for: &PK,
        cur_time: Duration,
    ) -> Result<u32, TrustGraphError> {
        let issued_by_weight = self.weight(issued_by.as_ref(), cur_time)?;

        // self-signed trust has same weight as max weight of issuer
        if issued_by.eq(issued_for) {
            Ok(issued_by_weight)
        } else {
            Ok(issued_by_weight / 2)
        }
    }

    /// Get the maximum weight of trust for one public key.
    pub fn weight<P>(&mut self, pk: P, cur_time: Duration) -> Result<u32, TrustGraphError>
    where
        P: Borrow<PublicKey>,
    {
        let mut max_weight = 0;
        if let Some(weight_factor) = self.storage.get_root_weight_factor(pk.borrow().as_ref())? {
            max_weight = get_weight_from_factor(weight_factor);
        }

        // get all possible certificates from the given public key to all roots in the graph
        let certs = self.get_all_certs(pk, cur_time)?;
        if let Some(weight_factor) = self.certificates_weight_factor(certs)? {
            max_weight = std::cmp::max(max_weight, get_weight_from_factor(weight_factor))
        }

        Ok(max_weight)
    }

    /// Calculate weight from given certificates
    /// Returns None if there is no such public key
    /// or some trust between this key and a root key is revoked.
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

            let root_weight_factor = self
                .storage
                .get_root_weight_factor(first.issued_for.as_ref())?
                .ok_or(NoRoot)?;

            // certificate weight_factor = root weight factor + 1 * every other element in the chain
            // (except root, so the formula is `root weight factor + chain length - 1`)
            weight_factor =
                std::cmp::min(weight_factor, root_weight_factor + c.chain.len() as u32 - 1)
        }

        Ok(Some(weight_factor))
    }

    /// BF search for all converging paths (chains) in the graph
    fn bf_search_paths(
        &self,
        pk: &PK,
        roots: HashSet<&PK>,
    ) -> Result<Vec<Vec<Auth>>, TrustGraphError> {
        // queue to collect all chains in the trust graph (each chain is a path in the trust graph)
        let mut chains_queue: VecDeque<Chain> = VecDeque::new();

        let node_auths: Vec<Auth> = self.storage.get_authorizations(pk)?;
        let node_revocations = self.storage.get_revocations(pk)?;

        // put all auth in the queue as the first possible paths through the graph
        for auth in node_auths {
            chains_queue.push_back(Chain::new(NonEmpty::new(auth), node_revocations.clone()));
        }

        // List of all chains that converge (terminate) to known roots
        let mut terminated_chains: Vec<Vec<Auth>> = Vec::new();

        while !chains_queue.is_empty() {
            let cur_chain = chains_queue
                .pop_front()
                .expect("`chains_queue` always has at least one element");

            let last = cur_chain.auths.last();

            let auths = self
                .storage
                .get_authorizations(&last.issued_by.clone().into())?;

            for auth in auths {
                // if there is auth, that we not visited in the current chain and no revocations to any chain member --  copy chain and append this auth
                if cur_chain.can_be_extended_by(&auth.issued_by) {
                    let mut new_chain = cur_chain.clone();
                    new_chain.add_revocations(
                        self.storage
                            .get_revocations(&auth.issued_by.clone().into())?,
                    );
                    new_chain.auths.push(auth);
                    chains_queue.push_back(new_chain);
                }
            }

            // to be considered a valid chain, the chain must:
            // - end with a self-signed trust
            // - that trust must converge to one of the roots
            // - there should be more than 1 trust in the chain
            let self_signed = last.issued_by == last.trust.issued_for;
            let issued_by: &PK = last.issued_by.as_ref();
            let converges_to_root = roots.contains(issued_by);

            if self_signed && converges_to_root && cur_chain.auths.len() > 1 {
                terminated_chains.push(cur_chain.auths.into());
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
        // garbage collect
        self.storage.remove_expired(cur_time)?;

        // maybe later we should retrieve root keys lazily
        let keys = self.storage.root_keys()?;
        let roots = keys.iter().collect();

        Ok(self
            .bf_search_paths(issued_for.borrow().as_ref(), roots)?
            .into_iter()
            .map(|auths| {
                let trusts: Vec<Trust> = auths.into_iter().map(|auth| auth.trust).rev().collect();
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
            .collect())
    }

    /// Mark public key as revoked.
    /// Every chain that contains path from `revoked_by` to revoked `pk`
    /// will be excluded from valid certificates until revocation canceled by giving trust
    pub fn revoke(&mut self, revocation: Revocation) -> Result<(), TrustGraphError> {
        Revocation::verify(&revocation)?;

        Ok(self.storage.revoke(revocation)?)
    }
}
