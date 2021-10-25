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

use crate::public_key_hashable::PublicKeyHashable;
use crate::revoke::Revoke;
use crate::trust::Trust;
use failure::_core::time::Duration;
use fluence_keypair::public_key::PublicKey;
use fluence_keypair::Signature;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustRelation {
    Auth(Auth),
    Revoke(Revoke),
}

impl TrustRelation {
    /// Returns timestamp of when this relation was created
    pub fn issued_at(&self) -> Duration {
        match self {
            TrustRelation::Auth(auth) => auth.trust.issued_at,
            TrustRelation::Revoke(revoke) => revoke.revoked_at,
        }
    }

    /// Returns public key of the creator of this relation
    pub fn issued_by(&self) -> &PublicKey {
        match self {
            TrustRelation::Auth(auth) => &auth.issued_by,
            TrustRelation::Revoke(revoke) => &revoke.revoked_by,
        }
    }

    pub fn issued_for(&self) -> &PublicKey {
        match self {
            TrustRelation::Auth(auth) => &auth.trust.issued_for,
            TrustRelation::Revoke(revoke) => &revoke.pk,
        }
    }

    pub fn expires_at(&self) -> Duration {
        match self {
            TrustRelation::Auth(auth) => auth.trust.expires_at,
            TrustRelation::Revoke(_) => Duration::from_secs(0),
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            TrustRelation::Auth(auth) => &auth.trust.signature,
            TrustRelation::Revoke(revoke) => &revoke.signature,
        }
    }
}

/// Represents who give a trust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    /// proof of this authorization
    pub trust: Trust,
    /// the issuer of this authorization
    pub issued_by: PublicKey,
}

/// An element of trust graph that store relations (trust or revoke)
/// that given by some owners of public keys.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TrustNode {
    /// identity key of this element
    pub pk: PublicKey,

    /// one public key could be authorized or revoked by multiple certificates
    #[serde_as(as = "Vec<(_, _)>")]
    trust_relations: HashMap<PublicKeyHashable, TrustRelation>,

    /// for maintain
    pub verified_at: Duration,
}

#[allow(dead_code)]
impl TrustNode {
    pub fn new(pk: PublicKey, verified_at: Duration) -> Self {
        Self {
            pk,
            trust_relations: HashMap::new(),
            verified_at,
        }
    }

    pub fn get_auth(&self, pk: PublicKey) -> Option<Auth> {
        match self.trust_relations.get(&pk.into()) {
            Some(TrustRelation::Auth(auth)) => Some(auth.clone()),
            _ => None,
        }
    }

    pub fn get_revoke(&self, pk: PublicKey) -> Option<Revoke> {
        match self.trust_relations.get(&pk.into()) {
            Some(TrustRelation::Revoke(rev)) => Some(rev.clone()),
            _ => None,
        }
    }

    pub fn authorizations(&self) -> impl Iterator<Item = &Auth> + '_ {
        self.trust_relations.values().filter_map(|tr| {
            if let TrustRelation::Auth(auth) = tr {
                Some(auth)
            } else {
                None
            }
        })
    }

    pub fn revocations(&self) -> impl Iterator<Item = &Revoke> + '_ {
        self.trust_relations.values().filter_map(|tr| {
            if let TrustRelation::Revoke(revoke) = tr {
                Some(revoke)
            } else {
                None
            }
        })
    }

    /// Adds authorization. If the trust node already has this authorization,
    /// add auth with later expiration date.
    pub fn update_auth(&mut self, auth: Auth) {
        self.update_relation(TrustRelation::Auth(auth));
    }

    // insert new trust relation, ignore if there is another one with same public key
    fn insert(&mut self, pk: PublicKeyHashable, tr: TrustRelation) {
        self.trust_relations.insert(pk, tr);
    }

    fn update_relation(&mut self, relation: TrustRelation) {
        let issued_by = relation.issued_by().as_ref();

        match self.trust_relations.get(issued_by) {
            Some(TrustRelation::Auth(auth)) => {
                if auth.trust.issued_at < relation.issued_at() {
                    self.insert(issued_by.clone(), relation)
                }
            }
            Some(TrustRelation::Revoke(existed_revoke)) => {
                if existed_revoke.revoked_at < relation.issued_at() {
                    self.insert(issued_by.clone(), relation)
                }
            }
            None => self.insert(issued_by.clone(), relation),
        };
    }

    pub fn update_revoke(&mut self, revoke: Revoke) {
        self.update_relation(TrustRelation::Revoke(revoke));
    }

    pub fn remove_expired(&mut self, cur_time: Duration) {
        self.trust_relations.retain(|_, tr| {
            if let TrustRelation::Auth(auth) = tr {
                auth.trust.expires_at > cur_time
            } else {
                true
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use fluence_keypair::key_pair::KeyPair;

    use super::*;

    #[test]
    fn test_auth_and_revoke_trust_node() {
        let kp = KeyPair::generate_ed25519();

        let now = Duration::new(50, 0);
        let past = Duration::new(5, 0);
        let future = Duration::new(500, 0);

        let mut trust_node = TrustNode {
            pk: kp.public(),
            trust_relations: HashMap::new(),
            verified_at: now,
        };

        let truster = KeyPair::generate_ed25519();

        let revoke = Revoke::create(&truster, kp.public(), now);

        trust_node.update_revoke(revoke);

        assert!(trust_node.get_revoke(truster.public()).is_some());

        let old_trust = Trust::create(&truster, kp.public(), Duration::new(60, 0), past);

        let old_auth = Auth {
            trust: old_trust,
            issued_by: truster.public(),
        };

        trust_node.update_auth(old_auth);

        assert!(trust_node.get_revoke(truster.public()).is_some());
        assert!(trust_node.get_auth(truster.public()).is_none());

        let trust = Trust::create(&truster, kp.public(), Duration::new(60, 0), future);
        let auth = Auth {
            trust,
            issued_by: truster.public(),
        };

        trust_node.update_auth(auth);

        assert!(trust_node.get_auth(truster.public()).is_some());
        assert!(trust_node.get_revoke(truster.public()).is_none());
    }
}
