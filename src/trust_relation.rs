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

use crate::revoke::Revocation;
use crate::trust::Trust;
use failure::_core::time::Duration;
use fluence_keypair::public_key::PublicKey;
use fluence_keypair::Signature;
use serde::{Deserialize, Serialize};

/// Represents who give a trust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    /// proof of this authorization
    pub trust: Trust,
    /// the issuer of this authorization
    pub issued_by: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustRelation {
    Auth(Auth),
    Revocation(Revocation),
}

impl TrustRelation {
    /// Returns timestamp of when this relation was created
    pub fn issued_at(&self) -> Duration {
        match self {
            TrustRelation::Auth(auth) => auth.trust.issued_at,
            TrustRelation::Revocation(r) => r.revoked_at,
        }
    }

    /// Returns public key of the creator of this relation
    pub fn issued_by(&self) -> &PublicKey {
        match self {
            TrustRelation::Auth(auth) => &auth.issued_by,
            TrustRelation::Revocation(r) => &r.revoked_by,
        }
    }

    pub fn issued_for(&self) -> &PublicKey {
        match self {
            TrustRelation::Auth(auth) => &auth.trust.issued_for,
            TrustRelation::Revocation(r) => &r.pk,
        }
    }

    pub fn expires_at(&self) -> Duration {
        match self {
            TrustRelation::Auth(auth) => auth.trust.expires_at,
            // revocations never expire
            TrustRelation::Revocation(_) => Duration::from_secs(0),
        }
    }

    pub fn signature(&self) -> &Signature {
        match self {
            TrustRelation::Auth(auth) => &auth.trust.signature,
            TrustRelation::Revocation(r) => &r.signature,
        }
    }
}
