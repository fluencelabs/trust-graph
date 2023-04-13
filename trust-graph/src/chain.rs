/*
 * Copyright 2021 Fluence Labs Limited
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

use crate::{Auth, PublicKeyHashable, Revocation};
use fluence_keypair::PublicKey;
use nonempty::NonEmpty;
use std::collections::HashSet;

#[derive(Clone)]
pub(crate) struct Chain {
    pub(crate) auths: NonEmpty<Auth>,
    revoked_by: HashSet<PublicKeyHashable>,
}
impl Chain {
    pub(crate) fn new(auths: NonEmpty<Auth>, revocations: Vec<Revocation>) -> Self {
        let mut chain = Self {
            auths,
            revoked_by: Default::default(),
        };
        chain.add_revocations(revocations);

        chain
    }
    pub(crate) fn can_be_extended_by(&self, pk: &PublicKey) -> bool {
        !self.revoked_by.contains(pk.as_ref())
            && !self.auths.iter().any(|a| a.trust.issued_for.eq(pk))
    }

    pub(crate) fn add_revocations(&mut self, revocations: Vec<Revocation>) {
        revocations.into_iter().for_each(move |r| {
            self.revoked_by.insert(r.revoked_by.into());
        });
    }
}
