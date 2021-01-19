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

use crate::signature::Signature;
use core::fmt::Debug;
use ed25519_dalek::SignatureError;

#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey(pub(crate) ed25519_dalek::PublicKey);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl PublicKey {
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        self.0.verify_strict(message, &signature.0)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
        let pk = ed25519_dalek::PublicKey::from_bytes(bytes)?;

        Ok(PublicKey(pk))
    }

    pub fn to_bytes(&self) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }
}
