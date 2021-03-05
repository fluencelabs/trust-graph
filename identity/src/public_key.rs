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

use crate::public_key::PKError::{FromBase58Error, FromBytesError};
use crate::signature::Signature;

use core::fmt::Debug;
use ed25519_dalek::SignatureError;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;
use libp2p_core::identity;

#[derive(ThisError, Debug)]
pub enum PKError {
    #[error("Cannot decode public key from bytes: {0}")]
    FromBytesError(#[source] SignatureError),
    #[error("Cannot decode public key from base58 format: {0}")]
    FromBase58Error(#[source] bs58::decode::Error),
    #[error("Only ed25519 is supported")]
    UnsupportedKey
}

#[derive(Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
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

    pub fn from_base58(str: &str) -> Result<PublicKey, PKError> {
        let bytes = bs58::decode(str).into_vec().map_err(FromBase58Error)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, PKError> {
        let pk = ed25519_dalek::PublicKey::from_bytes(bytes).map_err(FromBytesError)?;
        Ok(PublicKey(pk))
    }

    pub fn to_bytes(&self) -> [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    pub fn from_libp2p(pk: identity::PublicKey) -> Result<Self, PKError> {
        if let identity::PublicKey::Ed25519(pk) = pk {
            Self::from_bytes(&pk.encode())
        } else {
            // TODO: support all keys
            PKError::UnsupportedKey
        }
    }
}
