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
use crate::ed25519;
use crate::secp256k1;
use crate::rsa;
use crate::error::SigningError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum Signature {
    Ed25519(ed25519::Signature),
    Rsa(rsa::Signature),
    Secp256k1(secp256k1::Signature),
}

impl Signature {
    pub fn encode(&self) -> Vec<u8> {
        use Signature::*;

        let mut result: Vec<u8> = Vec::new();

        result.push(self.get_prefix());
        match self {
            Ed25519(sig) => result.extend(sig.to_bytes().to_vec()),
            Rsa(sig) => result.extend(sig.0.clone()),
            Secp256k1(sig) => result.extend(sig.0.clone()),
        }

        result
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        use Signature::*;

        match self {
            Ed25519(sig) => sig.to_bytes().to_vec(),
            Rsa(sig) => sig.0.to_vec(),
            Secp256k1(sig) => sig.0.to_vec(),
        }
    }

    fn get_prefix(&self) -> u8 {
        use Signature::*;
        match self {
            Ed25519(_) => 0,
            Rsa(_) => 1,
            Secp256k1(_) => 2
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SigningError> {
        match bytes[0] {
            0 => Ok(Signature::Ed25519(ed25519::Signature::from_bytes(&bytes[1..])?)),
            1 => Ok(Signature::Rsa(rsa::Signature(bytes[1..].to_vec()))),
            2 => Ok(Signature::Secp256k1(secp256k1::Signature(bytes[1..].to_vec()))),
            _ => Err(SigningError::new("invalid type byte".to_string())),
        }
    }
}
