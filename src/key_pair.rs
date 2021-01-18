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

use crate::ed25519::{Keypair as Libp2pKeyPair};
use ed25519_dalek::SignatureError;
use ed25519_dalek::{PublicKey, Signer};

use core::fmt::{Debug};
use std::fmt;
use rand::rngs::OsRng;

pub type Signature = ed25519_dalek::Signature;

/// An Ed25519 keypair.
#[derive(Debug)]
pub struct KeyPair {
    pub key_pair: ed25519_dalek::Keypair,
}

impl KeyPair {
    /// Generate a new Ed25519 keypair.
    #[allow(dead_code)]
    pub fn generate() -> Self {
        let mut csprng = OsRng { };
        let kp = ed25519_dalek::Keypair::generate(&mut csprng);
        kp.into()
    }

    pub fn from_bytes(sk_bytes: &[u8]) -> Result<Self, SignatureError> {
        let kp = ed25519_dalek::Keypair::from_bytes(sk_bytes)?;
        Ok(KeyPair {key_pair: kp})
    }

    /// Encode the keypair into a byte array by concatenating the bytes
    /// of the secret scalar and the compressed public point/
    #[allow(dead_code)]
    pub fn encode(&self) -> [u8; 64] {
        self.key_pair.to_bytes()
    }

    /// Decode a keypair from the format produced by `encode`.
    #[allow(dead_code)]
    pub fn decode(kp: &[u8]) -> Result<KeyPair, SignatureError> {
        let kp = ed25519_dalek::Keypair::from_bytes(kp)?;
        Ok(Self {
            key_pair: kp,
        })
    }

    /// Get the public key of this keypair.
    #[allow(dead_code)]
    pub fn public_key(&self) -> PublicKey {
        self.key_pair.public
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.key_pair.sign(msg)
    }

    /// Verify the Ed25519 signature on a message using the public key.
    pub fn verify(pk: &PublicKey, msg: &[u8], signature: Signature) -> Result<(), String> {
        // let signature = ed25519_dalek::Signature::from_bytes(signature)
        //     .map_err(|err| format!("Cannot convert bytes to a signature: {:?}", err))?;
        pk.verify_strict(msg, &signature)
            .map_err(|err| format!("Signature verification failed: {:?}", err))
    }
}

impl From<Libp2pKeyPair> for KeyPair {
    fn from(kp: Libp2pKeyPair) -> Self {
        let kp = ed25519_dalek::Keypair::from_bytes(&kp.encode()).unwrap();
        Self { key_pair: kp }
    }
}

impl From<ed25519_dalek::Keypair> for KeyPair {
    fn from(kp: ed25519_dalek::Keypair) -> Self {
        Self { key_pair: kp }
    }
}

/// Implement serde::Deserialize for KeyPair
impl<'de> serde::Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<KeyPair, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Unexpected, Visitor};

        struct KeyPairVisitor;

        impl<'de> Visitor<'de> for KeyPairVisitor {
            type Value = KeyPair;

            /// Error message stating what was expected
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("byte array or base58 string")
            }

            /// Implement deserialization from base58 string
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                bs58::decode(s)
                    .into_vec()
                    .map_err(|_| Error::invalid_value(Unexpected::Str(s), &self))
                    .and_then(|v| self.visit_bytes(v.as_slice()))
            }

            /// Implement deserialization from bytes
            fn visit_bytes<E>(self, b: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                KeyPair::decode(b).map_err(|_| Error::invalid_value(Unexpected::Bytes(b), &self))
            }
        }

        deserializer.deserialize_str(KeyPairVisitor)
    }
}
