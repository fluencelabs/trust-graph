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
use crate::ed25519;
use crate::rsa;
use crate::secp256k1;
use crate::error::*;
use crate::signature::Signature;

use serde::{Deserialize, Serialize};

/// The public key of a node's identity keypair.
#[repr(u8)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    /// A public Ed25519 key.
    Ed25519(ed25519::PublicKey),
    #[cfg(not(target_arch = "wasm32"))]
    /// A public RSA key.
    Rsa(rsa::PublicKey),
    /// A public Secp256k1 key.
    Secp256k1(secp256k1::PublicKey)
}

impl PublicKey {
    /// Verify a signature for a message using this public key, i.e. check
    /// that the signature has been produced by the corresponding
    /// private key (authenticity), and that the message has not been
    /// tampered with (integrity).
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> bool {
        use PublicKey::*;
        match self {
            Ed25519(pk) => pk.verify(msg, sig.to_bytes().as_slice()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pk) => pk.verify(msg, sig.to_bytes().as_slice()),
            Secp256k1(pk) => pk.verify(msg, sig.to_bytes().as_slice())
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        use PublicKey::*;
        let mut result: Vec<u8> = Vec::new();

        result.push(self.get_prefix());
        match self {
            Ed25519(pk) => result.extend(pk.encode().to_vec()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pk) => result.extend(pk.encode_pkcs1().to_vec()),
            Secp256k1(pk) => result.extend(pk.encode().to_vec()),
        };

        result
    }

    pub fn decode(bytes: Vec<u8>) -> Result<PublicKey, DecodingError> {
        match bytes[0] {
            0 => Ok(PublicKey::Ed25519(ed25519::PublicKey::decode(&bytes[1..])?)),
            1 => Ok(PublicKey::Rsa(rsa::PublicKey::decode_pkcs1(&bytes[1..])?)),
            2 => Ok(PublicKey::Secp256k1(secp256k1::PublicKey::decode(&bytes[1..])?)),
            _ => Err(DecodingError::new("invalid type byte".to_string())),
        }
    }

    fn get_prefix(&self) -> u8 {
        use PublicKey::*;
        match self {
            Ed25519(_) => 0,
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(_) => 1,
            Secp256k1(_) => 2
        }
    }

    pub fn from_base58(str: &str) -> Result<PublicKey, DecodingError> {
        let bytes = bs58::decode(str).into_vec().map_err(DecodingError::new)?;
        Self::decode(bytes)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        use PublicKey::*;

        match self {
            Ed25519(pk) => pk.encode().to_vec(),
            Rsa(pk) => pk.encode_pkcs1().to_vec(),
            Secp256k1(pk) => pk.encode().to_vec(),
        }
    }
}

impl From<libp2p_core::identity::PublicKey> for PublicKey {
    fn from(key: libp2p_core::identity::PublicKey) -> Self {
        use libp2p_core::identity::PublicKey::*;

        match key {
            Ed25519(key) => PublicKey::Ed25519(ed25519::PublicKey::decode(key.encode().to_vec().as_slice()).unwrap()),
            Rsa(key) => PublicKey::Rsa(rsa::PublicKey::decode_pkcs1(key.encode_pkcs1().as_slice()).unwrap()),
            Secp256k1(key) => PublicKey::Secp256k1(secp256k1::PublicKey::decode(key.encode().to_vec().as_slice()).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn public_key_encode_decode_ed25519() {
        let kp = KeyPair::generate_ed25519();
        let pk = kp.public();
        let encoded_pk = pk.encode();
        assert_eq!(pk, PublicKey::decode(encoded_pk).unwrap());
    }

    #[test]
    fn public_key_encode_decode_secp256k1() {
        let kp = KeyPair::generate_secp256k1();
        let pk = kp.public();
        let encoded_pk = pk.encode();
        assert_eq!(pk, PublicKey::decode(encoded_pk).unwrap());
    }
}
