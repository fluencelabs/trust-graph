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
use crate::error::{DecodingError, SigningError};
#[cfg(not(target_arch = "wasm32"))]
use crate::rsa;
use crate::secp256k1;
use crate::signature::Signature;

use crate::key_pair::KeyFormat;
use libp2p_core::PeerId;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// The public key of a node's identity keypair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    /// A public Ed25519 key.
    Ed25519(ed25519::PublicKey),
    #[cfg(not(target_arch = "wasm32"))]
    /// A public RSA key.
    Rsa(rsa::PublicKey),
    /// A public Secp256k1 key.
    Secp256k1(secp256k1::PublicKey),
}

impl PublicKey {
    /// Verify a signature for a message using this public key, i.e. check
    /// that the signature has been produced by the corresponding
    /// private key (authenticity), and that the message has not been
    /// tampered with (integrity).
    // TODO: add VerificationError
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SigningError> {
        use PublicKey::*;
        match self {
            Ed25519(pk) => pk.verify(msg, sig.to_vec()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pk) => pk.verify(msg, sig.to_vec()),
            Secp256k1(pk) => pk.verify(msg, sig.to_vec()),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        use PublicKey::*;
        let mut result: Vec<u8> = vec![self.get_prefix()];

        match self {
            Ed25519(pk) => result.extend(pk.encode().to_vec()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pk) => result.extend(pk.to_pkcs1()),
            Secp256k1(pk) => result.extend(pk.encode().to_vec()),
        };

        result
    }

    pub fn decode(bytes: &[u8]) -> Result<PublicKey, DecodingError> {
        match KeyFormat::try_from(bytes[0])? {
            KeyFormat::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::decode(&bytes[1..])?)),
            #[cfg(not(target_arch = "wasm32"))]
            KeyFormat::Rsa => Ok(PublicKey::Rsa(rsa::PublicKey::from_pkcs1(
                bytes[1..].to_owned(),
            )?)),
            KeyFormat::Secp256k1 => Ok(PublicKey::Secp256k1(secp256k1::PublicKey::decode(
                &bytes[1..],
            )?)),
        }
    }

    fn get_prefix(&self) -> u8 {
        use PublicKey::*;
        match self {
            Ed25519(_) => KeyFormat::Ed25519.into(),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(_) => KeyFormat::Rsa.into(),
            Secp256k1(_) => KeyFormat::Secp256k1.into(),
        }
    }

    pub fn from_base58(str: &str) -> Result<PublicKey, DecodingError> {
        let bytes = bs58::decode(str)
            .into_vec()
            .map_err(DecodingError::Base58DecodeError)?;
        Self::decode(&bytes)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        use PublicKey::*;

        match self {
            Ed25519(pk) => pk.encode().to_vec(),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pk) => pk.to_pkcs1().to_vec(),
            Secp256k1(pk) => pk.encode().to_vec(),
        }
    }

    pub fn to_peer_id(&self) -> PeerId {
        PeerId::from_public_key(self.clone().into())
    }
}

impl From<libp2p_core::identity::PublicKey> for PublicKey {
    fn from(key: libp2p_core::identity::PublicKey) -> Self {
        use libp2p_core::identity::PublicKey::*;

        match key {
            Ed25519(key) => {
                PublicKey::Ed25519(ed25519::PublicKey::decode(&key.encode()[..]).unwrap())
            }
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(key) => PublicKey::Rsa(rsa::PublicKey::from_pkcs1(key.encode_pkcs1()).unwrap()),
            Secp256k1(key) => {
                PublicKey::Secp256k1(secp256k1::PublicKey::decode(&key.encode()[..]).unwrap())
            }
        }
    }
}

impl From<PublicKey> for libp2p_core::identity::PublicKey {
    fn from(key: PublicKey) -> Self {
        use libp2p_core::identity as libp2p_identity;

        match key {
            PublicKey::Ed25519(key) => libp2p_identity::PublicKey::Ed25519(
                libp2p_identity::ed25519::PublicKey::decode(&key.encode()[..]).unwrap(),
            ),
            #[cfg(not(target_arch = "wasm32"))]
            PublicKey::Rsa(key) => libp2p_identity::PublicKey::Rsa(
                libp2p_identity::rsa::PublicKey::decode_x509(&key.encode_x509()).unwrap(),
            ),
            PublicKey::Secp256k1(key) => libp2p_identity::PublicKey::Secp256k1(
                libp2p_identity::secp256k1::PublicKey::decode(&key.encode()[..]).unwrap(),
            ),
        }
    }
}

pub fn peer_id_to_fluence_pk(peer_id: libp2p_core::PeerId) -> eyre::Result<PublicKey> {
    Ok(peer_id
        .as_public_key()
        .ok_or(eyre::eyre!(
            "public key is not inlined in peer id: {}",
            peer_id
        ))?
        .into())
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
        assert_eq!(pk, PublicKey::decode(&encoded_pk).unwrap());
    }

    #[test]
    fn public_key_encode_decode_secp256k1() {
        let kp = KeyPair::generate_secp256k1();
        let pk = kp.public();
        let encoded_pk = pk.encode();
        assert_eq!(pk, PublicKey::decode(&encoded_pk).unwrap());
    }
}
