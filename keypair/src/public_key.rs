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
use crate::error::{DecodingError, VerificationError};
#[cfg(not(target_arch = "wasm32"))]
use crate::rsa;
use crate::secp256k1;
use crate::signature::Signature;

use crate::key_pair::KeyFormat;
use libp2p_identity::{KeyType, PeerId};
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
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), VerificationError> {
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
        PeerId::from_public_key(&self.clone().into())
    }

    pub fn get_key_format(&self) -> KeyFormat {
        use PublicKey::*;

        match self {
            Ed25519(_) => KeyFormat::Ed25519,
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(_) => KeyFormat::Rsa,
            Secp256k1(_) => KeyFormat::Secp256k1,
        }
    }
}

impl From<libp2p_identity::PublicKey> for PublicKey {
    fn from(key: libp2p_identity::PublicKey) -> Self {
        fn convert_key(key: libp2p_identity::PublicKey) -> eyre::Result<PublicKey> {
            match key.key_type() {
                KeyType::Ed25519 => {
                    let pk = key.try_into_ed25519()?;
                    let raw_pk = ed25519::PublicKey::decode(&pk.to_bytes())?;
                    Ok(PublicKey::Ed25519(raw_pk))
                }
                #[cfg(not(target_arch = "wasm32"))]
                KeyType::RSA => {
                    let pk = key.try_into_rsa()?;
                    let raw_pk = rsa::PublicKey::from_pkcs1(pk.encode_pkcs1())?;
                    Ok(PublicKey::Rsa(raw_pk))
                }
                KeyType::Secp256k1 => {
                    let pk = key.try_into_secp256k1()?;
                    let raw_pk = secp256k1::PublicKey::decode(&pk.to_bytes())?;
                    Ok(PublicKey::Secp256k1(raw_pk))
                }
                _ => unreachable!(),
            }
        }

        convert_key(key).expect("Could not convert public key")
    }
}

impl From<PublicKey> for libp2p_identity::PublicKey {
    fn from(key: PublicKey) -> Self {
        fn convert_key(key: PublicKey) -> eyre::Result<libp2p_identity::PublicKey> {
            match key {
                PublicKey::Ed25519(key) => {
                    let raw_pk =
                        libp2p_identity::ed25519::PublicKey::try_from_bytes(&key.encode())?;
                    let pk = libp2p_identity::PublicKey::from(raw_pk);
                    Ok(pk)
                }
                #[cfg(not(target_arch = "wasm32"))]
                PublicKey::Rsa(key) => {
                    let raw_pk =
                        libp2p_identity::rsa::PublicKey::try_decode_x509(&key.encode_x509())?;
                    let pk = libp2p_identity::PublicKey::from(raw_pk);
                    Ok(pk)
                }
                PublicKey::Secp256k1(key) => {
                    let raw_pk =
                        libp2p_identity::secp256k1::PublicKey::try_from_bytes(&key.encode())?;
                    let pk = libp2p_identity::PublicKey::from(raw_pk);
                    Ok(pk)
                }
            }
        }
        convert_key(key).expect("Could not convert key")
    }
}

impl TryFrom<PeerId> for PublicKey {
    type Error = DecodingError;

    fn try_from(peer_id: PeerId) -> Result<Self, Self::Error> {
        Ok(as_public_key(&peer_id)
            .ok_or_else(|| DecodingError::PublicKeyNotInlined(peer_id.to_base58()))?
            .into())
    }
}

/// Convert PeerId to libp2p's PublicKey
fn as_public_key(peer_id: &PeerId) -> Option<libp2p_identity::PublicKey> {
    let mhash = peer_id.as_ref();

    match multihash::Code::try_from(mhash.code()) {
        Ok(multihash::Code::Identity) => {
            libp2p_identity::PublicKey::try_decode_protobuf(mhash.digest()).ok()
        }
        _ => None,
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
        assert_eq!(pk, PublicKey::decode(&encoded_pk).unwrap());
    }

    #[test]
    fn public_key_encode_decode_secp256k1() {
        let kp = KeyPair::generate_secp256k1();
        let pk = kp.public();
        let encoded_pk = pk.encode();
        assert_eq!(pk, PublicKey::decode(&encoded_pk).unwrap());
    }

    #[test]
    fn public_key_peer_id_conversions() {
        let kp = KeyPair::generate_secp256k1();
        let fluence_pk = kp.public();
        let libp2p_pk: libp2p_identity::PublicKey = fluence_pk.clone().into();
        let peer_id = PeerId::from_public_key(&libp2p_pk);
        let fluence_pk_converted = PublicKey::try_from(peer_id).unwrap();

        assert_eq!(fluence_pk, fluence_pk_converted);
    }
}
