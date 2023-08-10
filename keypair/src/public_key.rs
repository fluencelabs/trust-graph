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
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        use PublicKey::*;
        let mut result: Vec<u8> = vec![self.get_prefix()];

        match self {
            Ed25519(pk) => result.extend(pk.encode().to_vec()),
        };

        result
    }

    pub fn decode(bytes: &[u8]) -> Result<PublicKey, DecodingError> {
        match KeyFormat::try_from(bytes[0])? {
            KeyFormat::Ed25519 => Ok(PublicKey::Ed25519(ed25519::PublicKey::decode(&bytes[1..])?)),
        }
    }

    fn get_prefix(&self) -> u8 {
        use PublicKey::*;
        match self {
            Ed25519(_) => KeyFormat::Ed25519.into(),
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
        }
    }

    pub fn to_peer_id(&self) -> PeerId {
        PeerId::from_public_key(&self.clone().into())
    }

    pub fn get_key_format(&self) -> KeyFormat {
        use PublicKey::*;

        match self {
            Ed25519(_) => KeyFormat::Ed25519,
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

#[cfg(all(test, feature = "rand"))]
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
    fn public_key_peer_id_conversions() {
        let kp = KeyPair::generate_ed25519();
        let fluence_pk = kp.public();
        let libp2p_pk: libp2p_identity::PublicKey = fluence_pk.clone().into();
        let peer_id = PeerId::from_public_key(&libp2p_pk);
        let fluence_pk_converted = PublicKey::try_from(peer_id).unwrap();

        assert_eq!(fluence_pk, fluence_pk_converted);
    }
}
