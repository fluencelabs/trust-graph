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
use crate::error::DecodingError;
use crate::key_pair::KeyFormat;
#[cfg(not(target_arch = "wasm32"))]
use crate::rsa;
use crate::secp256k1;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub enum Signature {
    Ed25519(ed25519::Signature),
    #[cfg(not(target_arch = "wasm32"))]
    Rsa(rsa::Signature),
    Secp256k1(secp256k1::Signature),
}

pub struct RawSignature {
    pub bytes: Vec<u8>,
    pub sig_type: KeyFormat,
}

impl Signature {
    fn get_prefix(&self) -> u8 {
        use Signature::*;
        match self {
            Ed25519(_) => KeyFormat::Ed25519.into(),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(_) => KeyFormat::Rsa.into(),
            Secp256k1(_) => KeyFormat::Secp256k1.into(),
        }
    }

    /// encode keypair type in first byte and signature as byte array
    pub fn encode(&self) -> Vec<u8> {
        use Signature::*;

        let mut result: Vec<u8> = vec![self.get_prefix()];

        match self {
            Ed25519(sig) => result.extend(sig.0.clone()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(sig) => result.extend(sig.0.clone()),
            Secp256k1(sig) => result.extend(sig.0.clone()),
        }

        result
    }

    /// decode with first byte set as keypair type
    pub fn decode(bytes: Vec<u8>) -> Result<Self, DecodingError> {
        match KeyFormat::try_from(bytes[0])? {
            KeyFormat::Ed25519 => Ok(Signature::Ed25519(ed25519::Signature(bytes[1..].to_vec()))),
            #[cfg(not(target_arch = "wasm32"))]
            KeyFormat::Rsa => Ok(Signature::Rsa(rsa::Signature(bytes[1..].to_vec()))),
            KeyFormat::Secp256k1 => Ok(Signature::Secp256k1(secp256k1::Signature(
                bytes[1..].to_vec(),
            ))),
        }
    }

    pub fn to_vec(&self) -> &[u8] {
        use Signature::*;

        match self {
            Ed25519(sig) => &sig.0,
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(sig) => &sig.0,
            Secp256k1(sig) => &sig.0,
        }
    }

    pub fn get_signature_type(&self) -> KeyFormat {
        use Signature::*;

        match self {
            Ed25519(_) => KeyFormat::Ed25519,
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(_) => KeyFormat::Rsa,
            Secp256k1(_) => KeyFormat::Secp256k1,
        }
    }

    pub fn get_raw_signature(&self) -> RawSignature {
        RawSignature {
            bytes: self.to_vec().clone().to_vec(),
            sig_type: self.get_signature_type(),
        }
    }

    pub fn from_bytes(key_format: KeyFormat, bytes: Vec<u8>) -> Self {
        match key_format {
            KeyFormat::Ed25519 => Signature::Ed25519(ed25519::Signature(bytes)),
            #[cfg(not(target_arch = "wasm32"))]
            KeyFormat::Rsa => Signature::Rsa(rsa::Signature(bytes)),
            KeyFormat::Secp256k1 => Signature::Secp256k1(secp256k1::Signature(bytes)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn signature_encode_decode() {
        let bytes: Vec<u8> = (0..10).collect();
        let ed25519_sig = Signature::Ed25519(crate::ed25519::Signature(bytes.clone()));
        let secp256k1_sig = Signature::Secp256k1(crate::secp256k1::Signature(bytes.clone()));
        #[cfg(not(target_arch = "wasm32"))]
        let rsa_sig = Signature::Rsa(crate::rsa::Signature(bytes.clone()));

        assert_eq!(
            Signature::decode(ed25519_sig.encode()).unwrap(),
            ed25519_sig
        );
        assert_eq!(
            Signature::decode(secp256k1_sig.encode()).unwrap(),
            secp256k1_sig
        );
        #[cfg(not(target_arch = "wasm32"))]
        assert_eq!(Signature::decode(rsa_sig.encode()).unwrap(), rsa_sig);
    }
}
