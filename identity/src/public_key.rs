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

/// The public key of a node's identity keypair.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        use PublicKey::*;
        match self {
            Ed25519(pk) => pk.verify(msg, sig),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pk) => pk.verify(msg, sig),
            Secp256k1(pk) => pk.verify(msg, sig)
        }
    }
}

