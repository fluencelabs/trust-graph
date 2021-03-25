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
//use crate::rsa;
use crate::ed25519;
use crate::secp256k1;

/// The secret key of a node's identity keypair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretKey {
    /// A secret Ed25519 key.
    Ed25519(ed25519::SecretKey),
    #[cfg(not(target_arch = "wasm32"))]
    /// A secret RSA key.
    //Rsa(rsa::SecretKey),
    /// A secret Secp256k1 key.
    Secp256k1(secp256k1::SecretKey),
}

impl SecretKey {}

