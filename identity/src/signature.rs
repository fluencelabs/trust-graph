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

use signature::Signature as SigSignature;
use serde::{Serialize, Deserialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(pub ed25519_dalek::Signature);

pub const SIGNATURE_LENGTH: usize = 64;

impl Signature {
    /// Create a new signature from a byte array
    pub fn new(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Signature(ed25519_dalek::Signature::from(bytes))
    }

    /// Return the inner byte array
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LENGTH] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let sig = ed25519_dalek::Signature::from_bytes(bytes).map_err(|err| err.to_string())?;
        Ok(Signature(sig))
    }
}
