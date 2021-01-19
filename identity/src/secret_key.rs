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

use ed25519_dalek::SignatureError;

pub struct SecretKey(ed25519_dalek::SecretKey);

impl SecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, SignatureError> {
        let pk = ed25519_dalek::SecretKey::from_bytes(bytes)?;

        Ok(SecretKey(pk))
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
