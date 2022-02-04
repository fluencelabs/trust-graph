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

use crate::revoke::RevokeError::IncorrectSignature;
use fluence_keypair::key_pair::KeyPair;
use fluence_keypair::public_key::PublicKey;
use fluence_keypair::signature::Signature;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::time::Duration;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum RevokeError {
    #[error("Signature is incorrect: {0}")]
    IncorrectSignature(
        #[from]
        #[source]
        fluence_keypair::error::VerificationError,
    ),
}

/// "A document" that cancels trust created before.
/// TODO delete pk from Revoke (it is already in a trust node)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revocation {
    /// who is revoked
    pub pk: PublicKey,
    /// date when revocation was created
    pub revoked_at: Duration,
    /// the issuer of this revocation
    pub revoked_by: PublicKey,
    /// proof of this revocation
    pub signature: Signature,
}

impl Revocation {
    pub fn new(
        revoked_by: PublicKey,
        pk: PublicKey,
        revoked_at: Duration,
        signature: Signature,
    ) -> Self {
        Self {
            pk,
            revoked_at,
            revoked_by,
            signature,
        }
    }

    /// Creates new revocation signed by a revoker.
    pub fn create(revoker: &KeyPair, to_revoke: PublicKey, revoked_at: Duration) -> Self {
        let msg = Revocation::signature_bytes(&to_revoke, revoked_at);
        let signature = revoker.sign(&msg).unwrap();

        Revocation::new(revoker.public(), to_revoke, revoked_at, signature)
    }

    pub fn signature_bytes(pk: &PublicKey, revoked_at: Duration) -> Vec<u8> {
        let mut metadata = Vec::new();
        let pk_bytes = &pk.encode();
        metadata.push(pk_bytes.len() as u8);
        metadata.extend(pk_bytes);
        metadata.extend_from_slice(&(revoked_at.as_secs() as u64).to_le_bytes());

        sha2::Sha256::digest(&metadata).to_vec()
    }

    /// Verifies that revocation is cryptographically correct.
    pub fn verify(revoke: &Revocation) -> Result<(), RevokeError> {
        let msg = Revocation::signature_bytes(&revoke.pk, revoke.revoked_at);

        revoke
            .revoked_by
            .verify(msg.as_slice(), &revoke.signature)
            .map_err(IncorrectSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_revoke_and_validate_ed25519() {
        let revoker = KeyPair::generate_ed25519();
        let to_revoke = KeyPair::generate_ed25519();

        let duration = Duration::new(100, 0);

        let revoke = Revocation::create(&revoker, to_revoke.public(), duration);

        assert_eq!(Revocation::verify(&revoke).is_ok(), true);
    }

    #[test]
    fn test_validate_corrupted_revoke_ed25519() {
        let revoker = KeyPair::generate_ed25519();
        let to_revoke = KeyPair::generate_ed25519();

        let duration = Duration::new(100, 0);

        let revoke = Revocation::create(&revoker, to_revoke.public(), duration);

        let duration2 = Duration::new(95, 0);
        let corrupted_revoke = Revocation::new(
            revoker.public(),
            to_revoke.public(),
            duration2,
            revoke.signature,
        );

        assert_eq!(Revocation::verify(&corrupted_revoke).is_ok(), false);
    }
}
