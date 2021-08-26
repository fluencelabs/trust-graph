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

use crate::trust::TrustError::{Base58DecodeError, DecodePublicKeyError, ParseError, SignatureError, DecodeErrorInvalidSize};
use derivative::Derivative;
use fluence_keypair::key_pair::KeyPair;
use fluence_keypair::public_key::PublicKey;
use fluence_keypair::signature::Signature;
use std::convert::TryInto;
use std::num::ParseIntError;
use std::time::Duration;
use thiserror::Error as ThisError;
use serde::{Deserialize, Serialize};
use sha2::Digest;

pub const EXPIRATION_LEN: usize = 8;
pub const ISSUED_LEN: usize = 8;

/// One element in chain of trust in a certificate.
/// TODO delete pk from Trust (it is already in a trust node)
#[derive(Clone, PartialEq, Derivative, Eq, Deserialize, Serialize)]
#[derivative(Debug)]
pub struct Trust {
    /// For whom this certificate is issued
    #[derivative(Debug(format_with = "show_pubkey"))]
    pub issued_for: PublicKey,
    /// Expiration date of a trust.
    pub expires_at: Duration,
    /// Signature of a previous trust in a chain.
    /// Signature is self-signed if it is a root trust.
    #[derivative(Debug(format_with = "show_sig"))]
    pub signature: Signature,
    /// Creation time of a trust
    pub issued_at: Duration,
}

fn show_pubkey(key: &PublicKey, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", bs58::encode(&key.encode()).into_string())
}

fn show_sig(sig: &Signature, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
    write!(f, "{}", bs58::encode(&sig.encode()).into_string())
}

#[derive(ThisError, Debug)]
pub enum TrustError {
    /// Errors occurred when 'expires_at' date is later then current time.
    #[error("Trust is expired at: '{0:?}', current time: '{1:?}'")]
    Expired(Duration, Duration),

    /// Errors occurred on signature verification
    #[error("{0}")]
    SignatureError(
        #[from]
        #[source]
        fluence_keypair::error::SigningError,
    ),

    /// Errors occurred on trust decoding from different formats
    #[error("Cannot decode the public key: {0} in the trust: {1}")]
    DecodePublicKeyError(String, #[source] fluence_keypair::error::DecodingError),

    #[error("Cannot parse `{0}` field in the trust '{1}': {2}")]
    ParseError(String, String, #[source] ParseIntError),

    #[error("Cannot decode `{0}` from base58 format in the trust '{1}': {2}")]
    Base58DecodeError(String, String, #[source] bs58::decode::Error),

    #[error("{0}")]
    PublicKeyError(
        #[from]
        #[source]
        fluence_keypair::error::DecodingError,
    ),

    #[error("Cannot decode `{0}` field in the trust: invalid size")]
    DecodeErrorInvalidSize(String),
}

impl Trust {
    #[allow(dead_code)]
    pub fn new(
        issued_for: PublicKey,
        expires_at: Duration,
        issued_at: Duration,
        signature: Signature,
    ) -> Self {
        Self {
            issued_for,
            expires_at,
            issued_at,
            signature,
        }
    }

    pub fn create(
        issued_by: &KeyPair,
        issued_for: PublicKey,
        expires_at: Duration,
        issued_at: Duration,
    ) -> Self {
        let msg = Self::metadata_bytes(&issued_for, expires_at, issued_at);

        let signature = issued_by.sign(msg.as_slice()).unwrap();

        Self {
            issued_for,
            expires_at,
            signature,
            issued_at,
        }
    }

    /// Verifies that authorization is cryptographically correct.
    pub fn verify(
        trust: &Trust,
        issued_by: &PublicKey,
        cur_time: Duration,
    ) -> Result<(), TrustError> {
        if trust.expires_at < cur_time {
            return Err(TrustError::Expired(trust.expires_at, cur_time));
        }

        let msg: &[u8] =
            &Self::metadata_bytes(&trust.issued_for, trust.expires_at, trust.issued_at);

        KeyPair::verify(issued_by, msg, &trust.signature).map_err(SignatureError)
    }

    pub fn metadata_bytes(pk: &PublicKey, expires_at: Duration, issued_at: Duration) -> Vec<u8> {
        let pk_encoded = pk.encode();
        let expires_at_encoded: [u8; EXPIRATION_LEN] = (expires_at.as_secs() as u64).to_le_bytes();
        let issued_at_encoded: [u8; ISSUED_LEN] = (issued_at.as_secs() as u64).to_le_bytes();
        let mut metadata = Vec::new();

        metadata.extend(pk_encoded);
        metadata.extend_from_slice(&expires_at_encoded[0..EXPIRATION_LEN]);
        metadata.extend_from_slice(&issued_at_encoded[0..ISSUED_LEN]);

        sha2::Sha256::digest(&metadata).to_vec()
    }

    /// Encode the trust into a byte array
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        let mut issued_for = self.issued_for.encode();
        let mut signature = self.signature.encode();
        vec.push(issued_for.len() as u8);
        vec.append(&mut issued_for);
        vec.push(signature.len() as u8);
        vec.append(&mut signature);
        vec.extend_from_slice(&(self.expires_at.as_secs() as u64).to_le_bytes());
        vec.extend_from_slice(&(self.issued_at.as_secs() as u64).to_le_bytes());

        vec
    }

    fn check_arr_len(arr: &[u8], field_name: &str, check_len: usize) -> Result<(), TrustError> {
        if arr.len() < check_len {
            Err(DecodeErrorInvalidSize(field_name.to_string()))
        } else {
            Ok(())
        }
    }

    /// Decode a trust from a byte array as produced by `encode`.
    #[allow(dead_code)]
    pub fn decode(arr: &[u8]) -> Result<Self, TrustError> {
        Self::check_arr_len(arr, "public_key_len", 1)?;
        let pk_len = arr[0] as usize;
        let mut offset = 1;

        Self::check_arr_len(arr, "public_key", offset + pk_len)?;
        let pk = PublicKey::decode(&arr[offset..offset + pk_len])?;
        offset += pk_len;

        Self::check_arr_len(arr, "signature_size", offset + 1)?;
        let signature_len = arr[offset] as usize;
        offset += 1;

        Self::check_arr_len(arr, "signature", offset + signature_len)?;
        let signature = &arr[offset..offset + signature_len];
        let signature = Signature::decode(signature.to_vec())?;
        offset += signature_len;

        Self::check_arr_len(arr, "expiration", offset + EXPIRATION_LEN)?;
        let expiration_bytes = &arr[offset..offset + EXPIRATION_LEN];
        let expiration_date = u64::from_le_bytes(expiration_bytes.try_into().unwrap());
        let expiration_date = Duration::from_secs(expiration_date);
        offset += EXPIRATION_LEN;

        Self::check_arr_len(arr, "issued", offset + ISSUED_LEN)?;
        let issued_bytes = &arr[offset..];
        let issued_date = u64::from_le_bytes(issued_bytes.try_into().unwrap());
        let issued_date = Duration::from_secs(issued_date);

        Ok(Self {
            issued_for: pk,
            signature,
            expires_at: expiration_date,
            issued_at: issued_date,
        })
    }

    fn bs58_str_to_vec(str: &str, field: &str) -> Result<Vec<u8>, TrustError> {
        bs58::decode(str)
            .into_vec()
            .map_err(|e| Base58DecodeError(field.to_string(), str.to_string(), e))
    }

    fn str_to_duration(str: &str, field: &str) -> Result<Duration, TrustError> {
        let secs = str
            .parse()
            .map_err(|e| ParseError(field.to_string(), str.to_string(), e))?;
        Ok(Duration::from_secs(secs))
    }

    pub fn convert_from_strings(
        issued_for: &str,
        signature: &str,
        expires_at: &str,
        issued_at: &str,
    ) -> Result<Self, TrustError> {
        // PublicKey
        let issued_for_bytes = Self::bs58_str_to_vec(issued_for, "issued_for")?;
        let issued_for = PublicKey::decode(&issued_for_bytes)
            .map_err(|e| DecodePublicKeyError(issued_for.to_string(), e))?;

        // 64 bytes signature
        let signature = Self::bs58_str_to_vec(signature, "signature")?;
        let signature = Signature::decode(signature.to_vec())?;

        // Duration
        let expires_at = Self::str_to_duration(expires_at, "expires_at")?;

        // Duration
        let issued_at = Self::str_to_duration(issued_at, "issued_at")?;

        Ok(Trust::new(issued_for, expires_at, issued_at, signature))
    }
}

impl ToString for Trust {
    fn to_string(&self) -> String {
        let issued_for = bs58::encode(self.issued_for.encode()).into_string();
        let signature = bs58::encode(self.signature.encode()).into_string();
        let expires_at = (self.expires_at.as_secs() as u64).to_string();
        let issued_at = (self.issued_at.as_secs() as u64).to_string();

        format!(
            "{}\n{}\n{}\n{}",
            issued_for, signature, expires_at, issued_at
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_revoke_and_validate_ed25519() {
        let truster = KeyPair::generate_ed25519();
        let trusted = KeyPair::generate_ed25519();

        let current = Duration::new(100, 0);
        let duration = Duration::new(1000, 0);
        let issued_at = Duration::new(10, 0);

        let trust = Trust::create(&truster, trusted.public(), duration, issued_at);

        assert_eq!(
            Trust::verify(&trust, &truster.public(), current).is_ok(),
            true
        );
    }

    #[test]
    fn test_validate_corrupted_revoke_ed25519() {
        let truster = KeyPair::generate_ed25519();
        let trusted = KeyPair::generate_ed25519();

        let current = Duration::new(1000, 0);
        let issued_at = Duration::new(10, 0);

        let trust = Trust::create(&truster, trusted.public(), current, issued_at);

        let corrupted_duration = Duration::new(1234, 0);
        let corrupted_trust = Trust::new(
            trust.issued_for,
            trust.expires_at,
            corrupted_duration,
            trust.signature,
        );

        assert!(Trust::verify(&corrupted_trust, &truster.public(), current).is_err());
    }

    #[test]
    fn test_encode_decode_ed25519() {
        let truster = KeyPair::generate_ed25519();
        let trusted = KeyPair::generate_ed25519();

        let current = Duration::new(1000, 0);
        let issued_at = Duration::new(10, 0);

        let trust = Trust::create(&truster, trusted.public(), current, issued_at);

        let encoded = trust.encode();
        let decoded = Trust::decode(encoded.as_slice()).unwrap();

        assert_eq!(trust, decoded);
    }
}
