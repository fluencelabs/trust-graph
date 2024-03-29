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

use crate::certificate::CertificateError::{
    CertificateLengthError, DecodeError, DecodeTrustError, ExpirationError,
    IncorrectCertificateFormat, KeyInCertificateError, MalformedRoot, NoTrustedRoot,
    VerificationError,
};
use crate::trust::{Trust, TrustError};
use fluence_keypair::key_pair::KeyPair;
use fluence_keypair::public_key::PublicKey;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;

/// Serialization format of a certificate.
/// TODO
const FORMAT: &[u8; 2] = &[0, 0];
/// Serialization format version of a certificate.
/// TODO
const VERSION: &[u8; 4] = &[0, 0, 0, 0];
const TRUST_NUMBER_LEN: usize = 1;

/// Chain of trusts started from self-signed root trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub chain: Vec<Trust>,
}

#[derive(ThisError, Debug)]
pub enum CertificateError {
    #[error("Incorrect format of the certificate: {0}")]
    IncorrectCertificateFormat(String),
    #[error("Incorrect length of an array. Should be 2 bytes of a format, 4 bytes of a version and 104 bytes for each trust")]
    IncorrectByteLength,
    #[error("Error while decoding a trust in a certificate: {0}")]
    DecodeError(#[source] TrustError),
    #[error("Certificate is expired. Issued at {issued_at} and expired at {expires_at}")]
    ExpirationError {
        expires_at: String,
        issued_at: String,
    },
    #[error("Certificate does not contain a trusted root.")]
    NoTrustedRoot,
    #[error("Root trust did not pass verification: {0}")]
    MalformedRoot(#[source] TrustError),
    #[error("There is no `issued_by` public key in a certificate")]
    KeyInCertificateError,
    #[error("The certificate must have at least 1 trust")]
    CertificateLengthError,
    #[error("Cannot convert trust number {0} from string: {1}")]
    DecodeTrustError(usize, #[source] TrustError),
    #[error("Trust {0} in chain did not pass verification: {1}")]
    VerificationError(usize, #[source] TrustError),
    #[error("there cannot be paths without any nodes after adding verified certificates")]
    Unexpected,
}

impl Certificate {
    pub fn new_unverified(chain: Vec<Trust>) -> Self {
        Self { chain }
    }

    pub fn new_from_root_trust(
        root_trust: Trust,
        issued_trust: Trust,
        cur_time: Duration,
    ) -> Result<Self, CertificateError> {
        Trust::verify(&root_trust, &root_trust.issued_for, cur_time).map_err(MalformedRoot)?;
        Trust::verify(&issued_trust, &root_trust.issued_for, cur_time)
            .map_err(|e| VerificationError(1, e))?;

        Ok(Self {
            chain: vec![root_trust, issued_trust],
        })
    }

    pub fn issue_with_trust(
        issued_by: PublicKey,
        trust: Trust,
        extend_cert: &Certificate,
        cur_time: Duration,
    ) -> Result<Self, CertificateError> {
        if trust.expires_at.lt(&trust.issued_at) {
            return Err(ExpirationError {
                expires_at: format!("{:?}", trust.expires_at),
                issued_at: format!("{:?}", trust.issued_at),
            });
        }

        Certificate::verify(
            extend_cert,
            &[extend_cert.chain[0].issued_for.clone()],
            cur_time,
        )?;
        // check if `issued_by` is allowed to issue a certificate (i.e., there’s a trust for it in a chain)
        let mut previous_trust_num: i32 = -1;
        for pk_id in 0..extend_cert.chain.len() {
            if extend_cert.chain[pk_id].issued_for == issued_by {
                previous_trust_num = pk_id as i32;
            }
        }

        if previous_trust_num == -1 {
            return Err(KeyInCertificateError);
        };

        // splitting old chain to add new trust after given public key
        let mut new_chain = extend_cert
            .chain
            .split_at((previous_trust_num + 1) as usize)
            .0
            .to_vec();

        new_chain.push(trust);

        Ok(Self { chain: new_chain })
    }

    /// Creates new certificate with root trust (self-signed public key) from a key pair.
    #[allow(dead_code)]
    pub fn issue_root(
        root_kp: &KeyPair,
        for_pk: PublicKey,
        expires_at: Duration,
        issued_at: Duration,
    ) -> Self {
        let root_expiration = Duration::from_secs(u64::max_value());

        let root_trust = Trust::create(root_kp, root_kp.public(), root_expiration, issued_at);

        let trust = Trust::create(root_kp, for_pk, expires_at, issued_at);

        let chain = vec![root_trust, trust];
        Self { chain }
    }

    /// Adds a new trust into chain of trust in certificate.
    #[allow(dead_code)]
    pub fn issue(
        issued_by: &KeyPair,
        for_pk: PublicKey,
        extend_cert: &Certificate,
        expires_at: Duration,
        issued_at: Duration,
        cur_time: Duration,
    ) -> Result<Self, CertificateError> {
        if expires_at.lt(&issued_at) {
            return Err(ExpirationError {
                expires_at: format!("{expires_at:?}"),
                issued_at: format!("{issued_at:?}"),
            });
        }

        // first, verify given certificate
        Certificate::verify(
            extend_cert,
            &[extend_cert.chain[0].issued_for.clone()],
            cur_time,
        )?;

        let issued_by_pk = issued_by.public();

        // check if `issued_by_pk` is allowed to issue a certificate (i.e., there’s a trust for it in a chain)
        let mut previous_trust_num: i32 = -1;
        for pk_id in 0..extend_cert.chain.len() {
            if extend_cert.chain[pk_id].issued_for == issued_by_pk {
                previous_trust_num = pk_id as i32;
            }
        }

        if previous_trust_num == -1 {
            return Err(KeyInCertificateError);
        };

        // splitting old chain to add new trust after given public key
        let mut new_chain = extend_cert
            .chain
            .split_at((previous_trust_num + 1) as usize)
            .0
            .to_vec();

        let trust = Trust::create(issued_by, for_pk, expires_at, issued_at);

        new_chain.push(trust);

        Ok(Self { chain: new_chain })
    }

    /// Verifies that a certificate is valid and you trust to this certificate.
    pub fn verify(
        cert: &Certificate,
        trusted_roots: &[PublicKey],
        cur_time: Duration,
    ) -> Result<(), CertificateError> {
        let chain = &cert.chain;

        if chain.is_empty() {
            return Err(CertificateLengthError);
        }

        // check root trust and its existence in trusted roots list
        let root = &chain[0];
        Trust::verify(root, &root.issued_for, cur_time).map_err(MalformedRoot)?;
        if !trusted_roots.contains(&root.issued_for) {
            return Err(NoTrustedRoot);
        }

        // check if every element in a chain is not expired and has the correct signature
        for trust_id in (1..chain.len()).rev() {
            let trust = &chain[trust_id];

            let trust_giver = &chain[trust_id - 1];

            Trust::verify(trust, &trust_giver.issued_for, cur_time)
                .map_err(|e| VerificationError(trust_id, e))?;
        }

        Ok(())
    }

    /// Convert certificate to byte format
    /// 2 format + 4 version + 1 trusts number + ((1 trust size byte + trust) for each trust)
    #[allow(dead_code)]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(FORMAT);
        encoded.extend_from_slice(VERSION);
        encoded.push(self.chain.len() as u8);

        for t in &self.chain {
            let trust = t.encode();
            encoded.push(trust.len() as u8);
            encoded.extend(trust);
        }

        encoded
    }

    fn check_arr_len(arr: &[u8], check_len: usize) -> Result<(), CertificateError> {
        if arr.len() < check_len {
            Err(CertificateLengthError)
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn decode(arr: &[u8]) -> Result<Self, CertificateError> {
        // TODO do match different formats and versions
        Self::check_arr_len(arr, FORMAT.len() + VERSION.len() + TRUST_NUMBER_LEN)?;
        let mut offset = 0;
        let _format = &arr[offset..offset + FORMAT.len()];
        offset += FORMAT.len();

        let _version = &arr[offset..offset + VERSION.len()];
        offset += VERSION.len();

        let number_of_trusts = arr[offset] as usize;
        offset += TRUST_NUMBER_LEN;

        if number_of_trusts < 2 {
            return Err(CertificateLengthError);
        }
        let mut chain = Vec::with_capacity(number_of_trusts);

        for _ in 0..number_of_trusts {
            Self::check_arr_len(arr, offset + 1)?;
            let trust_len = arr[offset] as usize;
            let from = offset + 1;
            let to = from + trust_len;
            Self::check_arr_len(arr, to)?;
            let slice = &arr[from..to];
            let t = Trust::decode(slice).map_err(DecodeError)?;
            chain.push(t);
            offset += 1 + trust_len;
        }

        Ok(Self { chain })
    }
}

impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", bs58::encode(FORMAT).into_string())?;
        writeln!(f, "{}", bs58::encode(VERSION).into_string())?;
        for trust in self.chain.iter() {
            writeln!(f, "{}", trust.to_string())?;
        }
        Ok(())
    }
}

impl FromStr for Certificate {
    type Err = CertificateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let str_lines: Vec<&str> = s.lines().collect();

        // TODO for future purposes
        let _format = str_lines[0];
        let _version = str_lines[1];

        if (str_lines.len() - 2) % 4 != 0 {
            return Err(IncorrectCertificateFormat(s.to_string()));
        }

        let num_of_trusts = (str_lines.len() - 2) / 4;
        let mut trusts = Vec::with_capacity(num_of_trusts);

        for i in (2..str_lines.len()).step_by(4) {
            let trust = Trust::convert_from_strings(
                str_lines[i],
                str_lines[i + 1],
                str_lines[i + 2],
                str_lines[i + 3],
            )
            .map_err(|e| DecodeTrustError(i, e))?;

            trusts.push(trust);
        }

        Ok(Self::new_unverified(trusts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::misc::current_time;
    use fluence_keypair::KeyPair;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub fn one_second() -> Duration {
        Duration::from_secs(1)
    }

    pub fn one_minute() -> Duration {
        Duration::from_secs(60)
    }

    pub fn one_year() -> Duration {
        Duration::from_secs(31_557_600)
    }

    #[test]
    pub fn test_string_encoding_decoding_ed25519() {
        let (_root_kp, second_kp, cert) = generate_root_cert();

        let cur_time = current_time();

        let third_kp = KeyPair::generate_ed25519();

        let new_cert = Certificate::issue(
            &second_kp,
            third_kp.public(),
            &cert,
            cur_time.checked_add(one_second()).unwrap(),
            cur_time,
            cur_time,
        )
        .unwrap();

        let serialized = new_cert.to_string();
        let deserialized = Certificate::from_str(&serialized);

        assert!(deserialized.is_ok());
        let after_cert = deserialized.unwrap();
        assert_eq!(&new_cert.chain[0], &after_cert.chain[0]);
        assert_eq!(&new_cert, &after_cert);
    }

    #[test]
    pub fn test_serialization_deserialization_ed25519() {
        let (_root_kp, second_kp, cert) = generate_root_cert();

        let cur_time = current_time();

        let third_kp = KeyPair::generate_ed25519();

        let new_cert = Certificate::issue(
            &second_kp,
            third_kp.public(),
            &cert,
            cur_time.checked_add(one_second()).unwrap(),
            cur_time,
            cur_time,
        )
        .unwrap();

        let serialized = new_cert.encode();
        let deserialized = Certificate::decode(serialized.as_slice());

        assert!(deserialized.is_ok());
        let after_cert = deserialized.unwrap();
        assert_eq!(&new_cert.chain[0], &after_cert.chain[0]);
        assert_eq!(&new_cert, &after_cert);
    }

    #[test]
    fn test_small_chain_ed25519() {
        let bad_cert = Certificate { chain: Vec::new() };

        let check = Certificate::verify(&bad_cert, &[], current_time());
        assert!(check.is_err());
    }

    fn generate_root_cert() -> (KeyPair, KeyPair, Certificate) {
        let root_kp = KeyPair::generate_ed25519();
        let second_kp = KeyPair::generate_ed25519();

        let cur_time = current_time();

        (
            root_kp.clone(),
            second_kp.clone(),
            Certificate::issue_root(
                &root_kp,
                second_kp.public(),
                cur_time.checked_add(one_year()).unwrap(),
                cur_time,
            ),
        )
    }

    #[test]
    fn test_issue_cert_ed25519() {
        let (root_kp, second_kp, cert) = generate_root_cert();
        let trusted_roots = [root_kp.public()];

        // we don't need nanos for serialization, etc
        let cur_time = Duration::from_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u64,
        );

        let third_kp = KeyPair::generate_ed25519();

        let new_cert = Certificate::issue(
            &second_kp,
            third_kp.public(),
            &cert,
            cur_time.checked_add(one_year()).unwrap(),
            cur_time,
            cur_time,
        );
        assert_eq!(new_cert.is_ok(), true);
        let new_cert = new_cert.unwrap();

        println!("cert is\n{}", new_cert.to_string());

        assert_eq!(new_cert.chain.len(), 3);
        assert_eq!(new_cert.chain[0].issued_for, root_kp.public());
        assert_eq!(new_cert.chain[1].issued_for, second_kp.public());
        assert_eq!(new_cert.chain[2].issued_for, third_kp.public());
        assert!(Certificate::verify(&new_cert, &trusted_roots, cur_time).is_ok());
    }

    #[test]
    fn test_cert_expiration_ed25519() {
        let (root_kp, second_kp, cert) = generate_root_cert();
        let trusted_roots = [root_kp.public()];
        let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let third_kp = KeyPair::generate_ed25519();

        let new_cert = Certificate::issue(
            &second_kp,
            third_kp.public(),
            &cert,
            cur_time.checked_sub(one_second()).unwrap(),
            cur_time.checked_sub(one_minute()).unwrap(),
            cur_time,
        )
        .unwrap();

        assert!(Certificate::verify(&new_cert, &trusted_roots, cur_time).is_err());
    }

    #[test]
    fn test_issue_in_chain_tail_ed25519() {
        let (root_kp, second_kp, cert) = generate_root_cert();
        let trusted_roots = [root_kp.public()];
        let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let third_kp = KeyPair::generate_ed25519();
        let fourth_kp = KeyPair::generate_ed25519();

        let new_cert = Certificate::issue(
            &second_kp,
            third_kp.public(),
            &cert,
            cur_time.checked_add(one_second()).unwrap(),
            cur_time,
            cur_time,
        )
        .unwrap();
        let new_cert = Certificate::issue(
            &third_kp,
            fourth_kp.public(),
            &new_cert,
            cur_time.checked_add(one_second()).unwrap(),
            cur_time,
            cur_time,
        );

        assert_eq!(new_cert.is_ok(), true);
        let new_cert = new_cert.unwrap();

        assert_eq!(new_cert.chain.len(), 4);
        assert_eq!(new_cert.chain[0].issued_for, root_kp.public());
        assert_eq!(new_cert.chain[1].issued_for, second_kp.public());
        assert_eq!(new_cert.chain[2].issued_for, third_kp.public());
        assert_eq!(new_cert.chain[3].issued_for, fourth_kp.public());
        assert!(Certificate::verify(&new_cert, &trusted_roots, cur_time).is_ok());
    }

    #[test]
    fn test_issue_in_chain_body_ed25519() {
        let (root_kp, second_kp, cert) = generate_root_cert();
        let trusted_roots = [root_kp.public()];
        let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let third_kp = KeyPair::generate_ed25519();
        let fourth_kp = KeyPair::generate_ed25519();

        let new_cert = Certificate::issue(
            &second_kp,
            third_kp.public(),
            &cert,
            cur_time.checked_add(one_second()).unwrap(),
            cur_time,
            cur_time,
        )
        .unwrap();
        let new_cert = Certificate::issue(
            &second_kp,
            fourth_kp.public(),
            &new_cert,
            cur_time.checked_add(one_second()).unwrap(),
            cur_time,
            cur_time,
        );

        assert_eq!(new_cert.is_ok(), true);
        let new_cert = new_cert.unwrap();

        assert_eq!(new_cert.chain.len(), 3);
        assert_eq!(new_cert.chain[0].issued_for, root_kp.public());
        assert_eq!(new_cert.chain[1].issued_for, second_kp.public());
        assert_eq!(new_cert.chain[2].issued_for, fourth_kp.public());
        assert!(Certificate::verify(&new_cert, &trusted_roots, cur_time).is_ok());
    }

    #[test]
    fn test_no_cert_in_chain_ed25519() {
        let (_root_kp, _second_kp, cert) = generate_root_cert();
        let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let bad_kp = KeyPair::generate_ed25519();
        let new_cert_bad = Certificate::issue(
            &bad_kp,
            bad_kp.public(),
            &cert,
            cur_time.checked_add(one_second()).unwrap(),
            cur_time,
            cur_time,
        );
        assert_eq!(new_cert_bad.is_err(), true);
    }

    #[test]
    fn test_no_trusted_root_in_chain() {
        let (_root_kp, second_kp, cert) = generate_root_cert();
        let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let trusted_roots = [second_kp.public()];
        assert!(Certificate::verify(&cert, &trusted_roots, cur_time).is_err());
        assert!(Certificate::verify(&cert, &[], cur_time).is_err());
    }

    #[test]
    fn test_forged_cert() {
        let (root_kp, _second_kp, cert) = generate_root_cert();
        let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let trusted_roots = [root_kp.public()];

        // forged cert
        let mut bad_chain = cert.chain;
        bad_chain.remove(0);
        let bad_cert = Certificate { chain: bad_chain };

        assert!(Certificate::verify(&bad_cert, &trusted_roots, cur_time).is_err());
    }

    #[test]
    fn test_generate_root_cert() {
        let (root_kp, second_kp, cert) = generate_root_cert();
        let cur_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

        let trusted_roots = [root_kp.public()];

        assert_eq!(cert.chain.len(), 2);
        assert_eq!(cert.chain[0].issued_for, root_kp.public());
        assert_eq!(cert.chain[1].issued_for, second_kp.public());
        assert!(Certificate::verify(&cert, &trusted_roots, cur_time).is_ok());
    }
}
