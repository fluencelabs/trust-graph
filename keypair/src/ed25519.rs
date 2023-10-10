// Copyright 2019 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Ed25519 keys.
use crate::error::{DecodingError, DecodingError::InvalidLength, SigningError, VerificationError};
use core::fmt;
use ed25519_dalek::{self as ed25519, Signer as _, Verifier as _};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use zeroize::Zeroize;

/// An Ed25519 keypair
#[derive(Clone)]
pub struct Keypair(ed25519::SigningKey);

impl Keypair {
    /// Generate a new Ed25519 keypair.
    pub fn generate() -> Self {
        Keypair::from(SecretKey::generate())
    }

    /// Encode the keypair into a byte array by concatenating the bytes
    /// of the secret scalar and the compressed public point,
    /// an informal standard for encoding Ed25519 keypairs.
    pub fn encode(&self) -> [u8; 64] {
        self.0.to_keypair_bytes()
    }

    /// Decode a keypair from the format produced by `encode`,
    /// zeroing the input on success.
    pub fn decode(kp: &mut [u8]) -> Result<Self, DecodingError> {
        let bytes = <[u8; 64]>::try_from(&*kp).map_err(InvalidLength)?;

        ed25519::SigningKey::from_keypair_bytes(&bytes)
            .map(|k| {
                kp.zeroize();
                Keypair(k)
            })
            .map_err(DecodingError::Ed25519)
    }

    /// Sign a message using the private key of this keypair.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        Ok(self.0.try_sign(msg)?.to_bytes().to_vec())
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Get the secret key of this keypair.
    pub fn secret(&self) -> SecretKey {
        SecretKey::from_bytes(&mut self.0.to_bytes())
            .expect("ed25519::SecretKey::from_bytes(to_bytes(k)) != k")
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.0.verifying_key())
            .finish()
    }
}

/// Build keypair from existing ed25519 keypair
impl From<ed25519::SigningKey> for Keypair {
    fn from(kp: ed25519::SigningKey) -> Self {
        Keypair(kp)
    }
}

/// Demote an Ed25519 keypair to a secret key.
impl From<Keypair> for SecretKey {
    fn from(kp: Keypair) -> Self {
        SecretKey(kp.0.to_bytes())
    }
}

/// Promote an Ed25519 secret key into a keypair.
impl From<SecretKey> for Keypair {
    fn from(sk: SecretKey) -> Self {
        let signing = ed25519::SigningKey::from_bytes(&sk.0);
        Keypair(signing)
    }
}

/// An Ed25519 public key.
#[derive(PartialEq, Eq, Debug, Clone, Deserialize, Serialize)]
pub struct PublicKey(ed25519::VerifyingKey);

impl PublicKey {
    /// Verify the Ed25519 signature on a message using the public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), VerificationError> {
        ed25519::Signature::try_from(sig)
            .and_then(|s| self.0.verify(msg, &s))
            .map_err(|e| {
                VerificationError::Ed25519(
                    e,
                    bs58::encode(sig).into_string(),
                    bs58::encode(self.0.as_bytes()).into_string(),
                )
            })
    }

    /// Encode the public key into a byte array in compressed form, i.e.
    /// where one coordinate is represented by a single bit.
    pub fn encode(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Decode a public key from a byte array as produced by `encode`.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodingError> {
        let bytes = <[u8; 32]>::try_from(bytes).map_err(InvalidLength)?;
        ed25519::VerifyingKey::from_bytes(&bytes)
            .map_err(DecodingError::Ed25519)
            .map(PublicKey)
    }
}

/// An Ed25519 secret key.
#[derive(Clone)]
pub struct SecretKey(pub ed25519::SecretKey);

/// View the bytes of the secret key.
impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey")
    }
}

impl SecretKey {
    /// Generate a new Ed25519 secret key.
    pub fn generate() -> Self {
        let signing = ed25519::SigningKey::generate(&mut rand::rngs::OsRng);
        SecretKey(signing.to_bytes())
    }

    /// Create an Ed25519 secret key from a byte slice, zeroing the input on success.
    /// If the bytes do not constitute a valid Ed25519 secret key, an error is
    /// returned.
    pub fn from_bytes(mut sk_bytes: impl AsMut<[u8]>) -> Result<Self, DecodingError> {
        let sk_bytes = sk_bytes.as_mut();
        let secret = <[u8; 32]>::try_from(&*sk_bytes).map_err(InvalidLength)?;
        sk_bytes.zeroize();
        Ok(SecretKey(secret))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Signature(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use quickcheck::*;

    fn eq_keypairs(kp1: &Keypair, kp2: &Keypair) -> bool {
        kp1.public() == kp2.public() && kp1.0.to_bytes() == kp2.0.to_bytes()
    }

    #[test]
    fn ed25519_keypair_encode_decode() {
        fn prop() -> bool {
            let kp1 = Keypair::generate();
            let mut kp1_enc = kp1.encode();
            let kp2 = Keypair::decode(&mut kp1_enc).unwrap();
            eq_keypairs(&kp1, &kp2) && kp1_enc.iter().all(|b| *b == 0)
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }

    #[test]
    fn ed25519_keypair_convert() {
        fn prop() -> bool {
            let kp1 = KeyPair::generate_ed25519();
            let libp2p_kp: libp2p_identity::Keypair = kp1.clone().into();
            let kp2: KeyPair = libp2p_kp.into();
            kp1.public() == kp2.public() && kp1.secret().unwrap() == kp2.secret().unwrap()
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }

    #[test]
    fn ed25519_keypair_from_secret() {
        fn prop() -> bool {
            let kp1 = Keypair::generate();
            let mut sk = kp1.0.to_bytes();
            let kp2 = Keypair::from(SecretKey::from_bytes(&mut sk).unwrap());
            eq_keypairs(&kp1, &kp2) && sk == [0u8; 32]
        }
        QuickCheck::new().tests(10).quickcheck(prop as fn() -> _);
    }

    #[test]
    fn ed25519_signature() {
        let kp = Keypair::generate();
        let pk = kp.public();

        let msg = "hello world".as_bytes();
        let sig = kp.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).is_ok());

        let mut invalid_sig = sig.clone();
        invalid_sig[3..6].copy_from_slice(&[10, 23, 42]);
        assert!(pk.verify(msg, &invalid_sig).is_err());

        let invalid_msg = "h3ll0 w0rld".as_bytes();
        assert!(pk.verify(invalid_msg, &sig).is_err());
    }
}
