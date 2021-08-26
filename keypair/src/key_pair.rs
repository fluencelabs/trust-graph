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

//! A node's network identity keys.
use crate::ed25519;
#[cfg(not(target_arch = "wasm32"))]
use crate::rsa;
use crate::secp256k1;
use crate::public_key::PublicKey;
use crate::signature::Signature;
use crate::error::{Error, DecodingError, SigningError};
use std::str::FromStr;
use std::convert::TryFrom;
use libp2p_core::PeerId;

/// Identity keypair of a node.
///
/// # Example: Generating RSA keys with OpenSSL
///
/// ```text
/// openssl genrsa -out private.pem 2048
/// openssl pkcs8 -in private.pem -inform PEM -topk8 -out private.pk8 -outform DER -nocrypt
/// rm private.pem      # optional
/// ```
///
/// Loading the keys:
///
/// ```text
/// let mut bytes = std::fs::read("private.pk8").unwrap();
/// let keypair = Keypair::rsa_from_pkcs8(&mut bytes);
/// ```
///


pub enum KeyFormat {
    Ed25519,
    #[cfg(not(target_arch = "wasm32"))]
    Rsa,
    Secp256k1,
}

impl FromStr for KeyFormat {
    type Err = Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" => Ok(KeyFormat::Ed25519),
            "secp256k1" => Ok(KeyFormat::Secp256k1),
            #[cfg(not(target_arch = "wasm32"))]
            "rsa" => Ok(KeyFormat::Rsa),
            _ => Err(Error::InvalidKeyFormat(s.to_string()))
        }
    }
}

impl TryFrom<u8> for KeyFormat {
    type Error = DecodingError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyFormat::Ed25519),
            #[cfg(not(target_arch = "wasm32"))]
            1 => Ok(KeyFormat::Rsa),
            2 => Ok(KeyFormat::Secp256k1),
            _ => Err(DecodingError::InvalidTypeByte)
        }
    }
}

impl From<KeyFormat> for u8 {
    fn from(kf: KeyFormat) -> Self {
        match kf {
            KeyFormat::Ed25519 => 0,
            #[cfg(not(target_arch = "wasm32"))]
            KeyFormat::Rsa => 1,
            KeyFormat::Secp256k1 => 2,
        }
    }
}

#[derive(Clone)]
pub enum KeyPair {
    /// An Ed25519 keypair.
    Ed25519(ed25519::Keypair),
    #[cfg(not(target_arch = "wasm32"))]
    /// An RSA keypair.
    Rsa(rsa::Keypair),
    /// A Secp256k1 keypair.
    Secp256k1(secp256k1::Keypair),
}

impl KeyPair {
    pub fn generate(format: KeyFormat) -> KeyPair {
        match format {
            KeyFormat::Ed25519 => KeyPair::generate_ed25519(),
            KeyFormat::Secp256k1 => KeyPair::generate_secp256k1(),
            #[cfg(not(target_arch = "wasm32"))]
            KeyFormat::Rsa => todo!("rsa generation is not supported yet!"),
        }
    }

    /// Generate a new Ed25519 keypair.
    pub fn generate_ed25519() -> KeyPair {
        KeyPair::Ed25519(ed25519::Keypair::generate())
    }

    /// Generate a new Secp256k1 keypair.
    pub fn generate_secp256k1() -> KeyPair {
        KeyPair::Secp256k1(secp256k1::Keypair::generate())
    }

    /// Decode an keypair from a DER-encoded secret key in PKCS#8 PrivateKeyInfo
    /// format (i.e. unencrypted) as defined in [RFC5208].
    ///
    /// [RFC5208]: https://tools.ietf.org/html/rfc5208#section-5
    #[cfg(not(target_arch = "wasm32"))]
    pub fn rsa_from_pkcs8(pkcs8_der: &mut [u8]) -> Result<KeyPair, DecodingError> {
        rsa::Keypair::from_pkcs8(pkcs8_der).map(KeyPair::Rsa)
    }

    /// Decode a keypair from a DER-encoded Secp256k1 secret key in an ECPrivateKey
    /// structure as defined in [RFC5915].
    ///
    /// [RFC5915]: https://tools.ietf.org/html/rfc5915
    pub fn secp256k1_from_der(der: &mut [u8]) -> Result<KeyPair, DecodingError> {
        secp256k1::SecretKey::from_der(der)
            .map(|sk| KeyPair::Secp256k1(secp256k1::Keypair::from(sk)))
    }

    /// Sign a message using the private key of this keypair, producing
    /// a signature that can be verified using the corresponding public key.
    pub fn sign(&self, msg: &[u8]) -> Result<Signature, SigningError> {
        use KeyPair::*;
        match self {
            Ed25519(ref pair) => Ok(Signature::Ed25519(ed25519::Signature(pair.sign(msg)?))),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(ref pair) => Ok(Signature::Rsa(rsa::Signature(pair.sign(msg)?))),
            Secp256k1(ref pair) => Ok(Signature::Secp256k1(secp256k1::Signature(pair.secret().sign(msg)?)))
        }
    }

    /// Get the public key of this keypair.
    pub fn public(&self) -> PublicKey {
        use KeyPair::*;
        match self {
            Ed25519(pair) => PublicKey::Ed25519(pair.public()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(pair) => PublicKey::Rsa(pair.public()),
            Secp256k1(pair) => PublicKey::Secp256k1(pair.public().clone()),
        }
    }

    pub fn secret(&self) -> eyre::Result<Vec<u8>> {
        use KeyPair::*;
        match self {
            Ed25519(pair) => Ok(pair.secret().0.to_bytes().to_vec()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(_) => Err(eyre::eyre!("secret key is not available for RSA")),
            Secp256k1(pair) => Ok(pair.secret().to_bytes().to_vec()),
        }
    }

    /// Verify the signature on a message using the public key.
    pub fn verify(pk: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), SigningError> {
        pk.verify(msg, signature)
    }

    pub fn to_vec(&self) -> Vec<u8> {
        use KeyPair::*;
        match self {
            Ed25519(kp) => kp.encode().to_vec(),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(_) => todo!("rsa encoding is not supported yet!"),
            Secp256k1(kp) => kp.secret().to_bytes().to_vec(),
        }
    }

    pub fn from_vec(mut bytes: Vec<u8>, format: KeyFormat) -> Result<Self, DecodingError> {
        use KeyPair::*;

        match format {
            KeyFormat::Ed25519 => Ok(Ed25519(ed25519::Keypair::decode(&mut bytes)?)),
            KeyFormat::Secp256k1 => Ok(Secp256k1(secp256k1::SecretKey::from_bytes(bytes)?.into())),
            #[cfg(not(target_arch = "wasm32"))]
            KeyFormat::Rsa => Err(DecodingError::KeypairDecodingIsNotSupported)
        }
    }

    pub fn get_peer_id(&self) -> PeerId {
       self.public().to_peer_id()
    }
}

impl From<libp2p_core::identity::Keypair> for KeyPair {
    fn from(key: libp2p_core::identity::Keypair) -> Self {
        use libp2p_core::identity::Keypair::*;

        match key {
            Ed25519(kp) => KeyPair::Ed25519(ed25519::Keypair::decode(&mut kp.encode()).unwrap()),
            #[cfg(not(target_arch = "wasm32"))]
            // safety: these Keypair structures are identical
            Rsa(kp) => KeyPair::Rsa(unsafe { std::mem::transmute::<libp2p_core::identity::rsa::Keypair, rsa::Keypair>(kp) }),
            Secp256k1(kp) => KeyPair::Secp256k1(secp256k1::Keypair::from(secp256k1::SecretKey::from_bytes(kp.secret().to_bytes()).unwrap())),
        }
    }
}

impl From<KeyPair> for libp2p_core::identity::Keypair {
    fn from(key: KeyPair) -> Self {
        use KeyPair::*;
        use libp2p_core::identity::Keypair;
        use libp2p_core::identity;

        match key {
            Ed25519(kp) => Keypair::Ed25519(identity::ed25519::Keypair::decode(kp.encode().to_vec().as_mut_slice()).unwrap()),
            #[cfg(not(target_arch = "wasm32"))]
            Rsa(kp) => Keypair::Rsa(unsafe { std::mem::transmute::<rsa::Keypair, libp2p_core::identity::rsa::Keypair>(kp) }),
            Secp256k1(kp) => Keypair::Secp256k1(identity::secp256k1::Keypair::from(identity::secp256k1::SecretKey::from_bytes(kp.secret().to_bytes()).unwrap())),
        }
    }
}
