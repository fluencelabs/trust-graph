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

use crate::public_key::PublicKey;
use crate::rsa;
use crate::error::*;
use crate::ed25519;
use crate::secp256k1;
use crate::signature::Signature;

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
            Ed25519(ref pair) => Ok(Signature::Ed25519(ed25519::Signature::from_bytes(pair.sign(msg).as_slice())?)),
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

    /// Verify the signature on a message using the public key.
    pub fn verify(pk: &PublicKey, msg: &[u8], signature: &Signature) -> Result<(), SigningError> {
        // let signature = ed25519_dalek::Signature::from_bytes(signature)
        //     .map_err(|err| format!("Cannot convert bytes to a signature: {:?}", err))?;
        if pk.verify(msg, signature) {
            Ok(())
        } else {
            Err(SigningError::new(""))
        }
    }
}

