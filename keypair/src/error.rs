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

//! Errors during identity key operations.
use thiserror::Error as ThisError;

/// An error during decoding of key material.
#[derive(ThisError, Debug)]
pub enum Error {
    #[error("{0} Key format is not supported")]
    InvalidKeyFormat(String),
}

/// An error during decoding of key material.
#[derive(ThisError, Debug)]
pub enum DecodingError {
    #[error("Failed to decode, invalid length: {0}")]
    InvalidLength(#[from] std::array::TryFromSliceError),
    #[error("Failed to decode with ed25519: {0}")]
    Ed25519(
        #[from]
        #[source]
        ed25519_dalek::ed25519::Error,
    ),
    #[error("Failed to decode with RSA")]
    Rsa,
    #[error("Failed to decode with secp256k1")]
    Secp256k1,
    #[error("RSA keypair decoding is not supported yet")]
    KeypairDecodingIsNotSupported,
    #[error("Invalid type prefix")]
    InvalidTypeByte,
    #[error("Cannot decode public key from base58 :{0}")]
    Base58DecodeError(#[source] bs58::decode::Error),
    #[error("Raw signature decoding failed: type {0} not supported")]
    RawSignatureUnsupportedType(String),
    #[error("public key is not inlined in peer id: {0}")]
    PublicKeyNotInlined(String),
}

/// An error during signing of a message.
#[derive(ThisError, Debug)]
pub enum SigningError {
    #[error("Failed to sign with ed25519: {0}")]
    Ed25519(
        #[from]
        #[source]
        ed25519_dalek::ed25519::Error,
    ),
    #[error("Failed to sign with RSA")]
    Rsa,
    #[error("Failed to sign with secp256k1: {0}")]
    Secp256k1(
        #[from]
        #[source]
        libsecp256k1::Error,
    ),
}

/// An error during verification of a message.
#[derive(ThisError, Debug)]
pub enum VerificationError {
    #[error("Failed to verify signature {1} with {2} ed25519 public key: {0}")]
    Ed25519(#[source] ed25519_dalek::ed25519::Error, String, String),

    #[cfg(not(target_arch = "wasm32"))]
    #[error("Failed to verify signature {1} with {2} RSA public key: {0}")]
    Rsa(#[source] ring::error::Unspecified, String, String),

    #[error("Failed to verify signature {1} with {2} secp256k1 public key: {0}")]
    Secp256k1(#[source] libsecp256k1::Error, String, String),
}
