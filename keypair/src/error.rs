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
    #[error("Failed to decode with ed25519")]
    Ed25519(),
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
    #[error("Failed to sign with ed25519")]
    Ed25519(),
}

/// An error during verification of a message.
#[derive(ThisError, Debug)]
pub enum VerificationError {
    #[error("Failed to verify signature {0} with {1} ed25519 public key")]
    Ed25519(String, String),
}
