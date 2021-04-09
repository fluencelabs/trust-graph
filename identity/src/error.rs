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
pub enum DecodingError {
    #[error("Failed to decode with ed25519: {0}")]
    Ed25519(
        #[from]
        #[source]
        ed25519_dalek::ed25519::Error
    ),
    #[error("Failed to decode with RSA")]
    Rsa,
    #[error("Failed to decode with secp256k1")]
    Secp256k1,
    #[error("RSA keypair decoding is not supported yet")]
    KeypairDecodingIsNotSupported,
    #[error("Invalid type byte")]
    InvalidTypeByte,
    #[error("Cannot decode from base58 :{0}")]
    Base58DecodeError(#[source] bs58::decode::Error),
}


/// An error during signing of a message.
#[derive(ThisError, Debug)]
pub enum SigningError {
    #[error("Failed to sign with ed25519: {0}")]
    Ed25519(
        #[from]
        #[source]
        ed25519_dalek::ed25519::Error
    ),
    #[error("Failed to sign with RSA")]
    Rsa,
    #[error("Failed to sign with secp256k1: {0}")]
    Secp256k1(
        #[from]
        #[source]
        secp256k1::Error
    ),
}

