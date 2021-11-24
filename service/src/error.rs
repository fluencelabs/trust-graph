/*
 * Copyright 2021 Fluence Labs Limited
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
use thiserror::Error as ThisError;

use crate::dto::DtoConversionError;
use fluence_keypair::error::DecodingError;
use trust_graph::{CertificateError, TrustError, TrustGraphError};

#[derive(ThisError, Debug)]
pub enum ServiceError {
    #[error("peer id parse error: {0}")]
    PeerIdParseError(String),
    #[error("public key extraction from peer id failed: {0}")]
    PublicKeyExtractionError(String),
    #[error("{0}")]
    PublicKeyDecodeError(
        #[from]
        #[source]
        DecodingError,
    ),
    #[error("{0}")]
    TGError(
        #[from]
        #[source]
        TrustGraphError,
    ),
    #[error("{0}")]
    CertError(
        #[from]
        #[source]
        CertificateError,
    ),
    #[error("{0}")]
    DtoError(
        #[from]
        #[source]
        DtoConversionError,
    ),
    #[error("{0}")]
    TrustError(
        #[from]
        #[source]
        TrustError,
    ),
    #[error("you should use host peer.timestamp_sec to pass timestamp: {0}")]
    InvalidTimestampTetraplet(String),
    #[error("{0} can't be issued later than the current timestamp")]
    InvalidTimestamp(String),
    #[error("Root could add only by trust graph service owner")]
    NotOwner,
}
