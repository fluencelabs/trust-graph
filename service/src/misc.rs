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
use crate::error::ServiceError;
use crate::error::ServiceError::*;
use crate::storage_impl::{SQLiteStorage, DB_PATH};
use crate::TRUSTED_TIMESTAMP;
use fluence_keypair::PublicKey;
use libp2p_core::PeerId;
use marine_rs_sdk::CallParameters;
use std::cell::RefCell;
use std::convert::TryFrom;
use std::str::FromStr;
use trust_graph::TrustGraph;

/// Check timestamps are generated on the current host with builtin ("peer" "timestamp_sec")
pub(crate) fn check_timestamp_tetraplets(
    call_parameters: &CallParameters,
    arg_number: usize,
) -> Result<(), ServiceError> {
    let tetraplets = call_parameters
        .tetraplets
        .get(arg_number)
        .ok_or_else(|| InvalidTimestampTetraplet(format!("{:?}", call_parameters.tetraplets)))?;
    let tetraplet = tetraplets
        .get(0)
        .ok_or_else(|| InvalidTimestampTetraplet(format!("{:?}", call_parameters.tetraplets)))?;
    (TRUSTED_TIMESTAMP.eq(&(&tetraplet.service_id, &tetraplet.function_name))
        && tetraplet.peer_pk == call_parameters.host_id)
        .then(|| ())
        .ok_or_else(|| InvalidTimestampTetraplet(format!("{:?}", tetraplet)))
}

fn parse_peer_id(peer_id: String) -> Result<PeerId, ServiceError> {
    libp2p_core::PeerId::from_str(&peer_id)
        .map_err(|e| ServiceError::PeerIdParseError(format!("{:?}", e)))
}

#[allow(dead_code)]
thread_local!(static INSTANCE: RefCell<TrustGraph<SQLiteStorage>> = RefCell::new(TrustGraph::new(
    SQLiteStorage::new(marine_sqlite_connector::open(DB_PATH).unwrap()),
)));

pub fn with_tg<F, T>(func: F) -> T
where
    F: FnOnce(&RefCell<TrustGraph<SQLiteStorage>>) -> T,
{
    INSTANCE.with(|tg| func(tg))
    // func(&mut *get_data())
}

pub fn wrapped_try<F, T>(func: F) -> T
where
    F: FnOnce() -> T,
{
    func()
}

pub fn extract_public_key(peer_id: String) -> Result<PublicKey, ServiceError> {
    PublicKey::try_from(
        parse_peer_id(peer_id)
            .map_err(|e| ServiceError::PublicKeyExtractionError(e.to_string()))?,
    )
    .map_err(ServiceError::PublicKeyDecodeError)
}
