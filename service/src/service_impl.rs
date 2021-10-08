use crate::dto::{Certificate, DtoConversionError, Revoke, Trust};
use crate::service_impl::ServiceError::InvalidTimestampTetraplet;
use crate::storage_impl::get_data;
use fluence_keypair::error::DecodingError;
use fluence_keypair::{PublicKey, Signature};
use libp2p_core::PeerId;
use marine_rs_sdk::CallParameters;
use std::convert::{Into, TryFrom, TryInto};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;
use trust_graph::{CertificateError, TrustError, TrustGraphError};

pub static TRUSTED_TIMESTAMP_SERVICE_ID: &str = "peer";
pub static TRUSTED_TIMESTAMP_FUNCTION_NAME: &str = "timestamp_sec";

/// Check timestamps are generated on the current host with builtin ("peer" "timestamp_sec")
pub(crate) fn check_timestamp_tetraplets(
    call_parameters: &CallParameters,
    arg_number: usize,
) -> Result<(), ServiceError> {
    let tetraplets = call_parameters
        .tetraplets
        .get(arg_number)
        .ok_or(InvalidTimestampTetraplet)?;
    let tetraplet = tetraplets.get(0).ok_or(InvalidTimestampTetraplet)?;
    (tetraplet.service_id == TRUSTED_TIMESTAMP_SERVICE_ID
        && tetraplet.function_name == TRUSTED_TIMESTAMP_FUNCTION_NAME
        && tetraplet.peer_pk == call_parameters.host_id)
        .then(|| ())
        .ok_or(InvalidTimestampTetraplet)
}

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
    #[error("you should use host peer.timestamp_sec to pass timestamp")]
    InvalidTimestampTetraplet,
    #[error("{0} can't be issued later than the current timestamp")]
    InvalidTimestamp(String),
}

fn parse_peer_id(peer_id: String) -> Result<PeerId, ServiceError> {
    libp2p_core::PeerId::from_str(&peer_id)
        .map_err(|e| ServiceError::PeerIdParseError(format!("{:?}", e)))
}

fn extract_public_key(peer_id: String) -> Result<PublicKey, ServiceError> {
    PublicKey::try_from(
        parse_peer_id(peer_id)
            .map_err(|e| ServiceError::PublicKeyExtractionError(e.to_string()))?,
    )
    .map_err(ServiceError::PublicKeyDecodeError)
}

pub fn get_weight_impl(peer_id: String, timestamp_sec: u64) -> Result<u32, ServiceError> {
    check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;
    let mut tg = get_data().lock();
    let public_key = extract_public_key(peer_id)?;
    let weight = tg.weight(public_key, Duration::from_secs(timestamp_sec))?;
    Ok(weight)
}

fn add_cert(certificate: trust_graph::Certificate, timestamp_sec: u64) -> Result<(), ServiceError> {
    let timestamp_sec = Duration::from_secs(timestamp_sec);
    let mut tg = get_data().lock();
    tg.add(certificate, timestamp_sec)?;
    Ok(())
}

pub fn insert_cert_impl_raw(certificate: String, timestamp_sec: u64) -> Result<(), ServiceError> {
    let certificate = trust_graph::Certificate::from_str(&certificate)?;

    add_cert(certificate, timestamp_sec)?;
    Ok(())
}

pub fn get_all_certs_impl(
    issued_for: String,
    timestamp_sec: u64,
) -> Result<Vec<Certificate>, ServiceError> {
    check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;
    let mut tg = get_data().lock();

    let public_key = extract_public_key(issued_for)?;
    let certs = tg.get_all_certs(public_key, Duration::from_secs(timestamp_sec))?;
    Ok(certs.into_iter().map(|c| c.into()).collect())
}

pub fn insert_cert_impl(certificate: Certificate, timestamp_sec: u64) -> Result<(), ServiceError> {
    let certificate: trust_graph::Certificate = certificate.try_into()?;

    add_cert(certificate, timestamp_sec)?;
    Ok(())
}

pub fn add_root_impl(peer_id: String, weight: u32) -> Result<(), ServiceError> {
    let mut tg = get_data().lock();
    let public_key = extract_public_key(peer_id)?;
    tg.add_root_weight_factor(public_key, weight)?;
    Ok(())
}

pub fn get_trust_bytes_imp(
    peer_id: String,
    expires_at_sec: u64,
    issued_at_sec: u64,
) -> Result<Vec<u8>, ServiceError> {
    let public_key = extract_public_key(peer_id)?;
    Ok(trust_graph::Trust::signature_bytes(
        &public_key,
        Duration::from_secs(expires_at_sec),
        Duration::from_secs(issued_at_sec),
    ))
}

pub fn issue_trust_impl(
    peer_id: String,
    expires_at_sec: u64,
    issued_at_sec: u64,
    trust_bytes: Vec<u8>,
) -> Result<Trust, ServiceError> {
    let public_key = extract_public_key(peer_id)?;
    let expires_at_sec = Duration::from_secs(expires_at_sec);
    let issued_at_sec = Duration::from_secs(issued_at_sec);
    let signature = Signature::from_bytes(public_key.get_key_format(), trust_bytes);
    Ok(Trust::from(trust_graph::Trust::new(
        public_key,
        expires_at_sec,
        issued_at_sec,
        signature,
    )))
}

pub fn verify_trust_impl(
    trust: Trust,
    issuer_peer_id: String,
    timestamp_sec: u64,
) -> Result<(), ServiceError> {
    check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 2)?;
    let public_key = extract_public_key(issuer_peer_id)?;
    trust_graph::Trust::verify(
        &trust.try_into()?,
        &public_key,
        Duration::from_secs(timestamp_sec),
    )?;

    Ok(())
}

pub fn add_trust_impl(
    trust: Trust,
    issuer_peer_id: String,
    timestamp_sec: u64,
) -> Result<u32, ServiceError> {
    let public_key = extract_public_key(issuer_peer_id)?;
    check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 2)?;

    if trust.issued_at > timestamp_sec {
        return Err(ServiceError::InvalidTimestamp("Trust".to_string()));
    }

    let mut tg = get_data().lock();
    tg.add_trust(
        &trust.try_into()?,
        public_key,
        Duration::from_secs(timestamp_sec),
    )
    .map_err(ServiceError::TGError)
}

pub fn get_revoke_bytes_impl(
    revoked_peer_id: String,
    revoked_at: u64,
) -> Result<Vec<u8>, ServiceError> {
    let public_key = extract_public_key(revoked_peer_id)?;
    Ok(trust_graph::Revoke::signature_bytes(
        &public_key,
        Duration::from_secs(revoked_at),
    ))
}

pub fn issue_revocation_impl(
    revoked_peer_id: String,
    revoked_by_peer_id: String,
    revoked_at_sec: u64,
    signature_bytes: Vec<u8>,
) -> Result<Revoke, ServiceError> {
    let revoked_pk = extract_public_key(revoked_peer_id)?;
    let revoked_by_pk = extract_public_key(revoked_by_peer_id)?;

    let revoked_at = Duration::from_secs(revoked_at_sec);
    let signature = Signature::from_bytes(revoked_by_pk.get_key_format(), signature_bytes);
    Ok(trust_graph::Revoke::new(revoked_pk, revoked_by_pk, revoked_at, signature).into())
}

pub fn revoke_impl(revoke: Revoke, timestamp_sec: u64) -> Result<(), ServiceError> {
    check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;

    if revoke.revoked_at > timestamp_sec {
        return Err(ServiceError::InvalidTimestamp("Revoke".to_string()));
    }

    let mut tg = get_data().lock();

    tg.revoke(revoke.try_into()?).map_err(ServiceError::TGError)
}
