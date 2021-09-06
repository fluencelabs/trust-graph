use crate::dto::{Certificate, DtoConversionError, Trust};
use crate::storage_impl::get_data;
use fluence_keypair::error::DecodingError;
use fluence_keypair::public_key::peer_id_to_fluence_pk;
use fluence_keypair::{PublicKey, Signature};
use libp2p_core::PeerId;
use std::convert::{Into, TryInto};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;
use trust_graph::{current_time, CertificateError, TrustError, TrustGraphError};

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
}

fn parse_peer_id(peer_id: String) -> Result<PeerId, ServiceError> {
    libp2p_core::PeerId::from_str(&peer_id)
        .map_err(|e| ServiceError::PeerIdParseError(format!("{:?}", e)))
}

fn extract_public_key(peer_id: String) -> Result<PublicKey, ServiceError> {
    peer_id_to_fluence_pk(parse_peer_id(peer_id)?)
        .map_err(|e| ServiceError::PublicKeyExtractionError(e.to_string()))
}

pub fn get_weight_impl(peer_id: String) -> Result<Option<u32>, ServiceError> {
    let tg = get_data().lock();
    let public_key = extract_public_key(peer_id)?;
    let weight = tg.weight(public_key)?;
    Ok(weight)
}

fn add_cert(certificate: trust_graph::Certificate, duration: u64) -> Result<(), ServiceError> {
    let duration = Duration::from_millis(duration);
    let mut tg = get_data().lock();
    tg.add(certificate, duration)?;
    Ok(())
}

pub fn insert_cert_impl_raw(certificate: String, duration: u64) -> Result<(), ServiceError> {
    let certificate = trust_graph::Certificate::from_str(&certificate)?;

    add_cert(certificate, duration)?;
    Ok(())
}

fn string_to_public_key(public_key: String) -> Result<PublicKey, ServiceError> {
    let public_key = PublicKey::from_base58(&public_key)?;

    Ok(public_key)
}

pub fn get_all_certs_impl(issued_for: String) -> Result<Vec<Certificate>, ServiceError> {
    let tg = get_data().lock();

    let public_key = extract_public_key(issued_for)?;
    let certs = tg.get_all_certs(public_key, &[])?;
    Ok(certs.into_iter().map(|c| c.into()).collect())
}

pub fn insert_cert_impl(certificate: Certificate, duration: u64) -> Result<(), ServiceError> {
    let certificate: trust_graph::Certificate = certificate.try_into()?;

    add_cert(certificate, duration)?;
    Ok(())
}

pub fn add_root_impl(peer_id: String, weight: u32) -> Result<(), ServiceError> {
    let mut tg = get_data().lock();
    let public_key = extract_public_key(peer_id)?;
    tg.add_root_weight(public_key, weight)?;
    Ok(())
}

pub fn get_trust_metadata_imp(
    peer_id: String,
    expires_at: u64,
    issued_at: u64,
) -> Result<Vec<u8>, ServiceError> {
    let public_key = extract_public_key(peer_id)?;
    Ok(trust_graph::Trust::metadata_bytes(
        &public_key,
        Duration::from_secs(expires_at),
        Duration::from_secs(issued_at),
    ))
}

pub fn issue_trust_impl(
    peer_id: String,
    expires_at: u64,
    issued_at: u64,
    signed_metadata: Vec<u8>,
) -> Result<Trust, ServiceError> {
    let public_key = extract_public_key(peer_id)?;
    let expires_at = Duration::from_secs(expires_at);
    let issued_at = Duration::from_secs(issued_at);
    let signature = Signature::from_bytes_with_public_key(&public_key, signed_metadata);
    Ok(Trust::from(trust_graph::Trust::new(
        public_key, expires_at, issued_at, signature,
    )))
}

pub fn verify_trust_impl(
    trust: Trust,
    issuer_peer_id: String,
    cur_time: u64,
) -> Result<(), ServiceError> {
    let public_key = extract_public_key(issuer_peer_id)?;
    trust_graph::Trust::verify(
        &trust.try_into()?,
        &public_key,
        Duration::from_secs(cur_time),
    )?;

    Ok(())
}

pub fn issue_root_certificate_checked_impl(
    root_trust: Trust,
    issued_trust: Trust,
    cur_time: u64,
) -> Result<Certificate, ServiceError> {
    trust_graph::Certificate::new_from_root_trust(
        root_trust.try_into()?,
        issued_trust.try_into()?,
        Duration::from_secs(cur_time),
    )
    .map(|c| c.into())
    .map_err(ServiceError::CertError)
}

pub fn issue_certificate_with_trust_checked_impl(
    cert: Certificate,
    trust: Trust,
    issued_by: String,
    cur_time: u64,
) -> Result<Certificate, ServiceError> {
    let public_key = extract_public_key(issued_by)?;
    trust_graph::Certificate::issue_with_trust(
        public_key,
        trust.try_into()?,
        &cert.try_into()?,
        Duration::from_secs(cur_time),
    )
    .map(|c| c.into())
    .map_err(ServiceError::CertError)
}
