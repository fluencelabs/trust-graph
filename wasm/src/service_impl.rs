use crate::dto::{Certificate, DtoConversionError};
use crate::storage_impl::get_data;
use fluence_identity::public_key::PKError;
use fluence_identity::PublicKey;
use std::convert::{Into, TryInto};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;
use trust_graph::{CertificateError, TrustGraphError};

#[derive(ThisError, Debug)]
pub enum ServiceError {
    #[error(transparent)]
    PublicKeyDecodeError(#[from] PKError),
    #[error(transparent)]
    TGError(#[from] TrustGraphError),
    #[error(transparent)]
    CertError(#[from] CertificateError),
    #[error(transparent)]
    DtoError(#[from] DtoConversionError),
}

pub fn get_weight_impl(public_key: String) -> Result<Option<u32>, ServiceError> {
    let tg = get_data().lock();
    let public_key = string_to_public_key(public_key)?;
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

    let public_key = string_to_public_key(issued_for)?;
    let certs = tg.get_all_certs(public_key, &[])?;
    Ok(certs.into_iter().map(|c| c.into()).collect())
}

pub fn insert_cert_impl(certificate: Certificate, duration: u64) -> Result<(), ServiceError> {
    let certificate: trust_graph::Certificate = certificate.try_into()?;

    add_cert(certificate, duration)?;
    Ok(())
}

pub fn add_root_impl(pk: String, weight: u32) -> Result<(), ServiceError> {
    let mut tg = get_data().lock();
    let pk = PublicKey::from_base58(&pk)?.into();
    tg.add_root_weight(pk, weight)?;
    Ok(())
}
