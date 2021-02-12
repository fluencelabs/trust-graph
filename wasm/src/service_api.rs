use crate::dto::{Certificate, DtoConversionError};
use crate::results::{AllCertsResult, InsertResult, WeightResult};
use crate::storage_impl::get_data;
use fluence::fce;
use fluence_identity::public_key::PKError;
use fluence_identity::{KeyPair, PublicKey};
use std::convert::{Into, TryInto};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;
use trust_graph::{CertificateError, TrustGraphError};

#[derive(ThisError, Debug)]
pub enum ServiceError {
    #[error("{0}")]
    PublicKeyDecodeError(#[from] PKError),
    #[error("{0}")]
    TGError(#[from] TrustGraphError),
    #[error("{0}")]
    CertError(#[from] CertificateError),
    #[error("{0}")]
    DtoError(#[from] DtoConversionError),
}

fn add_cert(certificate: trust_graph::Certificate, duration: u64) -> Result<(), ServiceError> {
    let duration = Duration::from_millis(duration);
    let mut tg = get_data().lock();
    tg.add(certificate, duration)?;
    Ok(())
}

fn insert_cert_impl_raw(certificate: String, duration: u64) -> Result<(), ServiceError> {
    let certificate = trust_graph::Certificate::from_str(&certificate)?;

    add_cert(certificate, duration)?;
    Ok(())
}

fn insert_cert_impl(certificate: Certificate, duration: u64) -> Result<(), ServiceError> {
    let certificate: trust_graph::Certificate = certificate.try_into()?;

    add_cert(certificate, duration)?;
    Ok(())
}

#[fce]
/// add a certificate in string representation to trust graph if it is valid
/// see `trust_graph::Certificate` class for string encoding/decoding
// TODO change `current_time` to time service
fn insert_cert_raw(certificate: String, current_time: u64) -> InsertResult {
    insert_cert_impl_raw(certificate, current_time).into()
}

#[fce]
/// add a certificate in JSON representation to trust graph if it is valid
/// see `dto::Certificate` class for structure
fn insert_cert(certificate: Certificate, current_time: u64) -> InsertResult {
    insert_cert_impl(certificate, current_time).into()
}

fn get_weight_impl(public_key: String) -> Result<Option<u32>, ServiceError> {
    let tg = get_data().lock();

    let public_key = string_to_public_key(public_key)?;

    let weight = tg.weight(public_key)?;

    Ok(weight)
}

#[fce]
fn get_weight(public_key: String) -> WeightResult {
    get_weight_impl(public_key).into()
}

fn string_to_public_key(public_key: String) -> Result<PublicKey, ServiceError> {
    let public_key = PublicKey::from_base58(&public_key)?;

    Ok(public_key)
}

#[fce]
fn get_all_certs(issued_for: String) -> AllCertsResult {
    get_all_certs_impl(issued_for).into()
}

fn get_all_certs_impl(issued_for: String) -> Result<Vec<Certificate>, ServiceError> {
    let tg = get_data().lock();

    let public_key = string_to_public_key(issued_for)?;
    let certs = tg.get_all_certs(public_key, &[])?;
    Ok(certs.into_iter().map(|c| c.into()).collect())
}

#[fce]
fn test() -> String {
    let mut tg = get_data().lock();

    let root_kp = KeyPair::generate();
    let root_kp2 = KeyPair::generate();
    let second_kp = KeyPair::generate();

    let expires_at = Duration::new(15, 15);
    let issued_at = Duration::new(5, 5);

    let cert = trust_graph::Certificate::issue_root(
        &root_kp,
        second_kp.public_key(),
        expires_at,
        issued_at,
    );
    tg.add_root_weight(root_kp.public().into(), 0).unwrap();
    tg.add_root_weight(root_kp2.public().into(), 1).unwrap();
    tg.add(cert, Duration::new(10, 10)).unwrap();

    let a = tg.get(second_kp.public_key()).unwrap();
    let str = format!("{:?}", a);
    log::info!("{}", &str);

    str
}
