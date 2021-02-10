use crate::proxy_structs::Certificate;
use crate::results::{AllCertsResult, InsertResult, WeightResult};
use crate::storage_impl::get_data;
use fluence::fce;
use fluence_identity::{KeyPair, PublicKey};
use std::convert::{From, Into};
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;
use trust_graph::Certificate as TGCertificate;

fn insert_cert_impl(certificate: String, duration: u64) -> Result<(), String> {
    let duration = Duration::from_millis(duration);
    let certificate = TGCertificate::from_str(&certificate)?;

    let mut tg = get_data().lock();
    tg.add(certificate, duration)?;
    Ok(())
}

#[fce]
// TODO: some sort of auth?
fn insert_cert(certificate: String, duration: u64) -> InsertResult {
    insert_cert_impl(certificate, duration).into()
}

fn get_weight_impl(public_key: String) -> Result<Option<u32>, String> {
    let mut tg = get_data().lock();

    let public_key = string_to_public_key(public_key)?;

    let weight = tg.weight(public_key)?;

    Ok(weight)
}

#[fce]
fn get_weight(public_key: String) -> WeightResult {
    get_weight_impl(public_key).into()
}

fn string_to_public_key(public_key: String) -> Result<PublicKey, String> {
    let public_key = bs58::decode(public_key)
        .into_vec()
        .map_err(|e| format!("Couldn't decode public_key from base58: {}", e))?;
    let public_key = PublicKey::from_bytes(&public_key)
        .map_err(|e| format!("Couldn't decode public_key: {}", e))?;

    Ok(public_key)
}

fn get_all_certs(issued_for: String) -> AllCertsResult {
    get_all_certs_impl(issued_for).into()
}

fn get_all_certs_impl(issued_for: String) -> Result<Vec<Certificate>, String> {
    let mut tg = get_data().lock();

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

    let cert = TGCertificate::issue_root(&root_kp, second_kp.public_key(), expires_at, issued_at);
    tg.add_root_weight(root_kp.public().into(), 0).unwrap();
    tg.add_root_weight(root_kp2.public().into(), 1).unwrap();
    tg.add(cert, Duration::new(10, 10)).unwrap();

    let a = tg.get(second_kp.public_key()).unwrap();
    let str = format!("{:?}", a);
    log::info!("{}", &str);

    str
}
