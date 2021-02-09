use crate::storage_impl::get_data;
use fluence::fce;
use fluence_identity::KeyPair;
use std::convert::{From, Into};
use std::fmt::Display;
use std::str::FromStr;
use std::time::Duration;
use trust_graph::Certificate;

struct InsertResult {
    ret_code: u32,
    error: String,
}

impl From<Result<(), String>> for InsertResult {
    fn from(result: Result<(), String>) -> Self {
        match result {
            Ok(()) => InsertResult {
                ret_code: 0,
                error: "".to_string(),
            },
            Err(e) => InsertResult {
                ret_code: 1,
                error: e,
            },
        }
    }
}

fn insert_cert_impl(certificate: String, duration: u64) -> Result<(), String> {
    let duration = Duration::from_millis(duration);
    let certificate = Certificate::from_str(&certificate)?;

    let mut tg = get_data().lock();
    tg.add(certificate, duration)?;
    Ok(())
}

// TODO: some sort of auth?
fn insert_cert(certificate: String, duration: u64) -> InsertResult {
    insert_cert_impl(certificate, duration).into()
}

#[fce]
fn test() -> String {
    let mut tg = get_data().lock();

    let root_kp = KeyPair::generate();
    let root_kp2 = KeyPair::generate();
    let second_kp = KeyPair::generate();

    let expires_at = Duration::new(15, 15);
    let issued_at = Duration::new(5, 5);

    let cert = Certificate::issue_root(&root_kp, second_kp.public_key(), expires_at, issued_at);
    tg.add_root_weight(root_kp.public().into(), 0);
    tg.add_root_weight(root_kp2.public().into(), 1);
    tg.add(cert, Duration::new(10, 10));

    let a = tg.get(second_kp.public_key());
    let str = format!("{:?}", a);
    log::info!("{}", &str);

    str
}
