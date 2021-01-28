use crate::storage_impl::get_data;
use fluence::fce;
use fluence_identity::KeyPair;
use std::time::Duration;
use trust_graph::Certificate;
use std::str::FromStr;

struct InsertResult {
    ret_code: u32,
    error: String,
}

// TODO: some sort of auth?
fn insert_cert(certificate: String, duration: u64) -> InsertResult {

    let duration = Duration::from_millis(duration);
    let certificate = Certificate::from_str(&certificate).unwrap();

    let mut tg = get_data().lock();
    tg.add(certificate, duration).unwrap();

    return InsertResult {
        ret_code: 0,
        error: "".to_string()
    }
}

#[fce]
fn looper() {

    let second = std::time::Duration::from_millis(1000);

    let mut a = 0;
    while true {
        std::thread::sleep(second);
        a = a + 1;
        log::info!("{}", a)
    }
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
