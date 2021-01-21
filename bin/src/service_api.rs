use crate::storage_impl::get_data;
use fluence::{fce, CallParameters};
use fluence_identity::KeyPair;
use std::ops::Deref;
use std::time::Duration;
use trust_graph::Certificate;

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
