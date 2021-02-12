use crate::dto::Certificate;
use crate::results::{AddRootResult, AllCertsResult, InsertResult, WeightResult};
use crate::service_impl::{
    add_root_impl, get_all_certs_impl, get_weight_impl, insert_cert_impl, insert_cert_impl_raw,
};
use fluence::{fce, CallParameters};

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

#[fce]
fn get_weight(public_key: String) -> WeightResult {
    get_weight_impl(public_key).into()
}

#[fce]
fn get_all_certs(issued_for: String) -> AllCertsResult {
    get_all_certs_impl(issued_for).into()
}

#[fce]
/// could add only a host of a trust graph service
fn add_root(pk: String, weight: u32) -> AddRootResult {
    let call_parameters: CallParameters = fluence::get_call_parameters();
    let init_peer_id = call_parameters.init_peer_id.clone();
    if call_parameters.host_id == init_peer_id {
        add_root_impl(pk, weight).into()
    } else {
        return AddRootResult {
            ret_code: 1,
            error: "Root could add only a host of trust graph service",
        };
    }
}

// TODO rewrite test after #[fce_test] will be implemented
// #[fce]
// fn test() -> String {
//     let mut tg = get_data().lock();
//
//     let root_kp = KeyPair::generate();
//     let root_kp2 = KeyPair::generate();
//     let second_kp = KeyPair::generate();
//
//     let expires_at = Duration::new(15, 15);
//     let issued_at = Duration::new(5, 5);
//
//     let cert = trust_graph::Certificate::issue_root(
//         &root_kp,
//         second_kp.public_key(),
//         expires_at,
//         issued_at,
//     );
//     tg.add_root_weight(root_kp.public().into(), 0).unwrap();
//     tg.add_root_weight(root_kp2.public().into(), 1).unwrap();
//     tg.add(cert, Duration::new(10, 10)).unwrap();
//
//     let a = tg.get(second_kp.public_key()).unwrap();
//     let str = format!("{:?}", a);
//     log::info!("{}", &str);
//
//     str
// }
