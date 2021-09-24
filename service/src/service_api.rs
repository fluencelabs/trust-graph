use crate::dto::{Certificate, Trust};
use crate::results::{
    AddRootResult, AddTrustResult, AllCertsResult, GetTrustBytesResult, InsertResult,
    IssueTrustResult, VerifyTrustResult, WeightResult,
};
use crate::service_impl::{
    add_root_impl, add_trust_impl, get_all_certs_impl, get_trust_bytes_imp, get_weight_impl,
    insert_cert_impl, insert_cert_impl_raw, issue_trust_impl, verify_trust_impl,
};
use marine_rs_sdk::{marine, CallParameters};

#[marine]
/// add a certificate in string representation to trust graph if it is valid
/// see `trust_graph::Certificate` class for string encoding/decoding
fn insert_cert_raw(certificate: String, timestamp_sec: u64) -> InsertResult {
    insert_cert_impl_raw(certificate, timestamp_sec).into()
}

#[marine]
/// add a certificate in JSON representation to trust graph if it is valid
/// see `dto::Certificate` class for structure
fn insert_cert(certificate: Certificate, timestamp_sec: u64) -> InsertResult {
    insert_cert_impl(certificate, timestamp_sec).into()
}

#[marine]
fn get_weight(peer_id: String, timestamp_sec: u64) -> WeightResult {
    get_weight_impl(peer_id.clone(), timestamp_sec)
        .map(|w| (w, peer_id))
        .into()
}

// TODO: delete expired
#[marine]
fn get_all_certs(issued_for: String, timestamp_sec: u64) -> AllCertsResult {
    get_all_certs_impl(issued_for, timestamp_sec).into()
}

#[marine]
/// could add only a owner of a trust graph service
fn add_root(peer_id: String, weight_factor: u32) -> AddRootResult {
    let call_parameters: CallParameters = marine_rs_sdk::get_call_parameters();
    let init_peer_id = call_parameters.init_peer_id.clone();
    if call_parameters.service_creator_peer_id == init_peer_id {
        add_root_impl(peer_id, weight_factor).into()
    } else {
        return AddRootResult {
            success: false,
            error: "Root could add only by trust graph service owner".to_string(),
        };
    }
}

#[marine]
fn get_trust_bytes(
    issued_for_peer_id: String,
    expires_at_sec: u64,
    issued_at_sec: u64,
) -> GetTrustBytesResult {
    get_trust_bytes_imp(issued_for_peer_id, expires_at_sec, issued_at_sec).into()
}

#[marine]
fn issue_trust(
    issued_for_peer_id: String,
    expires_at_sec: u64,
    issued_at_sec: u64,
    trust_bytes: Vec<u8>,
) -> IssueTrustResult {
    issue_trust_impl(
        issued_for_peer_id,
        expires_at_sec,
        issued_at_sec,
        trust_bytes,
    )
    .into()
}

#[marine]
fn verify_trust(trust: Trust, issuer_peer_id: String, timestamp_sec: u64) -> VerifyTrustResult {
    verify_trust_impl(trust, issuer_peer_id, timestamp_sec).into()
}

#[marine]
fn add_trust(trust: Trust, issuer_peer_id: String, timestamp_sec: u64) -> AddTrustResult {
    add_trust_impl(trust, issuer_peer_id, timestamp_sec).into()
}
