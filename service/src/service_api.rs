use crate::dto::{Certificate, Trust};
use crate::results::{
    AddRootResult, AllCertsResult, GetTrustMetadataResult, InsertResult, IssueCertificateResult,
    IssueTrustResult, VerifyTrustResult, WeightResult,
};
use crate::service_impl::{
    add_root_impl, get_all_certs_impl, get_trust_metadata_imp, get_weight_impl, insert_cert_impl,
    insert_cert_impl_raw, issue_certificate_with_trust_checked_impl,
    issue_root_certificate_checked_impl, issue_trust_impl, verify_trust_impl,
};
use marine_rs_sdk::{marine, CallParameters};

#[marine]
/// add a certificate in string representation to trust graph if it is valid
/// see `trust_graph::Certificate` class for string encoding/decoding
// TODO change `current_time` to time service
fn insert_cert_raw(certificate: String, current_time: u64) -> InsertResult {
    insert_cert_impl_raw(certificate, current_time).into()
}

#[marine]
/// add a certificate in JSON representation to trust graph if it is valid
/// see `dto::Certificate` class for structure
fn insert_cert(certificate: Certificate, current_time: u64) -> InsertResult {
    insert_cert_impl(certificate, current_time).into()
}

// TODO: pass current timestamp, return only valid, delete expired
#[marine]
fn get_weight(peer_id: String) -> WeightResult {
    get_weight_impl(peer_id).into()
}

// TODO: pass current timestamp, return only valid, delete expired
#[marine]
fn get_all_certs(issued_for: String) -> AllCertsResult {
    get_all_certs_impl(issued_for).into()
}

#[marine]
/// could add only a host of a trust graph service
fn add_root(peer_id: String, weight: u32) -> AddRootResult {
    let call_parameters: CallParameters = marine_rs_sdk::get_call_parameters();
    let init_peer_id = call_parameters.init_peer_id.clone();
    if call_parameters.host_id == init_peer_id {
        add_root_impl(peer_id, weight).into()
    } else {
        return AddRootResult {
            success: false,
            error: "Root could add only a host of trust graph service".to_string(),
        };
    }
}

#[marine]
fn get_trust_metadata(
    issued_for_peer_id: String,
    expires_at: u64,
    issued_at: u64,
) -> GetTrustMetadataResult {
    get_trust_metadata_imp(issued_for_peer_id, expires_at, issued_at).into()
}

#[marine]
fn issue_trust(
    issued_for_peer_id: String,
    expires_at: u64,
    issued_at: u64,
    signed_metadata: Vec<u8>,
) -> IssueTrustResult {
    issue_trust_impl(issued_for_peer_id, expires_at, issued_at, signed_metadata).into()
}

// TODO: use "peer" "timestamp_sec" and check tetraplets
#[marine]
fn verify_trust(trust: Trust, issuer_peer_id: String, cur_time: u64) -> VerifyTrustResult {
    verify_trust_impl(trust, issuer_peer_id, cur_time).into()
}

#[marine]
fn issue_root_certificate_checked(
    root_trust: Trust,
    issued_trust: Trust,
    cur_time: u64,
) -> IssueCertificateResult {
    issue_root_certificate_checked_impl(root_trust, issued_trust, cur_time).into()
}

#[marine]
fn issue_certificate_with_trust_checked(
    cert: Certificate,
    trust: Trust,
    issued_by_peer_id: String,
    cur_time: u64,
) -> IssueCertificateResult {
    issue_certificate_with_trust_checked_impl(cert, trust, issued_by_peer_id, cur_time).into()
}
