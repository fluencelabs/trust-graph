use crate::dto::{Certificate, Revoke, Trust};
use crate::results::{
    AddRootResult, AddTrustResult, AllCertsResult, GetRevokeBytesResult, GetTrustBytesResult,
    InsertResult, IssueRevocationResult, IssueTrustResult, RevokeResult, VerifyTrustResult,
    WeightResult,
};
use crate::service_impl::{
    add_root_impl, add_trust_impl, get_all_certs_impl, get_revoke_bytes_impl, get_trust_bytes_impl,
    get_weight_impl, insert_cert_impl, insert_cert_impl_raw, issue_revocation_impl,
    issue_trust_impl, revoke_impl, verify_trust_impl, ServiceError,
};
use marine_rs_sdk::{marine, CallParameters};
use trust_graph::MAX_WEIGHT_FACTOR;

#[marine]
fn get_weight_factor(max_chain_len: u32) -> u32 {
    MAX_WEIGHT_FACTOR - max_chain_len
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
            error: ServiceError::NotOwner.to_string(),
        };
    }
}

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
fn get_all_certs(issued_for: String, timestamp_sec: u64) -> AllCertsResult {
    get_all_certs_impl(issued_for, timestamp_sec).into()
}

#[marine]
fn get_weight(peer_id: String, timestamp_sec: u64) -> WeightResult {
    get_weight_impl(peer_id.clone(), timestamp_sec)
        .map(|w| (w, peer_id))
        .into()
}

#[marine]
fn get_trust_bytes(
    issued_for_peer_id: String,
    expires_at_sec: u64,
    issued_at_sec: u64,
) -> GetTrustBytesResult {
    get_trust_bytes_impl(issued_for_peer_id, expires_at_sec, issued_at_sec).into()
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

#[marine]
fn get_revoke_bytes(revoked_peer_id: String, revoked_at: u64) -> GetRevokeBytesResult {
    get_revoke_bytes_impl(revoked_peer_id, revoked_at).into()
}

#[marine]
fn issue_revocation(
    revoked_peer_id: String,
    revoked_by_peer_id: String,
    revoked_at_sec: u64,
    signature_bytes: Vec<u8>,
) -> IssueRevocationResult {
    issue_revocation_impl(
        revoked_peer_id,
        revoked_by_peer_id,
        revoked_at_sec,
        signature_bytes,
    )
    .into()
}

#[marine]
fn revoke(revoke: Revoke, timestamp_sec: u64) -> RevokeResult {
    revoke_impl(revoke, timestamp_sec).into()
}
