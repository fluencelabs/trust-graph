use crate::dto::{Certificate, Trust};
use crate::results::{
    AddRootResult, AddTrustResult, AllCertsResult, GetTrustMetadataResult, InsertResult,
    IssueCertificateResult, IssueTrustResult, VerifyTrustResult, WeightResult,
};
use crate::service_impl::{
    add_root_impl, add_trust_impl, get_all_certs_impl, get_trust_metadata_imp, get_weight_impl,
    insert_cert_impl, insert_cert_impl_raw, issue_certificate_with_trust_checked_impl,
    issue_root_certificate_checked_impl, issue_trust_impl, verify_trust_impl,
};
use marine_rs_sdk::{marine, CallParameters};

#[marine]
/// add a certificate in string representation to trust graph if it is valid
/// see `trust_graph::Certificate` class for string encoding/decoding
// TODO change `timestamp_sec` to time service
fn insert_cert_raw(certificate: String, timestamp_sec: u64) -> InsertResult {
    insert_cert_impl_raw(certificate, timestamp_sec).into()
}

#[marine]
/// add a certificate in JSON representation to trust graph if it is valid
/// see `dto::Certificate` class for structure
fn insert_cert(certificate: Certificate, timestamp_sec: u64) -> InsertResult {
    insert_cert_impl(certificate, timestamp_sec).into()
}

// TODO: pass current timestamp, return only valid, delete expired, return max weight
#[marine]
fn get_weight(peer_id: String) -> WeightResult {
    get_weight_impl(peer_id).into()
}

// TODO: pass current timestamp, return only valid, delete expired
#[marine]
fn get_all_certs(issued_for: String) -> AllCertsResult {
    get_all_certs_impl(issued_for).into()
}

// todo: add trust method

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

#[marine]
fn verify_trust(trust: Trust, issuer_peer_id: String, timestamp_sec: u64) -> VerifyTrustResult {
    verify_trust_impl(trust, issuer_peer_id, timestamp_sec).into()
}

#[marine]
fn add_trust(trust: Trust, issuer_peer_id: String, timestamp_sec: u64) -> AddTrustResult {
    add_trust_impl(trust, issuer_peer_id, timestamp_sec).into()
}

// service TrustGraph("trust-graph"):
// -- returns hash of metadata to sign
// get_trust_bytes(issued_for_peer_id: string, expires_at: u64, issued_at: u64) -> GetTrustMetadataResult
//
// -- issued_by needed to identify signature type (ed25519, rsa or secp256k1)
// issue_trust(issued_by_peer_id: string, issued_for_peer_id: string, expires_at: u64, issued_at: u64, signature: []u8) -> IssueTrustResult
//
// -- just verifying signatures, timestamp without inserting into local trust graph
// verify_trust(issued_by_peer_id: string, trust: Trust, timestamp_sec: u64) -> VerifyTrustResult
//
// -- checks signature, timestamp, try to find place to insert, returns max_weight if succeed
// add_trust(issued_by_peer_id: string, trust: Trust, timestamp_sec: u64) -> AddTrustResult
//
// -- add root trust with given weight
// add_root(peer_id: string, trust: Trust, weight: u32) -> AddRootResult
//
// -- return max weight if found, remove expired
// get_weight(issued_for: string, timestamp_sec: u32) -> WeightResult
//
// -- return all certs, remove expired
// get_all_certs(issued_for: string, timestamp_sec) -> AllCertsResult
//
// -- insert full certificate if possible
// insert_cert(certificate: Certificate, current_time: u64) -> InsertResult
// insert_cert_raw(certificate: string, current_time: u64) -> InsertResult
//
// -- returns hash of metadata to sign
// get_revoke_bytes(revoked_peer_id: string, revoked_at: u64, issued_at: u64) -> GetRevokeMetadataResult
//
// -- revoked_by needed to identify signature type (ed25519, rsa or secp256k1)
// issue_revoke(revoked_by_peer_id: string, revoked_peer_id: string, revoked_at: u64, signature: []u8) -> IssueRevokeResult
//
// -- checks signature, checks timestamp
// revoke(revoke: Revoke, timestamp_sec: u64) -> AddRevokeResult
//
// get_all_revocation(revoked_peer_id: string)
//
// -- TODO
// get_trust
