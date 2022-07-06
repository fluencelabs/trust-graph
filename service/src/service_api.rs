use crate::dto::{Certificate, Revocation, Trust};
use crate::error::ServiceError;
use crate::misc::{check_timestamp_tetraplets, extract_public_key, with_tg, wrapped_try};
use crate::results::{
    AddTrustResult, AllCertsResult, ExportRevocationsResult, GetRevokeBytesResult,
    GetTrustBytesResult, InsertResult, IssueRevocationResult, IssueTrustResult, RevokeResult,
    SetRootResult, VerifyTrustResult, WeightResult,
};
use crate::storage_impl::SQLiteStorage;
use fluence_keypair::Signature;
use marine_rs_sdk::{get_call_parameters, marine, CallParameters};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use std::time::Duration;
use trust_graph::TrustGraph;

#[marine]
/// Only service owner can set roots
fn set_root(peer_id: String, max_chain_len: u32) -> SetRootResult {
    let call_parameters: CallParameters = marine_rs_sdk::get_call_parameters();
    let init_peer_id = call_parameters.init_peer_id;
    if call_parameters.service_creator_peer_id == init_peer_id {
        with_tg(|tg| {
            let public_key = extract_public_key(peer_id)?;
            tg.set_root(public_key, max_chain_len)?;
            Ok(())
        })
        .into()
    } else {
        SetRootResult {
            success: false,
            error: ServiceError::NotOwner.to_string(),
        }
    }
}

#[marine]
/// add a certificate in string representation to trust graph if it is valid
/// see `trust_graph::Certificate` class for string encoding/decoding
fn insert_cert_raw(certificate: String, timestamp_sec: u64) -> InsertResult {
    with_tg(|tg| {
        let certificate = trust_graph::Certificate::from_str(&certificate)?;
        let timestamp_sec = Duration::from_secs(timestamp_sec);
        tg.add(certificate, timestamp_sec)?;
        Ok(())
    })
    .into()
}

#[marine]
/// add a certificate in JSON representation to trust graph if it is valid
/// see `dto::Certificate` class for structure
fn insert_cert(certificate: Certificate, timestamp_sec: u64) -> InsertResult {
    with_tg(|tg| {
        let timestamp_sec = Duration::from_secs(timestamp_sec);
        tg.add(
            trust_graph::Certificate::try_from(certificate)?,
            timestamp_sec,
        )?;
        Ok(())
    })
    .into()
}

fn get_certs(
    tg: &mut TrustGraph<SQLiteStorage>,
    issued_for: String,
    timestamp_sec: u64,
) -> Result<Vec<Certificate>, ServiceError> {
    let public_key = extract_public_key(issued_for)?;
    let certs = tg.get_all_certs(public_key, Duration::from_secs(timestamp_sec))?;
    Ok(certs.into_iter().map(|c| c.into()).collect())
}

fn get_certs_from(
    tg: &mut TrustGraph<SQLiteStorage>,
    issued_for: String,
    issuer: String,
    timestamp_sec: u64,
) -> Result<Vec<Certificate>, ServiceError> {
    let issued_for_pk = extract_public_key(issued_for)?;
    let issuer_pk = extract_public_key(issuer)?;
    let certs =
        tg.get_all_certs_from(issued_for_pk, issuer_pk, Duration::from_secs(timestamp_sec))?;
    Ok(certs.into_iter().map(|c| c.into()).collect())
}

#[marine]
fn get_all_certs(issued_for: String, timestamp_sec: u64) -> AllCertsResult {
    with_tg(|tg| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;
        get_certs(tg, issued_for, timestamp_sec)
    })
    .into()
}

#[marine]
fn get_all_certs_from(issued_for: String, issuer: String, timestamp_sec: u64) -> AllCertsResult {
    with_tg(|tg| {
        let cp = get_call_parameters();
        check_timestamp_tetraplets(&cp, 2)?;
        get_certs_from(tg, issued_for, issuer, timestamp_sec)
    })
    .into()
}

#[marine]
fn get_host_certs(timestamp_sec: u64) -> AllCertsResult {
    with_tg(|tg| {
        let cp = marine_rs_sdk::get_call_parameters();
        check_timestamp_tetraplets(&cp, 0)?;
        get_certs(tg, cp.host_id, timestamp_sec)
    })
    .into()
}

#[marine]
fn get_host_certs_from(issuer: String, timestamp_sec: u64) -> AllCertsResult {
    with_tg(|tg| {
        let cp = get_call_parameters();
        check_timestamp_tetraplets(&cp, 1)?;
        get_certs_from(tg, cp.host_id, issuer, timestamp_sec)
    })
    .into()
}

#[marine]
fn get_weight(peer_id: String, timestamp_sec: u64) -> WeightResult {
    with_tg(|tg| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;
        let public_key = extract_public_key(peer_id.clone())?;
        let weight = tg.weight(public_key, Duration::from_secs(timestamp_sec))?;
        Ok(weight)
    })
    .map(|w| (w, peer_id))
    .into()
}

#[marine]
fn get_weight_from(peer_id: String, issuer: String, timestamp_sec: u64) -> WeightResult {
    with_tg(|tg| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;
        let issued_for_pk = extract_public_key(peer_id.clone())?;
        let issuer_pk = extract_public_key(issuer)?;
        let weight =
            tg.weight_from(issued_for_pk, issuer_pk, Duration::from_secs(timestamp_sec))?;
        Ok(weight)
    })
    .map(|w| (w, peer_id))
    .into()
}

#[marine]
fn get_trust_bytes(
    issued_for_peer_id: String,
    expires_at_sec: u64,
    issued_at_sec: u64,
) -> GetTrustBytesResult {
    wrapped_try(|| {
        let public_key = extract_public_key(issued_for_peer_id)?;

        Ok(trust_graph::Trust::signature_bytes(
            &public_key,
            Duration::from_secs(expires_at_sec),
            Duration::from_secs(issued_at_sec),
        ))
    })
    .into()
}

#[marine]
fn issue_trust(
    issued_for_peer_id: String,
    expires_at_sec: u64,
    issued_at_sec: u64,
    trust_bytes: Vec<u8>,
) -> IssueTrustResult {
    wrapped_try(|| {
        let public_key = extract_public_key(issued_for_peer_id)?;
        let expires_at_sec = Duration::from_secs(expires_at_sec);
        let issued_at_sec = Duration::from_secs(issued_at_sec);
        let signature = Signature::from_bytes(public_key.get_key_format(), trust_bytes);
        Ok(Trust::from(trust_graph::Trust::new(
            public_key,
            expires_at_sec,
            issued_at_sec,
            signature,
        )))
    })
    .into()
}

#[marine]
fn verify_trust(trust: Trust, issuer_peer_id: String, timestamp_sec: u64) -> VerifyTrustResult {
    wrapped_try(|| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 2)?;
        let public_key = extract_public_key(issuer_peer_id)?;
        trust_graph::Trust::verify(
            &trust.try_into()?,
            &public_key,
            Duration::from_secs(timestamp_sec),
        )?;

        Ok(())
    })
    .into()
}

#[marine]
fn add_trust(trust: Trust, issuer_peer_id: String, timestamp_sec: u64) -> AddTrustResult {
    with_tg(|tg| {
        let public_key = extract_public_key(issuer_peer_id)?;
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 2)?;

        if trust.issued_at > timestamp_sec {
            return Err(ServiceError::InvalidTimestamp("trust".to_string()));
        }

        Ok(tg.add_trust(
            &trust.try_into()?,
            public_key,
            Duration::from_secs(timestamp_sec),
        )?)
    })
    .into()
}

#[marine]
fn get_revocation_bytes(revoked_peer_id: String, revoked_at: u64) -> GetRevokeBytesResult {
    wrapped_try(|| {
        let public_key = extract_public_key(revoked_peer_id)?;
        Ok(trust_graph::Revocation::signature_bytes(
            &public_key,
            Duration::from_secs(revoked_at),
        ))
    })
    .into()
}

#[marine]
fn issue_revocation(
    revoked_by_peer_id: String,
    revoked_peer_id: String,
    revoked_at_sec: u64,
    signature_bytes: Vec<u8>,
) -> IssueRevocationResult {
    wrapped_try(|| {
        let revoked_pk = extract_public_key(revoked_peer_id)?;
        let revoked_by_pk = extract_public_key(revoked_by_peer_id)?;

        let revoked_at = Duration::from_secs(revoked_at_sec);
        let signature = Signature::from_bytes(revoked_by_pk.get_key_format(), signature_bytes);
        Ok(trust_graph::Revocation::new(revoked_by_pk, revoked_pk, revoked_at, signature).into())
    })
    .into()
}

#[marine]
fn revoke(revoke: Revocation, timestamp_sec: u64) -> RevokeResult {
    with_tg(|tg| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;

        if revoke.revoked_at > timestamp_sec {
            return Err(ServiceError::InvalidTimestamp("revoke".to_string()));
        }

        Ok(tg.revoke(revoke.try_into()?)?)
    })
    .into()
}

#[marine]
fn export_revocations(issued_for: String) -> ExportRevocationsResult {
    with_tg(|tg| {
        let issued_for_pk = extract_public_key(issued_for)?;
        Ok(tg
            .get_revocations(issued_for_pk)?
            .into_iter()
            .map(|r| r.into())
            .collect())
    })
    .into()
}
