use crate::dto::{Certificate, Revoke, Trust};
use crate::error::ServiceError;
use crate::misc::{check_timestamp_tetraplets, extract_public_key, with_tg, wrapped_try};
use crate::results::{
    AddRootResult, AddTrustResult, AllCertsResult, GetRevokeBytesResult, GetTrustBytesResult,
    InsertResult, IssueRevocationResult, IssueTrustResult, RevokeResult, VerifyTrustResult,
    WeightResult,
};
use crate::storage_impl::SQLiteStorage;
use fluence_keypair::Signature;
use marine_rs_sdk::{get_call_parameters, marine, CallParameters};
use std::cell::RefMut;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;
use std::time::Duration;
use trust_graph::{TrustGraph, MAX_WEIGHT_FACTOR};

#[marine]
fn get_weight_factor(max_chain_len: u32) -> u32 {
    MAX_WEIGHT_FACTOR.checked_sub(max_chain_len).unwrap_or(0u32)
}

#[marine]
/// could add only a owner of a trust graph service
fn add_root(peer_id: String, weight_factor: u32) -> AddRootResult {
    let call_parameters: CallParameters = marine_rs_sdk::get_call_parameters();
    let init_peer_id = call_parameters.init_peer_id;
    if call_parameters.service_creator_peer_id == init_peer_id {
        with_tg(|mut tg| {
            let public_key = extract_public_key(peer_id)?;
            tg.add_root_weight_factor(public_key, weight_factor)?;
            Ok(())
        })
        .into()
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
    with_tg(|mut tg| {
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
    with_tg(|mut tg| {
        let timestamp_sec = Duration::from_secs(timestamp_sec);
        tg.add(
            trust_graph::Certificate::try_from(certificate)?,
            timestamp_sec,
        )?;
        Ok(())
    })
    .into()
}

fn get_certs_helper(
    tg: &mut TrustGraph<SQLiteStorage>,
    issued_for: String,
    timestamp_sec: u64,
) -> Result<Vec<Certificate>, ServiceError> {
    let public_key = extract_public_key(issued_for)?;
    let certs = tg.get_all_certs(public_key, Duration::from_secs(timestamp_sec))?;
    Ok(certs.into_iter().map(|c| c.into()).collect())
}

#[marine]
fn get_all_certs(issued_for: String, timestamp_sec: u64) -> AllCertsResult {
    with_tg(|tg| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;
        get_certs_helper(tg, issued_for, timestamp_sec)
    })
    .into()
}

#[marine]
fn get_host_certs(timestamp_sec: u64) -> AllCertsResult {
    with_tg(|tg| {
        let cp = marine_rs_sdk::get_call_parameters();
        check_timestamp_tetraplets(&cp, 0)?;
        get_certs_helper(tg, cp.host_id, timestamp_sec)
    })
    .into()
}

#[marine]
fn get_host_certs_from(issuer: String, timestamp_sec: u64) -> AllCertsResult {
    with_tg(|tg| {
        let cp = get_call_parameters();
        check_timestamp_tetraplets(&cp, 1)?;
        get_certs_helper(tg, cp.host_id, timestamp_sec).map(|c| {
            c.into_iter()
                .filter(|cert: &Certificate| cert.chain.iter().any(|t| t.issued_for == issuer))
                .collect()
        })
    })
    .into()
}

#[marine]
fn get_weight(peer_id: String, timestamp_sec: u64) -> WeightResult {
    with_tg(|mut tg| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;
        let public_key = extract_public_key(peer_id.clone())?;
        let weight = tg.weight(public_key, Duration::from_secs(timestamp_sec))?;
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
    with_tg(|mut tg| {
        let public_key = extract_public_key(issuer_peer_id)?;
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 2)?;

        if trust.issued_at > timestamp_sec {
            return Err(ServiceError::InvalidTimestamp("trust".to_string()));
        }

        tg.add_trust(
            &trust.try_into()?,
            public_key,
            Duration::from_secs(timestamp_sec),
        )
        .map_err(ServiceError::TGError)
    })
    .into()
}

#[marine]
fn get_revoke_bytes(revoked_peer_id: String, revoked_at: u64) -> GetRevokeBytesResult {
    wrapped_try(|| {
        let public_key = extract_public_key(revoked_peer_id)?;
        Ok(trust_graph::Revoke::signature_bytes(
            &public_key,
            Duration::from_secs(revoked_at),
        ))
    })
    .into()
}

#[marine]
fn issue_revocation(
    revoked_peer_id: String,
    revoked_by_peer_id: String,
    revoked_at_sec: u64,
    signature_bytes: Vec<u8>,
) -> IssueRevocationResult {
    wrapped_try(|| {
        let revoked_pk = extract_public_key(revoked_peer_id)?;
        let revoked_by_pk = extract_public_key(revoked_by_peer_id)?;

        let revoked_at = Duration::from_secs(revoked_at_sec);
        let signature = Signature::from_bytes(revoked_by_pk.get_key_format(), signature_bytes);
        Ok(trust_graph::Revoke::new(revoked_pk, revoked_by_pk, revoked_at, signature).into())
    })
    .into()
}

#[marine]
fn revoke(revoke: Revoke, timestamp_sec: u64) -> RevokeResult {
    with_tg(|mut tg| {
        check_timestamp_tetraplets(&marine_rs_sdk::get_call_parameters(), 1)?;

        if revoke.revoked_at > timestamp_sec {
            return Err(ServiceError::InvalidTimestamp("revoke".to_string()));
        }

        tg.revoke(revoke.try_into()?).map_err(ServiceError::TGError)
    })
    .into()
}
