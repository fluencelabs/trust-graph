use marine_rs_sdk::marine;
use fluence_keypair::error::DecodingError;
use fluence_keypair::{Signature};
use std::convert::TryFrom;
use std::time::Duration;
use thiserror::Error as ThisError;
use libp2p_core::PeerId;
use fluence_keypair::public_key::peer_id_to_fluence_pk;
use std::str::FromStr;
use fluence_keypair::signature::RawSignature;
use crate::dto::DtoConversionError::PeerIdDecodeError;

#[derive(ThisError, Debug)]
pub enum DtoConversionError {
    #[error("Cannot convert base58 string to bytes: {0}")]
    Base58Error(
        #[from]
        #[source]
        bs58::decode::Error,
    ),
    #[error("Cannot convert string to PublicKey: {0}")]
    PublicKeyDecodeError(
        #[from]
        #[source]
        DecodingError,
    ),
    #[error("Cannot decode peer id from string: {0}")]
    PeerIdDecodeError(String),
}

#[marine]
pub struct Certificate {
    pub chain: Vec<Trust>,
}

impl From<trust_graph::Certificate> for Certificate {
    fn from(c: trust_graph::Certificate) -> Self {
        let chain: Vec<Trust> = c.chain.into_iter().map(|t| t.into()).collect();
        return Certificate { chain };
    }
}

impl TryFrom<Certificate> for trust_graph::Certificate {
    type Error = DtoConversionError;

    fn try_from(c: Certificate) -> Result<Self, Self::Error> {
        let chain: Result<Vec<trust_graph::Trust>, DtoConversionError> = c
            .chain
            .into_iter()
            .map(|t| trust_graph::Trust::try_from(t))
            .collect();
        let chain = chain?;
        return Ok(trust_graph::Certificate { chain });
    }
}

#[marine]
#[derive(Default)]
pub struct Trust {
    /// For whom this certificate is issued, base58 peer_id
    pub issued_for: String,
    /// Expiration date of a trust, in secs
    pub expires_at: u64,
    /// Signature of a previous trust in a chain.
    /// Signature is self-signed if it is a root trust, base58
    pub signature: String,
    pub sig_type: String,
    /// Creation time of a trust, in secs
    pub issued_at: u64,
}

impl TryFrom<Trust> for trust_graph::Trust {
    type Error = DtoConversionError;

    fn try_from(t: Trust) -> Result<Self, Self::Error> {
        let issued_for = peer_id_to_fluence_pk(PeerId::from_str(&t.issued_for)
            .map_err(|e| PeerIdDecodeError(format!("{:?}", e)))?)
            .map_err(|e| DtoConversionError::PeerIdDecodeError(e.to_string()))?;
        let signature = bs58::decode(&t.signature).into_vec()?;
        let signature = Signature::from_raw_signature(RawSignature { bytes: signature, sig_type: t.sig_type })?;
        let expires_at = Duration::from_secs(t.expires_at);
        let issued_at = Duration::from_secs(t.issued_at);
        return Ok(trust_graph::Trust {
            issued_for,
            expires_at,
            signature,
            issued_at,
        });
    }
}

impl From<trust_graph::Trust> for Trust {
    fn from(t: trust_graph::Trust) -> Self {
        let issued_for = t.issued_for.to_peer_id().to_base58();
        let raw_signature = t.signature.get_raw_signature();
        let signature = bs58::encode(raw_signature.bytes).into_string();
        let expires_at = t.expires_at.as_secs();
        let issued_at = t.issued_at.as_secs();
        return Trust {
            issued_for,
            expires_at,
            signature,
            sig_type: raw_signature.sig_type,
            issued_at,
        };
    }
}