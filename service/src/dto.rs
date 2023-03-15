use crate::dto::DtoConversionError::PeerIdDecodeError;
use fluence_keypair::error::DecodingError;
use fluence_keypair::{KeyFormat, PublicKey, Signature};
use libp2p_identity::PeerId;
use marine_rs_sdk::marine;
use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error as ThisError;

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
    #[error("{0}")]
    InvalidKeyFormat(
        #[from]
        #[source]
        fluence_keypair::error::Error,
    ),
}

#[marine]
pub struct Certificate {
    pub chain: Vec<Trust>,
}

impl From<trust_graph::Certificate> for Certificate {
    fn from(c: trust_graph::Certificate) -> Self {
        let chain: Vec<Trust> = c.chain.into_iter().map(|t| t.into()).collect();
        Certificate { chain }
    }
}

impl TryFrom<Certificate> for trust_graph::Certificate {
    type Error = DtoConversionError;

    fn try_from(c: Certificate) -> Result<Self, Self::Error> {
        let chain: Result<Vec<trust_graph::Trust>, DtoConversionError> = c
            .chain
            .into_iter()
            .map(trust_graph::Trust::try_from)
            .collect();
        let chain = chain?;
        Ok(trust_graph::Certificate { chain })
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
        let issued_for = PublicKey::try_from(
            PeerId::from_str(&t.issued_for).map_err(|e| PeerIdDecodeError(format!("{e:?}")))?,
        )
        .map_err(|e| DtoConversionError::PeerIdDecodeError(e.to_string()))?;
        let signature = bs58::decode(&t.signature).into_vec()?;
        let signature = Signature::from_bytes(KeyFormat::from_str(&t.sig_type)?, signature);
        let expires_at = Duration::from_secs(t.expires_at);
        let issued_at = Duration::from_secs(t.issued_at);
        Ok(trust_graph::Trust {
            issued_for,
            expires_at,
            signature,
            issued_at,
        })
    }
}

impl From<trust_graph::Trust> for Trust {
    fn from(t: trust_graph::Trust) -> Self {
        let issued_for = t.issued_for.to_peer_id().to_base58();
        let raw_signature = t.signature.get_raw_signature();
        let signature = bs58::encode(raw_signature.bytes).into_string();
        let expires_at = t.expires_at.as_secs();
        let issued_at = t.issued_at.as_secs();
        Trust {
            issued_for,
            expires_at,
            signature,
            sig_type: raw_signature.sig_type.into(),
            issued_at,
        }
    }
}

#[marine]
#[derive(Default)]
pub struct Revocation {
    /// who is revoked
    pub revoked_peer_id: String,
    /// date when revocation was created
    pub revoked_at: u64,
    /// Signature of a previous trust in a chain.
    /// Signature is self-signed if it is a root trust, base58
    pub signature: String,
    pub sig_type: String,
    /// the issuer of this revocation, base58 peer id
    pub revoked_by: String,
}

impl TryFrom<Revocation> for trust_graph::Revocation {
    type Error = DtoConversionError;

    fn try_from(r: Revocation) -> Result<Self, Self::Error> {
        let revoked_pk = PublicKey::try_from(
            PeerId::from_str(&r.revoked_peer_id)
                .map_err(|e| PeerIdDecodeError(format!("{e:?}")))?,
        )
        .map_err(|e| DtoConversionError::PeerIdDecodeError(e.to_string()))?;
        let revoked_by_pk = PublicKey::try_from(
            PeerId::from_str(&r.revoked_by).map_err(|e| PeerIdDecodeError(format!("{e:?}")))?,
        )
        .map_err(|e| DtoConversionError::PeerIdDecodeError(e.to_string()))?;
        let signature = bs58::decode(&r.signature).into_vec()?;
        let signature = Signature::from_bytes(KeyFormat::from_str(&r.sig_type)?, signature);
        let revoked_at = Duration::from_secs(r.revoked_at);
        Ok(trust_graph::Revocation {
            pk: revoked_pk,
            revoked_at,
            revoked_by: revoked_by_pk,
            signature,
        })
    }
}

impl From<trust_graph::Revocation> for Revocation {
    fn from(r: trust_graph::Revocation) -> Self {
        let revoked_by = r.revoked_by.to_peer_id().to_base58();
        let revoked_peer_id = r.pk.to_peer_id().to_base58();
        let raw_signature = r.signature.get_raw_signature();
        let signature = bs58::encode(raw_signature.bytes).into_string();
        let revoked_at = r.revoked_at.as_secs();
        Revocation {
            revoked_peer_id,
            revoked_at,
            signature,
            sig_type: raw_signature.sig_type.into(),
            revoked_by,
        }
    }
}
