use fluence::fce;
use fluence_identity::public_key::PKError;
use fluence_identity::signature::SignatureError;
use fluence_identity::{PublicKey, Signature};
use std::convert::TryFrom;
use std::time::Duration;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum DtoConversionError {
    #[error("Cannot convert base58 string to bytes: {0}")]
    Base58Error(#[from] bs58::decode::Error),
    #[error("Cannot convert string to PublicKey: {0}")]
    PublicKeyDecodeError(#[from] PKError),
    #[error("Cannot convert string to PublicKey: {0}")]
    SignatureDecodeError(#[from] SignatureError),
}

#[fce]
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

#[fce]
pub struct Trust {
    /// For whom this certificate is issued, base58
    pub issued_for: String,
    /// Expiration date of a trust, in secs
    pub expires_at: u64,
    /// Signature of a previous trust in a chain.
    /// Signature is self-signed if it is a root trust, base58
    pub signature: String,
    /// Creation time of a trust, in secs
    pub issued_at: u64,
}

impl TryFrom<Trust> for trust_graph::Trust {
    type Error = DtoConversionError;

    fn try_from(t: Trust) -> Result<Self, Self::Error> {
        let issued_for = PublicKey::from_base58(&t.issued_for)?;
        let signature = bs58::decode(&t.signature).into_vec()?;
        let signature = Signature::from_bytes(&signature)?;
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
        let issued_for = bs58::encode(t.issued_for.to_bytes()).into_string();
        let signature = bs58::encode(t.signature.to_bytes()).into_string();
        let expires_at = t.expires_at.as_secs();
        let issued_at = t.issued_at.as_secs();
        return Trust {
            issued_for,
            expires_at,
            signature,
            issued_at,
        };
    }
}
