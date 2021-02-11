use fluence::fce;

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
