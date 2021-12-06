use crate::dto::{Certificate, Revocation, Trust};
use crate::error::ServiceError;
use marine_rs_sdk::marine;

#[marine]
pub struct InsertResult {
    pub success: bool,
    pub error: String,
}

impl From<Result<(), ServiceError>> for InsertResult {
    fn from(result: Result<(), ServiceError>) -> Self {
        match result {
            Ok(()) => InsertResult {
                success: true,
                error: "".to_string(),
            },
            Err(e) => InsertResult {
                success: false,
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct WeightResult {
    pub success: bool,
    pub weight: u32,
    pub peer_id: String,
    pub error: String,
}

impl From<Result<(u32, String), ServiceError>> for WeightResult {
    fn from(result: Result<(u32, String), ServiceError>) -> Self {
        match result {
            Ok((weight, peer_id)) => WeightResult {
                success: true,
                weight,
                peer_id,
                error: "".to_string(),
            },
            Err(e) => WeightResult {
                success: false,
                weight: 0u32,
                peer_id: "".to_string(),
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct AllCertsResult {
    pub success: bool,
    pub certificates: Vec<Certificate>,
    pub error: String,
}

impl From<Result<Vec<Certificate>, ServiceError>> for AllCertsResult {
    fn from(result: Result<Vec<Certificate>, ServiceError>) -> Self {
        match result {
            Ok(certs) => AllCertsResult {
                success: true,
                certificates: certs,
                error: "".to_string(),
            },
            Err(e) => AllCertsResult {
                success: false,
                certificates: vec![],
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct AddRootResult {
    pub success: bool,
    pub error: String,
}

impl From<Result<(), ServiceError>> for AddRootResult {
    fn from(result: Result<(), ServiceError>) -> Self {
        match result {
            Ok(()) => AddRootResult {
                success: true,
                error: "".to_string(),
            },
            Err(e) => AddRootResult {
                success: false,
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct GetTrustBytesResult {
    pub success: bool,
    pub error: String,
    pub result: Vec<u8>,
}

impl From<Result<Vec<u8>, ServiceError>> for GetTrustBytesResult {
    fn from(result: Result<Vec<u8>, ServiceError>) -> Self {
        match result {
            Ok(res) => GetTrustBytesResult {
                success: true,
                error: "".to_string(),
                result: res,
            },
            Err(e) => GetTrustBytesResult {
                success: false,
                error: format!("{}", e),
                result: vec![],
            },
        }
    }
}

#[marine]
pub struct IssueTrustResult {
    pub success: bool,
    pub error: String,
    pub trust: Trust,
}

impl From<Result<Trust, ServiceError>> for IssueTrustResult {
    fn from(result: Result<Trust, ServiceError>) -> Self {
        match result {
            Ok(trust) => IssueTrustResult {
                success: true,
                error: "".to_string(),
                trust,
            },
            Err(e) => IssueTrustResult {
                success: false,
                error: format!("{}", e),
                trust: Trust::default(),
            },
        }
    }
}

#[marine]
pub struct VerifyTrustResult {
    pub success: bool,
    pub error: String,
}

impl From<Result<(), ServiceError>> for VerifyTrustResult {
    fn from(result: Result<(), ServiceError>) -> Self {
        match result {
            Ok(()) => VerifyTrustResult {
                success: true,
                error: "".to_string(),
            },
            Err(e) => VerifyTrustResult {
                success: false,
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct AddTrustResult {
    pub success: bool,
    pub error: String,
    pub weight: u32,
}

impl From<Result<u32, ServiceError>> for AddTrustResult {
    fn from(result: Result<u32, ServiceError>) -> Self {
        match result {
            Ok(weight) => AddTrustResult {
                success: true,
                error: "".to_string(),
                weight,
            },
            Err(e) => AddTrustResult {
                success: false,
                error: format!("{}", e),
                weight: u32::default(),
            },
        }
    }
}

#[marine]
pub struct GetRevokeBytesResult {
    pub success: bool,
    pub error: String,
    pub result: Vec<u8>,
}

impl From<Result<Vec<u8>, ServiceError>> for GetRevokeBytesResult {
    fn from(result: Result<Vec<u8>, ServiceError>) -> Self {
        match result {
            Ok(res) => GetRevokeBytesResult {
                success: true,
                error: "".to_string(),
                result: res,
            },
            Err(e) => GetRevokeBytesResult {
                success: false,
                error: format!("{}", e),
                result: vec![],
            },
        }
    }
}

#[marine]
pub struct IssueRevocationResult {
    pub success: bool,
    pub error: String,
    pub revocation: Revocation,
}

impl From<Result<Revocation, ServiceError>> for IssueRevocationResult {
    fn from(result: Result<Revocation, ServiceError>) -> Self {
        match result {
            Ok(revocation) => IssueRevocationResult {
                success: true,
                error: "".to_string(),
                revocation,
            },
            Err(e) => IssueRevocationResult {
                success: false,
                error: format!("{}", e),
                revocation: Revocation::default(),
            },
        }
    }
}

#[marine]
pub struct RevokeResult {
    pub success: bool,
    pub error: String,
}

impl From<Result<(), ServiceError>> for RevokeResult {
    fn from(result: Result<(), ServiceError>) -> Self {
        match result {
            Ok(()) => RevokeResult {
                success: true,
                error: "".to_string(),
            },
            Err(e) => RevokeResult {
                success: false,
                error: format!("{}", e),
            },
        }
    }
}
