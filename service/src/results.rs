use crate::dto::{Certificate, Trust};
use crate::service_impl::ServiceError;
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
    pub weight: Vec<u32>,
    pub error: String,
}

impl From<Result<Option<u32>, ServiceError>> for WeightResult {
    fn from(result: Result<Option<u32>, ServiceError>) -> Self {
        match result {
            Ok(wo) => WeightResult {
                success: true,
                weight: wo.map(|w| vec![w]).unwrap_or(vec![]),
                error: "".to_string(),
            },
            Err(e) => WeightResult {
                success: false,
                weight: vec![],
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
pub struct GetTrustMetadataResult {
    pub success: bool,
    pub error: String,
    pub result: Vec<u8>,
}

impl From<Result<Vec<u8>, ServiceError>> for GetTrustMetadataResult {
    fn from(result: Result<Vec<u8>, ServiceError>) -> Self {
        match result {
            Ok(res) => GetTrustMetadataResult {
                success: true,
                error: "".to_string(),
                result: res
            },
            Err(e) => GetTrustMetadataResult {
                success: false,
                error: format!("{}", e),
                result: vec![]
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
