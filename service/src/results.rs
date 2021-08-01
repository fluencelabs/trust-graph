use crate::dto::Certificate;
use crate::service_impl::ServiceError;
use marine_rs_sdk::marine;

#[marine]
pub struct InsertResult {
    pub ret_code: u32,
    pub error: String,
}

impl From<Result<(), ServiceError>> for InsertResult {
    fn from(result: Result<(), ServiceError>) -> Self {
        match result {
            Ok(()) => InsertResult {
                ret_code: 0,
                error: "".to_string(),
            },
            Err(e) => InsertResult {
                ret_code: 1,
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct WeightResult {
    pub ret_code: u32,
    pub weight: Vec<u32>,
    pub error: String,
}

impl From<Result<Option<u32>, ServiceError>> for WeightResult {
    fn from(result: Result<Option<u32>, ServiceError>) -> Self {
        match result {
            Ok(wo) => WeightResult {
                ret_code: 0,
                weight: wo.map(|w| vec![w]).unwrap_or(vec![]),
                error: "".to_string(),
            },
            Err(e) => WeightResult {
                ret_code: 1,
                weight: vec![],
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct AllCertsResult {
    pub ret_code: u32,
    pub certificates: Vec<Certificate>,
    pub error: String,
}

impl From<Result<Vec<Certificate>, ServiceError>> for AllCertsResult {
    fn from(result: Result<Vec<Certificate>, ServiceError>) -> Self {
        match result {
            Ok(certs) => AllCertsResult {
                ret_code: 0,
                certificates: certs,
                error: "".to_string(),
            },
            Err(e) => AllCertsResult {
                ret_code: 1,
                certificates: vec![],
                error: format!("{}", e),
            },
        }
    }
}

#[marine]
pub struct AddRootResult {
    pub ret_code: u32,
    pub error: String,
}

impl From<Result<(), ServiceError>> for AddRootResult {
    fn from(result: Result<(), ServiceError>) -> Self {
        match result {
            Ok(()) => AddRootResult {
                ret_code: 0,
                error: "".to_string(),
            },
            Err(e) => AddRootResult {
                ret_code: 1,
                error: format!("{}", e),
            },
        }
    }
}
