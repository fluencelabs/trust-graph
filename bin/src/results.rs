use crate::proxy_structs::Certificate;
use fluence::fce;

#[fce]
pub struct InsertResult {
    pub ret_code: u32,
    pub error: String,
}

impl From<Result<(), String>> for InsertResult {
    fn from(result: Result<(), String>) -> Self {
        match result {
            Ok(()) => InsertResult {
                ret_code: 0,
                error: "".to_string(),
            },
            Err(e) => InsertResult {
                ret_code: 1,
                error: e,
            },
        }
    }
}

#[fce]
pub struct WeightResult {
    pub ret_code: u32,
    pub weight: Vec<u32>,
    pub error: String,
}

impl From<Result<Option<u32>, String>> for WeightResult {
    fn from(result: Result<Option<u32>, String>) -> Self {
        match result {
            Ok(wo) => WeightResult {
                ret_code: 0,
                weight: wo.map(|w| vec![w]).unwrap_or(vec![]),
                error: "".to_string(),
            },
            Err(e) => WeightResult {
                ret_code: 1,
                weight: vec![],
                error: e,
            },
        }
    }
}

#[fce]
pub struct AllCertsResult {
    pub ret_code: u32,
    pub certificates: Vec<Certificate>,
    pub error: String,
}

impl From<Result<Vec<Certificate>, String>> for AllCertsResult {
    fn from(result: Result<Vec<Certificate>, String>) -> Self {
        match result {
            Ok(certs) => AllCertsResult {
                ret_code: 0,
                certificates: certs,
                error: "".to_string(),
            },
            Err(e) => AllCertsResult {
                ret_code: 1,
                certificates: vec![],
                error: e,
            },
        }
    }
}
