use serde::{Deserialize, Serialize};
use lazy_static::lazy_static;

pub const TRUST_GRAPH_WASM: &'static [u8] =
    include_bytes!("../trust-graph-service/trust-graph.wasm");
pub const SQLITE_WASM: &'static [u8] = include_bytes!("../trust-graph-service/sqlite3.wasm");
pub const CONFIG: &'static [u8] = include_bytes!("../trust-graph-service/Config.toml");

pub const KRAS_CERTS_JSON: &'static str = include_str!("../trust-graph-service/on_start.json");

pub mod build_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub use build_info::PKG_VERSION as VERSION;

pub fn modules() -> std::collections::HashMap<&'static str, &'static [u8]> {
    maplit::hashmap! {
        "sqlite3" => SQLITE_WASM,
        "trust-graph" => TRUST_GRAPH_WASM,
    }
}

#[derive(Deserialize, Serialize)]
pub struct Certs {
    pub root_node: String,
    pub max_chain_length: u32,
    pub certs: Vec<Cert>,
}

#[derive(Deserialize, Serialize)]
pub struct Cert {
    pub chain: Vec<Trust>,
}

#[derive(Deserialize, Serialize)]
pub struct Trust {
    pub issued_for: String,
    pub expires_at: u64,
    pub signature: String,
    pub sig_type: String,
    pub issued_at: u64,
}

lazy_static! {
    pub static ref KRAS_CERTS: Certs = serde_json::from_str(&KRAS_CERTS_JSON).unwrap();
}
