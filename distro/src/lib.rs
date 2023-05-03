pub const TRUST_GRAPH_WASM: &'static [u8] =
    include_bytes!("../trust-graph-service/trust-graph.wasm");
pub const SQLITE_WASM: &'static [u8] = include_bytes!("../trust-graph-service/sqlite3.wasm");
pub const CONFIG: &'static [u8] = include_bytes!("../trust-graph-service/Config.toml");

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
