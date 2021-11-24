#![allow(dead_code)]

use crate::storage_impl::create_tables;
use marine_rs_sdk::module_manifest;
use marine_rs_sdk::WasmLoggerBuilder;

module_manifest!();

mod dto;
mod error;
mod misc;
mod results;
mod service_api;
mod storage_impl;
mod tests;

pub static TRUSTED_TIMESTAMP_SERVICE_ID: &str = "peer";
pub static TRUSTED_TIMESTAMP_FUNCTION_NAME: &str = "timestamp_sec";

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::LevelFilter::Trace)
        .build()
        .unwrap();

    create_tables();
}
