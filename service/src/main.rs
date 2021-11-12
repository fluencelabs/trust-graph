#![allow(dead_code)]

use crate::storage_impl::create_tables;
use marine_rs_sdk::module_manifest;
use marine_rs_sdk::WasmLoggerBuilder;

module_manifest!();

mod dto;
mod results;
mod service_api;
mod service_impl;
mod storage_impl;
mod tests;

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::LevelFilter::Trace)
        .build()
        .unwrap();

    create_tables();
}
