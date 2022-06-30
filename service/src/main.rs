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
/*
   _initialize function that calls __wasm_call_ctors is required to mitigade memory leak
   that is described in https://github.com/WebAssembly/wasi-libc/issues/298

   In short, without this code rust wraps every export function
   with __wasm_call_ctors/__wasm_call_dtors calls. This causes memory leaks. When compiler sees
   an explicit call to __wasm_call_ctors in _initialize function, it disables export wrapping.

   TODO: remove when updating to marine-rs-sdk with fix
*/
extern "C" {
    pub fn __wasm_call_ctors();
}

#[no_mangle]
fn _initialize() {
    unsafe {
        __wasm_call_ctors();
    }
}
//------------------------------
pub static TRUSTED_TIMESTAMP: (&str, &str) = ("peer", "timestamp_sec");

pub fn main() {
    _initialize(); // As __wasm_call_ctors still does necessary work, we call it at the start of the module
    WasmLoggerBuilder::new()
        .with_log_level(log::LevelFilter::Trace)
        .build()
        .unwrap();

    create_tables();
}
