use marine_rs_sdk::WasmLoggerBuilder;

mod dto;
mod results;
mod service_api;
mod service_impl;
mod storage_impl;
mod tests;

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::LevelFilter::Info)
        .build()
        .unwrap();
}
