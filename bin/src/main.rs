use fluence::WasmLoggerBuilder;

mod storage_impl;
mod service_api;

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::Level::Info)
        .build()
        .unwrap();
}
