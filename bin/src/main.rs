use fluence::WasmLoggerBuilder;

mod service_api;
mod storage_impl;

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::Level::Info)
        .build()
        .unwrap();
}
