use fluence::WasmLoggerBuilder;

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::Level::Info)
        .build()
        .unwrap();
}
