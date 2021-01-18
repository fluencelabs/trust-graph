use fluence::WasmLoggerBuilder;

pub(crate) type Result<T> = std::result::Result<T, errors::HistoryError>;

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::Level::Info)
        .build()
        .unwrap();
}