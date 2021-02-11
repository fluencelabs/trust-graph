use fluence::WasmLoggerBuilder;

mod dto;
mod results;
mod service_api;
mod storage_impl;

pub fn main() {
    WasmLoggerBuilder::new()
        .with_log_level(log::Level::Info)
        .build()
        .unwrap();
}

// only option for now is to copy tests from trust graph,
// change connector to sqlite and fix compilation -_-
// TODO: fix it
/*#[cfg(test)]
mod tests {

}*/
