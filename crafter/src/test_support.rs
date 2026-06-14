#[allow(unused_macros)]
macro_rules! fixture_bytes {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/",
            $path
        ))
    };
}

#[allow(unused_macros)]
macro_rules! fixture_str {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/",
            $path
        ))
    };
}
