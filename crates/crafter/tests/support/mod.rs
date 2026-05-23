#[allow(unused_macros)]
macro_rules! fixture_bytes {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/",
            $path
        ))
    };
}

#[allow(unused_macros)]
macro_rules! fixture_str {
    ($path:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/",
            $path
        ))
    };
}

#[allow(dead_code)]
pub fn fixture_path(path: impl AsRef<std::path::Path>) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures")
        .join(path)
}
