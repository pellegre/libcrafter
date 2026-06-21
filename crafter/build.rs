fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "whad")]
    generate_whad_proto()?;

    #[cfg(not(feature = "whad"))]
    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}

#[cfg(feature = "whad")]
fn generate_whad_proto() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "src/wire/backend/whad/proto/generic.proto",
        "src/wire/backend/whad/proto/device.proto",
        "src/wire/backend/whad/proto/ble.proto",
        "src/wire/backend/whad/proto/whad.proto",
    ];
    let includes = ["src/wire/backend/whad/proto"];

    println!("cargo:rerun-if-changed=src/wire/backend/whad/proto/generic.proto");
    println!("cargo:rerun-if-changed=src/wire/backend/whad/proto/device.proto");
    println!("cargo:rerun-if-changed=src/wire/backend/whad/proto/ble.proto");
    println!("cargo:rerun-if-changed=src/wire/backend/whad/proto/whad.proto");

    let mut config = prost_build::Config::new();
    config.include_file("whad_proto.rs");
    config.compile_protos(&protos, &includes)?;
    Ok(())
}
