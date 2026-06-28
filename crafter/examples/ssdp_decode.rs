mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

const FIXTURES: &[(&str, &[u8])] = &[
    (
        "m-search",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ssdp/valid-m-search.ssdp"
        )),
    ),
    (
        "notify",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ssdp/valid-notify.ssdp"
        )),
    ),
    (
        "response",
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ssdp/valid-response.ssdp"
        )),
    ),
];

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ssdp_decode --\n\nDecode tracked SSDP payload fixtures and print summaries without live capture.",
    ) {
        return Ok(());
    }

    println!("example: ssdp_decode");
    println!("mode: offline");

    for (label, bytes) in FIXTURES {
        let ssdp = Ssdp::parse(bytes)?;
        let packet = Packet::from_layer(ssdp);

        println!("{label} bytes: {}", bytes.len());
        println!("{label} summary: {}", packet.summary());
        println!("{label} show:\n{}", packet.show());
    }

    Ok(())
}
