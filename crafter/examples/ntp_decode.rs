mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

const NTP_CLIENT_REQUEST: [u8; NTP_FIXED_HEADER_LEN] = [
    0x23, 0x00, 0x06, 0xec, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, b'L', b'O', b'C', b'L',
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xec, 0xc0, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
];

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ntp_decode --\n\nDecode deterministic NTP payload bytes and print summary/show output without live traffic.",
    ) {
        return Ok(());
    }

    let ntp = Ntp::decode(&NTP_CLIENT_REQUEST)?;
    let packet = Packet::from_layer(ntp);
    let compiled = packet.compile()?;

    println!("example: ntp_decode");
    println!("mode: offline");
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());
    println!("roundtrip bytes: {}", compiled.len());
    println!("hexdump:\n{}", compiled.hexdump());
    Ok(())
}
