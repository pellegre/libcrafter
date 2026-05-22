mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example payload_hello_world --\n\nMutate Raw payload layers offline and inspect the compiled packet.",
    ) {
        return Ok(());
    }

    let mut raw = Raw::new();
    raw.extend_from_slice(b"Hello ");
    raw.extend_from_slice(b"World!");

    let mut packet = Packet::from_layer(raw);
    println!("first payload: {:?}", packet.raw_string_lossy()?);

    if let Some(raw_layer) = packet.layer_mut::<Raw>() {
        raw_layer.as_bytes_mut().clear();
        raw_layer.extend_from_slice(b"This is a new Payload");
    }
    println!("mutated payload: {:?}", packet.raw_string_lossy()?);

    let packet = Raw::from("Hello World!") / Raw::from("This is another payload on another layer");
    println!("layered summary: {}", packet.summary());
    println!("layered hexdump:\n{}", packet.hexdump()?);

    Ok(())
}
