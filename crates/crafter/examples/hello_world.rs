mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example hello_world -- [--dry-run]\n\nBuild and inspect a Raw/Raw Hello World packet without sending traffic.",
    ) {
        return Ok(());
    }

    let packet = Packet::new()
        .push(Raw::from("Hello "))
        .push(Raw::from("World!"));
    let compiled = packet.compile()?;

    println!("mode: dry-run");
    println!("summary: {}", packet.summary());
    println!("{}", packet.show());
    println!("hexdump:\n{}", compiled.hexdump());
    println!("raw string: {:?}", packet.raw_string_lossy()?);

    Ok(())
}
