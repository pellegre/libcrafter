mod common;

use common::{
    arg_value, default_target_path, print_help_if_requested, write_example_pcap, ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example read_pcap -- [--in FILE] [--filter EXPR]\n\nRead an offline pcap, decode packets, and print timestamps plus summaries.",
    ) {
        return Ok(());
    }

    let path = arg_value("--in")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("libcrafter-read-pcap.pcap"));

    if !path.exists() {
        write_example_pcap(&path, 3)?;
    }

    let packets = match arg_value("--filter") {
        Some(filter) => read_pcap_filtered(&path, &filter)?,
        None => read_pcap(&path)?,
    };

    println!("pcap: {}", path.display());
    println!("packets: {}", packets.len());
    for packet in packets {
        let ts = packet.timestamp();
        println!(
            "ts_sec={} ts_fractional={} summary={}",
            ts.seconds(),
            ts.fractional(),
            packet.packet().summary()
        );
    }

    Ok(())
}
