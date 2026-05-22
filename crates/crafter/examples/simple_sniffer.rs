mod common;

use common::{
    arg_or, arg_value, default_target_path, parse_usize_arg, print_help_if_requested,
    write_example_pcap, ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example simple_sniffer -- [--pcap FILE] [--filter EXPR] [--count N]\n\nRead packets from an offline pcap and handle matching packets without live capture.",
    ) {
        return Ok(());
    }

    let path = arg_value("--pcap")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("libcrafter-simple-sniffer.pcap"));
    let filter = arg_or("--filter", "tcp");
    let count = parse_usize_arg("--count", 5)?;

    if !path.exists() {
        write_example_pcap(&path, count)?;
    }

    let packets = Sniffer::offline(&path)
        .filter(filter)
        .count(count)
        .collect()?;
    println!("offline pcap: {}", path.display());
    println!("captured: {}", packets.len());

    for packet in packets {
        let decoded = packet.packet();
        println!("{}", decoded.summary());

        if let Some(tcp) = decoded.layer::<Tcp>() {
            println!(
                "tcp ports: {} -> {}",
                tcp.source_port_value(),
                tcp.destination_port_value()
            );
        }
        if let Some(raw) = decoded.layer::<Raw>() {
            println!("payload: {:?}", raw.raw_string_lossy());
        }
    }

    Ok(())
}
