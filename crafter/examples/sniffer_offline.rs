mod common;

use common::{
    arg_or, arg_value, default_target_path, parse_usize_arg, print_help_if_requested,
    write_example_pcap, ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example sniffer_offline -- [--pcap FILE] [--filter EXPR] [--count N]\n\nRead packets from an offline pcap with Sniffer and inspect decoded layers.",
    ) {
        return Ok(());
    }

    let path = arg_value("--pcap")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("examples/sniffer-offline.pcap"));
    let filter = arg_or("--filter", "tcp");
    let count = parse_usize_arg("--count", 5)?;

    if !path.exists() {
        let generated = write_example_pcap(&path, count)?;
        println!("created: {} packets at {}", generated.len(), path.display());
    }

    let source = PacketWire::pcap_file(&path)
        .filter(&filter)
        .open()?
        .source()?;
    let packets = Sniffer::new(source).count(count).collect_records()?;

    println!("example: sniffer_offline");
    println!("mode: offline");
    println!("pcap: {}", path.display());
    println!("filter: {filter}");
    println!("packets: {}", packets.len());

    for (index, record) in packets.iter().enumerate() {
        let packet = record.packet();
        println!("packet[{index}]: {}", packet.summary());

        if let Some(tcp) = packet.layer::<Tcp>() {
            println!(
                "packet[{index}] tcp: {} -> {}",
                tcp.source_port_value(),
                tcp.destination_port_value()
            );
        }
        if let Some(raw) = packet.layer::<Raw>() {
            println!("packet[{index}] raw: {:?}", raw.raw_string_lossy());
        }
    }

    Ok(())
}
