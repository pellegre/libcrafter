mod common;

use common::{
    arg_value, default_target_path, print_help_if_requested, write_example_pcap, ExampleResult,
};
use crafter::prelude::*;

fn print_packet(label: &str, index: usize, packet: &PcapPacket) {
    let timestamp = packet.timestamp();
    println!(
        "{label}[{index}] ts_sec={} ts_fractional={} link_type={:?} summary={}",
        timestamp.seconds(),
        timestamp.fractional(),
        packet.pcap_link_type(),
        packet.packet().summary()
    );
}

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example pcap_read -- [--in FILE]\n\nRead an offline pcap through PcapReader collection and streaming APIs.",
    ) {
        return Ok(());
    }

    let path = arg_value("--in")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("examples/pcap-read.pcap"));

    if !path.exists() {
        let generated = write_example_pcap(&path, 3)?;
        println!("created: {} packets at {}", generated.len(), path.display());
    }

    println!("example: pcap_read");
    println!("mode: offline");
    println!("pcap: {}", path.display());

    let reader = PcapReader::open(&path)?;
    let header = reader.header();
    println!(
        "pcap_reader header: link_type={:?} snaplen={} precision={:?}",
        header.pcap_link_type(),
        header.snaplen(),
        header.precision()
    );

    let packets = PcapReader::open(&path)?.collect_packets()?;
    println!("collected packets: {}", packets.len());
    for (index, packet) in packets.iter().enumerate() {
        print_packet("collected", index, packet);
    }

    for (index, record) in reader.records().enumerate() {
        let record = record?;
        let timestamp = record.timestamp();
        let decoded = record.decode()?;
        println!(
            "record[{index}] ts_sec={} ts_fractional={} captured_len={} original_len={} summary={}",
            timestamp.seconds(),
            timestamp.fractional(),
            record.captured_len(),
            record.original_len(),
            decoded.summary()
        );
    }

    Ok(())
}
