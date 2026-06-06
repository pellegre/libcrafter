mod common;

use common::{
    arg_value, default_target_path, parse_usize_arg, print_help_if_requested, write_example_pcap,
    ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example wire_pcap_sniffer -- [--pcap FILE] [--count N]\n\nRead a generated offline pcap through PacketWire and Sniffer.",
    ) {
        return Ok(());
    }

    let path = arg_value("--pcap")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("examples/wire-pcap-sniffer.pcap"));
    let count = parse_usize_arg("--count", 3)?;

    if !path.exists() {
        let generated = write_example_pcap(&path, count)?;
        println!("created: {} packets at {}", generated.len(), path.display());
    }

    let source = PacketWire::pcap_file(&path).open()?.source()?;
    let records = Sniffer::new(source).count(count).collect_records()?;

    println!("example: wire_pcap_sniffer");
    println!("mode: offline");
    println!("pcap: {}", path.display());
    println!("records: {}", records.len());

    for (index, record) in records.iter().enumerate() {
        let metadata = record.metadata();
        println!("record[{index}] summary: {}", record.packet().summary());
        println!(
            "record[{index}] metadata: origin={:?} backend={:?} file={} link={:?} pcap_link={:?} captured_len={:?} original_len={:?}",
            metadata.origin(),
            metadata.backend(),
            metadata
                .file()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
            metadata.link_type(),
            metadata.pcap_link_type(),
            metadata.captured_len(),
            metadata.original_len()
        );

        if let Some(timestamp) = metadata.timestamp() {
            println!(
                "record[{index}] timestamp: ts_sec={} ts_fractional={}",
                timestamp.seconds(),
                timestamp.fractional()
            );
        }

        if let Some(tcp) = record.packet().layer::<Tcp>() {
            println!(
                "record[{index}] tcp: {} -> {}",
                tcp.source_port_value(),
                tcp.destination_port_value()
            );
        }
    }

    Ok(())
}
