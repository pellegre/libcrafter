mod common;

use common::{
    arg_value, default_target_path, print_help_if_requested, write_example_pcap, ExampleResult,
};
use crafter::prelude::*;

fn print_record(label: &str, index: usize, record: &PacketRecord) {
    let metadata = record.metadata();
    let timestamp = metadata.timestamp();
    println!(
        "{label}[{index}] ts_sec={} ts_fractional={} captured_len={:?} original_len={:?} link_type={:?} file={} summary={}",
        timestamp.map(|ts| ts.seconds()).unwrap_or(0),
        timestamp.map(|ts| ts.fractional()).unwrap_or(0),
        metadata.captured_len(),
        metadata.original_len(),
        metadata.link_type(),
        metadata.file().map(|path| path.display().to_string()).unwrap_or_else(|| "-".to_string()),
        record.packet().summary()
    );
}

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example pcap_read -- [--in FILE]\n\nRead an offline pcap through PacketWire and Sniffer.",
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

    let source = PacketWire::pcap_file(&path).open()?.source()?;
    let records = Sniffer::new(source).collect_records()?;
    println!("collected records: {}", records.len());
    for (index, record) in records.iter().enumerate() {
        print_record("record", index, record);
    }

    Ok(())
}
