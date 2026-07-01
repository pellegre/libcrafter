mod common;

use std::path::PathBuf;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

const TLS_PCAP_FIXTURE: &str = "tests/fixtures/pcaps/raw-ipv4-tcp-tls-client-hello.pcap";
const TLS_BPF_FILTER: &str = "tcp port 443";

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example tls_pcap_read --\n\nRead the checked-in TLS pcap fixture through PacketWire and print TLS summaries offline.",
    ) {
        return Ok(());
    }

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(TLS_PCAP_FIXTURE);
    let source = PacketWire::pcap_file(&path)
        .filter(TLS_BPF_FILTER)
        .open()?
        .source()?;
    let records = Sniffer::new(source).no_timeout().collect_records()?;

    println!("example: tls_pcap_read");
    println!("mode: offline");
    println!("pcap: {}", path.display());
    println!("filter: {TLS_BPF_FILTER}");
    println!("records: {}", records.len());

    for (index, record) in records.iter().enumerate() {
        print_record(index, record);
    }

    Ok(())
}

fn print_record(index: usize, record: &PacketRecord) {
    let metadata = record.metadata();
    let timestamp = metadata.timestamp();
    println!(
        "record[{index}] ts_sec={} ts_fractional={} captured_len={:?} original_len={:?}",
        timestamp.map(|ts| ts.seconds()).unwrap_or(0),
        timestamp.map(|ts| ts.fractional()).unwrap_or(0),
        metadata.captured_len(),
        metadata.original_len()
    );
    println!("record[{index}] summary: {}", record.packet().summary());

    let tcp = record
        .packet()
        .layer::<Tcp>()
        .expect("TLS pcap record should contain TCP");
    println!(
        "record[{index}] tcp: {} -> {}",
        tcp.source_port_value(),
        tcp.destination_port_value()
    );

    let tls = record
        .packet()
        .layer::<Tls>()
        .expect("TLS pcap record should contain TLS");
    println!("record[{index}] tls records: {}", tls.record_count());
    for (record_index, tls_record) in tls.records().iter().enumerate() {
        println!(
            "record[{index}] tls[{record_index}]: {}",
            tls_record.summary()
        );
    }
}
