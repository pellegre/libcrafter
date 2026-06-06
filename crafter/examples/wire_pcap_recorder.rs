mod common;

use common::{
    arg_value, default_target_path, ensure_parent, example_pcap_packets, parse_usize_arg,
    print_help_if_requested, ExampleResult, EXAMPLE_PCAP_LINK_TYPE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example wire_pcap_recorder -- [--out FILE] [--count N]\n\nWrite generated packet records through PacketWire and Transmitter, then verify the pcap readback.",
    ) {
        return Ok(());
    }

    let path = arg_value("--out")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("examples/wire-pcap-recorder.pcap"));
    let count = parse_usize_arg("--count", 4)?;
    let packets = example_pcap_packets(count)?;

    ensure_parent(&path)?;

    let write_reports = {
        let writer = PacketWire::pcap_recorder(&path, EXAMPLE_PCAP_LINK_TYPE)
            .open()?
            .writer()?;
        let mut transmitter = Transmitter::new(writer);
        let mut reports = Vec::with_capacity(packets.len());

        for packet in packets.iter().cloned() {
            let record = PacketRecord::new(packet).with_pcap_link_type(EXAMPLE_PCAP_LINK_TYPE);
            let mut packet_reports = transmitter.send_record(record)?;
            if packet_reports.len() != 1 {
                return Err(format!(
                    "expected one pcap write report per packet, got {}",
                    packet_reports.len()
                )
                .into());
            }
            reports.push(packet_reports.remove(0));
        }

        reports
    };

    let source = PacketWire::pcap_file(&path).open()?.source()?;
    let records = Sniffer::new(source).count(count).collect_records()?;
    if records.len() != packets.len() {
        return Err(format!(
            "expected {} records after pcap readback, got {}",
            packets.len(),
            records.len()
        )
        .into());
    }

    for record in &records {
        if record.metadata().pcap_link_type() != Some(EXAMPLE_PCAP_LINK_TYPE) {
            return Err(format!(
                "expected readback link type {:?}, got {:?}",
                EXAMPLE_PCAP_LINK_TYPE,
                record.metadata().pcap_link_type()
            )
            .into());
        }
    }

    println!("example: wire_pcap_recorder");
    println!("mode: offline");
    println!("pcap: {}", path.display());
    println!("records written: {}", write_reports.len());
    println!("records read: {}", records.len());
    println!("link_type: {:?}", EXAMPLE_PCAP_LINK_TYPE);

    for (index, report) in write_reports.iter().enumerate() {
        println!(
            "write[{index}]: backend={:?} bytes={} dry_run={} target={}",
            report.backend(),
            report.bytes_written(),
            report.is_dry_run(),
            report.target_details().unwrap_or("-")
        );
    }

    for (index, record) in records.iter().enumerate() {
        println!("record[{index}]: {}", record.packet().summary());
    }

    Ok(())
}
