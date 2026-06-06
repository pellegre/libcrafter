mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::{
    arg_or, arg_value, default_target_path, ensure_parent, live_mode, parse_usize_arg,
    print_help_if_requested, ExampleResult, ADVANCED_LIVE_ACK_FLAG, EXAMPLE_IFACE, LIVE_WIRE_ENV,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example capture_pcap -- [--live] [--iface IFACE] [--out FILE] [--filter EXPR] [--count N] [--timeout-seconds N]\n\nPrint a live capture plan by default; only --live opens libpcap and writes captured packets.",
    ) {
        return Ok(());
    }

    let iface = arg_or("--iface", EXAMPLE_IFACE);
    let out: PathBuf = arg_value("--out")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("examples/capture.pcap"));
    let filter = arg_value("--filter");
    let count = parse_usize_arg("--count", 1)?;
    let timeout_seconds = parse_usize_arg("--timeout-seconds", 15)?;
    let live = live_mode("capture_pcap")?;

    println!("example: capture_pcap");
    println!("interface: {iface}");
    println!("filter: {}", filter.as_deref().unwrap_or("(none)"));
    println!("count: {count}");
    println!("timeout_seconds: {timeout_seconds}");
    println!("pcap: {}", out.display());

    if !live {
        println!("mode: plan");
        println!(
            "safety: no live capture handle opened; add --live, {ADVANCED_LIVE_ACK_FLAG}, and {LIVE_WIRE_ENV}=1 on an isolated wire endpoint"
        );
        return Ok(());
    }

    println!("mode: wire-endpoint");
    println!("safety: live capture guard satisfied");
    ensure_parent(&out)?;

    let timeout = Duration::from_secs(timeout_seconds as u64);
    let mut wire = PacketWire::pcap_interface(iface.clone()).timeout(timeout);
    if let Some(filter) = filter.as_deref() {
        wire = wire.filter(filter);
    }

    let source = wire.open()?.source()?;
    let packets = Sniffer::new(source)
        .count(count)
        .timeout(timeout)
        .collect_records()?;
    let Some(first) = packets.first() else {
        return Err("no packets captured".into());
    };

    let link_type = first
        .metadata()
        .pcap_link_type()
        .ok_or("capture record is missing pcap link type")?;
    let mut writer = PcapWriter::create(&out, link_type)?;
    for record in &packets {
        if record.metadata().pcap_link_type() != Some(link_type) {
            return Err("capture returned mixed pcap link types".into());
        }
        let timestamp = record
            .metadata()
            .timestamp()
            .ok_or("capture record is missing pcap timestamp")?;
        writer.write_packet_with_timestamp(record.packet(), timestamp)?;
    }
    writer.flush()?;

    println!("packets: {}", packets.len());
    println!("link_type: {:?}", link_type);

    Ok(())
}
