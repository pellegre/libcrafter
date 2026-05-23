mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::{
    arg_value, default_target_path, ensure_parent, parse_usize_arg, print_help_if_requested,
    ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example capture_pcap -- --iface IFACE --out FILE [--filter EXPR] [--count N] [--timeout-seconds N]\n\nCapture packets from an interface with libpcap and write a pcap file.",
    ) {
        return Ok(());
    }

    let iface = arg_value("--iface").unwrap_or_else(|| "lo".to_string());
    let out: PathBuf = arg_value("--out")
        .map(Into::into)
        .unwrap_or_else(|| default_target_path("libcrafter-capture.pcap"));
    let filter = arg_value("--filter");
    let count = parse_usize_arg("--count", 1)?;
    let timeout_seconds = parse_usize_arg("--timeout-seconds", 15)?;

    ensure_parent(&out)?;

    let mut sniffer = Sniffer::interface(iface.clone())
        .count(count)
        .timeout(Duration::from_secs(timeout_seconds as u64));
    if let Some(filter) = filter {
        sniffer = sniffer.filter(filter);
    }

    let packets = sniffer.collect()?;
    let Some(first) = packets.first() else {
        return Err("no packets captured".into());
    };

    let link_type = first.pcap_link_type();
    let mut writer = PcapWriter::create(&out, link_type)?;
    for packet in &packets {
        if packet.pcap_link_type() != link_type {
            return Err("capture returned mixed pcap link types".into());
        }
        writer.write_packet_with_timestamp(packet.packet(), packet.timestamp())?;
    }
    writer.flush()?;

    println!("interface: {iface}");
    println!("pcap: {}", out.display());
    println!("packets: {}", packets.len());
    println!("link_type: {:?}", link_type);

    Ok(())
}
