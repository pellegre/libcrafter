mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

const STA_MAC: MacAddr = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
const AP_MAC: MacAddr = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example dot11_radiotap_ipv4 --\n\nBuild and decode an offline Radiotap/Dot11/LlcSnap/IPv4 stack.",
    ) {
        return Ok(());
    }

    let dot11 = Dot11::data();
    let to_ds = dot11.frame_control_value().with_to_ds(true);
    let packet = Radiotap::new()
        .rate(12)
        .channel((2412, 0))
        .antenna_signal(-42)
        / dot11
            .frame_control(to_ds)
            .addr1(AP_MAC)
            .addr2(STA_MAC)
            .addr3(AP_MAC)
            .sequence_number(1)
        / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(local_ipv4())
            .dst(remote_ipv4())
            .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(49152).dport(33434)
        / Raw::from("offline dot11 ipv4");

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Radiotap, compiled.as_bytes())?;

    println!("mode: offline");
    println!("summary: {}", packet.summary());
    println!("decoded summary: {}", decoded.summary());
    println!("show:\n{}", decoded.show());
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
