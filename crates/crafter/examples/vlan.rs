mod common;

use common::{
    local_ipv4, local_mac, print_help_if_requested, remote_ipv4, remote_mac, ExampleResult,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example vlan --\n\nBuild, compile, and decode an Ethernet 802.1Q VLAN packet offline.",
    ) {
        return Ok(());
    }

    let packet = Ethernet::new()
        .src(local_mac())
        .dst(remote_mac())
        .ethertype(ETHERTYPE_VLAN)
        / Vlan::new().pcp(3).vlan_id(42).ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src(local_ipv4())
            .dst(remote_ipv4())
            .protocol(IPPROTO_UDP)
        / Udp::new().sport(53002).dport(9999)
        / Raw::from("vlan example");
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes())?;
    let vlan = decoded
        .layer::<Vlan>()
        .expect("decoded packet should contain VLAN");

    println!("example: vlan");
    println!("mode: offline");
    println!("decoded summary: {}", decoded.summary());
    println!("vlan id: {}", vlan.vlan_id_value());
    println!("priority: {}", vlan.pcp_value());
    println!("inner ethertype: 0x{:04x}", vlan.ethertype_value());
    if let Some(ipv4) = decoded.layer::<Ipv4>() {
        println!("inner protocol summary: {}", ipv4.summary());
    }
    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
