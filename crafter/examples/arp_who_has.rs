mod common;

use common::{
    gateway_ipv4, local_ipv4, local_mac, print_help_if_requested, ExampleResult, EXAMPLE_IFACE,
};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example arp_who_has --\n\nBuild an Ethernet broadcast ARP who-has frame and inspect a link-layer dry-run send plan.",
    ) {
        return Ok(());
    }

    let packet = Ethernet::new()
        .src(local_mac())
        .dst(MacAddr::BROADCAST)
        .ethertype(ETHERTYPE_ARP)
        / Arp::who_has(local_ipv4(), gateway_ipv4(), local_mac());
    let arp = packet
        .layer::<Arp>()
        .expect("constructed packet should contain ARP");
    let report = packet.send(
        SendOptions::new()
            .iface(EXAMPLE_IFACE)
            .link_layer()
            .dry_run(),
    )?;

    let opcode = arp.opcode_value();
    let operation = ArpOperation::from_opcode(opcode)
        .map(|op| op.label().to_string())
        .unwrap_or_else(|| format!("unknown({opcode})"));
    let hardware_type = format!(
        "{} (0x{:04x})",
        arp.hardware_type_label().unwrap_or("unknown"),
        arp.hardware_type_value()
    );
    let protocol_type = format!(
        "{} (0x{:04x})",
        arp.protocol_type_label().unwrap_or("unknown"),
        arp.protocol_type_value()
    );

    println!("example: arp_who_has");
    println!("mode: dry-run");
    println!("summary: {}", packet.summary());
    println!("operation: {operation} (opcode {opcode})");
    println!("hardware type: {hardware_type}");
    println!("protocol type: {protocol_type}");
    println!(
        "address lengths: hardware {}, protocol {}",
        arp.hardware_len_value(),
        arp.protocol_len_value()
    );
    println!("sender mac: {}", arp.sender_mac().unwrap_or(local_mac()));
    println!("sender ip: {}", arp.sender_ipv4().unwrap_or(local_ipv4()));
    println!("target mac: {}", arp.target_mac().unwrap_or(MacAddr::ZERO));
    println!("target ip: {}", arp.target_ipv4().unwrap_or(gateway_ipv4()));
    println!(
        "reply filter: {}",
        reply_filter(&packet).unwrap_or_default()
    );
    println!("interface: {}", report.plan().interface());
    println!("target: {:?}", report.plan().target());
    println!("bytes planned: {}", report.bytes_sent());
    println!("show:\n{}", packet.show());
    println!("hexdump:\n{}", report.plan().compiled_packet().hexdump());

    Ok(())
}
