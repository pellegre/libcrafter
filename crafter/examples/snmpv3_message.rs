mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example snmpv3_message --\n\nBuild a synthetic SNMPv3 USM Report packet and decode it offline.",
    ) {
        return Ok(());
    }

    let usm = SnmpUsmSecurityParameters::new(
        b"\x80\x00\x00\x00doc-engine".to_vec(),
        1,
        42,
        b"doc-user".to_vec(),
        Vec::<u8>::new(),
        Vec::<u8>::new(),
    );
    let report = Snmp::v3_usm_report(
        3001,
        1500,
        [SNMP_V3_FLAG_REPORTABLE],
        usm,
        b"\x80\x00\x00\x00doc-context".to_vec(),
        b"doc-context".to_vec(),
        7001,
        SnmpVarBindList::new(vec![SnmpVarBind::time_ticks(
            SnmpOid::from_dotted("1.3.6.1.2.1.1.3.0")?,
            42,
        )]),
    )?;
    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .id(0x3001)
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(49_363).dport(SNMP_PORT)
        / report;
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    println!("packet: snmpv3 usm report");
    println!("mode: offline");
    println!("security material: synthetic placeholder bytes only");
    println!("constructed summary: {}", packet.summary());
    println!("decoded summary: {}", decoded.summary());
    println!("decoded show:\n{}", decoded.show());
    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
