mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example snmp_get --\n\nBuild SNMPv1 and SNMPv2c GetRequest packets, then decode them offline.",
    ) {
        return Ok(());
    }

    inspect_get(
        "snmpv1 get-request",
        49_161,
        Snmp::v1_get_request(b"doc-community".to_vec(), 1, sys_descr_request()?)?,
    )?;
    inspect_get(
        "snmpv2c get-request",
        49_162,
        Snmp::v2c_get_request(b"doc-community".to_vec(), 2, sys_descr_request()?)?,
    )?;

    Ok(())
}

fn sys_descr_request() -> crafter::Result<SnmpVarBindList> {
    Ok(SnmpVarBindList::new(vec![SnmpVarBind::null(
        SnmpOid::from_dotted("1.3.6.1.2.1.1.1.0")?,
    )]))
}

fn inspect_get(label: &str, sport: u16, snmp: Snmp) -> ExampleResult<()> {
    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .id(sport)
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(sport).dport(SNMP_PORT)
        / snmp;
    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    println!("packet: {label}");
    println!("mode: offline");
    println!("constructed summary: {}", packet.summary());
    println!("decoded summary: {}", decoded.summary());
    println!("decoded show:\n{}", decoded.show());
    println!("hexdump:\n{}", bytes.hexdump());

    Ok(())
}
