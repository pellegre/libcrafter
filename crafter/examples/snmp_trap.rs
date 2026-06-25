mod common;

use common::{local_ipv4, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example snmp_trap --\n\nBuild SNMPv1 Trap and SNMPv2c SNMPv2-Trap packets, then decode them offline.",
    ) {
        return Ok(());
    }

    inspect_trap(
        "snmpv1 trap",
        49_261,
        Snmp::v1_trap(
            b"doc-trap".to_vec(),
            oid("1.3.6.1.2.1.1.2.0")?,
            local_ipv4().octets(),
            0,
            0,
            12_345,
            SnmpVarBindList::new(vec![SnmpVarBind::time_ticks(
                oid("1.3.6.1.2.1.1.3.0")?,
                12_345,
            )]),
        )?,
    )?;

    inspect_trap(
        "snmpv2c snmpv2-trap",
        49_262,
        Snmp::v2c_snmpv2_trap(
            b"doc-trap".to_vec(),
            3,
            SnmpVarBindList::new(vec![
                SnmpVarBind::time_ticks(oid("1.3.6.1.2.1.1.3.0")?, 12_345),
                SnmpVarBind::object_identifier(
                    oid("1.3.6.1.6.3.1.1.4.1.0")?,
                    oid("1.3.6.1.6.3.1.1.5.1")?,
                ),
            ]),
        )?,
    )?;

    Ok(())
}

fn oid(dotted: &str) -> crafter::Result<SnmpOid> {
    SnmpOid::from_dotted(dotted)
}

fn inspect_trap(label: &str, sport: u16, snmp: Snmp) -> ExampleResult<()> {
    let packet = Ipv4::new()
        .src(local_ipv4())
        .dst(remote_ipv4())
        .id(sport)
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(sport).dport(SNMP_TRAP_PORT)
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
