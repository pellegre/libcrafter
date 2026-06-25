//! Public-surface baseline tests for the SNMP layer.
//!
//! Pins that SNMP types are reachable through `crafter::prelude::*` and stay
//! inside the standard packet abstraction. The tests are fully offline and use
//! documentation address space.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 61);
const DOC_CLIENT_PORT: u16 = 49_152;
const SNMP_AGENT_PORT: u16 = 161;

fn oid(dotted: &str) -> crafter::Result<SnmpOid> {
    SnmpOid::from_dotted(dotted)
}

#[test]
fn snmp_public_api_builds_v1_packet_via_prelude() -> crafter::Result<()> {
    let varbind = SnmpVarBind::null(oid("1.3.6.1.2.1.1.3.0")?);
    let snmp = Snmp::v1_get_request(b"public".to_vec(), 7, SnmpVarBindList::new(vec![varbind]))?;

    let snmp_bytes = snmp.compile()?;
    assert_eq!(&snmp_bytes[..13], b"\x30\x26\x02\x01\x00\x04\x06public");
    assert_eq!(snmp.version(), SnmpVersion::V1);
    assert_eq!(snmp.summary(), "Snmp(version=v1, community_len=6, pdu=SnmpPdu(pdu_type=get-request request_id=7 error_status=no-error(0) error_index=0 varbind_count=1))");
    assert!(!snmp.summary().contains("public"));

    let packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST)
        / Udp::new().sport(DOC_CLIENT_PORT).dport(SNMP_AGENT_PORT)
        / snmp.clone();
    let compiled = packet.compile()?;

    assert!(!compiled.as_bytes().is_empty());
    assert_eq!(
        packet.layer::<Snmp>().expect("SNMP layer").version(),
        SnmpVersion::V1
    );
    assert!(packet.summary().contains("Ipv4("));
    assert!(packet.summary().contains("Udp("));
    assert!(packet.summary().contains("Snmp(version=v1"));

    let fields = snmp.inspection_fields();
    assert!(fields.contains(&("version", "v1".to_string())));
    assert!(fields.contains(&("community_len", "6".to_string())));
    assert!(fields.contains(&("pdu_type", "get-request".to_string())));
    assert!(fields.contains(&("request_id", "7".to_string())));
    assert!(fields.contains(&("varbind_count", "1".to_string())));
    assert!(!snmp.show().contains("public"));

    Ok(())
}

#[test]
fn snmp_public_api_builds_v2c_packet_and_decodes_message_bytes() -> crafter::Result<()> {
    let varbind = SnmpVarBind::time_ticks(oid("1.3.6.1.2.1.1.3.0")?, 12_345);
    let snmp = Snmp::v2c_response(b"private".to_vec(), 42, SnmpVarBindList::new(vec![varbind]))?;

    let bytes = snmp.compile()?;
    let decoded = Snmp::decode(&bytes)?;

    assert_eq!(decoded.compile()?, bytes);
    assert_eq!(decoded.version(), SnmpVersion::V2c);
    assert_eq!(decoded.community(), b"private");
    assert!(decoded.summary().contains("pdu_type=response"));
    assert!(decoded.summary().contains("request_id=42"));
    assert!(decoded.summary().contains("varbind_count=1"));
    assert!(!decoded.summary().contains("private"));

    let packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST)
        / Udp::new().sport(DOC_CLIENT_PORT).dport(SNMP_AGENT_PORT)
        / decoded.clone();
    let compiled = packet.compile()?;

    assert_eq!(
        packet.layer::<Snmp>().expect("SNMP layer").version(),
        SnmpVersion::V2c
    );
    assert!(compiled.hexdump().contains("0000:"));
    assert!(packet.show().contains("version: v2c"));
    assert!(packet.show().contains("request_id: 42"));
    assert!(!packet.show().contains("private"));

    Ok(())
}

#[test]
fn snmp_public_api_raw_decode_preserves_unknown_pdu() -> crafter::Result<()> {
    let bytes = [
        0x30, 0x0b, 0x02, 0x01, 0x01, 0x04, 0x01, b'x', 0xa9, 0x03, 0x02, 0x01, 0x05,
    ];
    let decoded = Snmp::decode(&bytes)?;
    let unknown = decoded.pdu().as_unknown().expect("unknown PDU");

    assert_eq!(decoded.compile()?, bytes);
    assert_eq!(decoded.version(), SnmpVersion::V2c);
    assert_eq!(decoded.community(), b"x");
    assert_eq!(unknown.tag_number(), 9);
    assert_eq!(unknown.raw_tlv_bytes(), Some(&bytes[8..]));
    assert_eq!(
        decoded.summary(),
        "Snmp(version=v2c, community_len=1, pdu=SnmpPdu(pdu_type=pdu-9 pdu_tag=9 constructed=true body_length=3))"
    );
    assert!(decoded.show().contains("pdu_tlv_bytes: a9 03 02 01 05"));

    Ok(())
}
