//! Public-surface baseline tests for the SNMP layer.
//!
//! Pins that SNMP types are reachable through `crafter::prelude::*` and stay
//! inside the standard packet abstraction. The tests are fully offline and use
//! documentation address space.

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;
use crafter::wire::backend::pcap::{
    PcapLinkType, PcapReader, PcapTimestamp, PcapWriter, PcapWriterOptions, TimestampPrecision,
};

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 61);
const DOC_V6_SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x61);
const DOC_V6_DST: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x62);
const DOC_CLIENT_PORT: u16 = 49_152;
const SNMP_AGENT_PORT: u16 = SNMP_PORT;
const DOC_SRC_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x61]);
const DOC_DST_MAC: MacAddr = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x62]);

fn oid(dotted: &str) -> crafter::Result<SnmpOid> {
    SnmpOid::from_dotted(dotted)
}

fn sys_uptime_varbind() -> crafter::Result<SnmpVarBind> {
    Ok(SnmpVarBind::time_ticks(oid("1.3.6.1.2.1.1.3.0")?, 12_345))
}

fn snmp_get_request(request_id: i64) -> crafter::Result<Snmp> {
    Snmp::v2c_get_request(
        b"public".to_vec(),
        request_id,
        SnmpVarBindList::new(vec![sys_uptime_varbind()?]),
    )
}

fn assert_decoded_snmp_stack(packet: &Packet, expected_payload_len: usize) {
    let udp = packet.layer::<Udp>().expect("UDP layer");
    assert_eq!(
        udp.length_value(),
        Some((UDP_HEADER_LEN + expected_payload_len) as u16)
    );
    assert_ne!(udp.checksum_value(), Some(0));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    let snmp = packet.layer::<Snmp>().expect("SNMP layer");
    assert_eq!(snmp.version(), SnmpVersion::V2c);
    assert_eq!(snmp.pdu().tag_number(), SNMP_PDU_TAG_GET_REQUEST);
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

#[test]
fn snmp_public_api_registry_controls_decode_behavior() -> crafter::Result<()> {
    let snmp = Snmp::v2c_get_request(b"public".to_vec(), 99, SnmpVarBindList::empty())?;
    let snmp_payload = snmp.compile()?;
    let packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST)
        / Udp::new().sport(DOC_CLIENT_PORT).dport(SNMP_PORT)
        / snmp;
    let bytes = packet.compile()?;

    let builtin = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    assert!(builtin.layer::<Snmp>().is_some());
    assert!(builtin.layer::<Raw>().is_none());

    let empty = ProtocolRegistry::empty().decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    assert!(empty.layer::<Snmp>().is_none());
    assert!(empty.layer::<Raw>().is_some());

    let mut custom = ProtocolRegistry::new();
    custom.bind_udp_port(SNMP_PORT, |packet, payload| {
        Ok(packet.push(Raw::from_bytes(payload)))
    });
    let custom_decoded = custom.decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    assert!(custom_decoded.layer::<Snmp>().is_none());
    assert_eq!(
        custom_decoded
            .layer::<Raw>()
            .expect("custom raw SNMP payload")
            .as_bytes(),
        snmp_payload
    );

    let disabled = ProtocolRegistry::new().application_decoding(false);
    let disabled_decoded = disabled.decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    assert!(disabled_decoded.layer::<Udp>().is_some());
    assert!(disabled_decoded.layer::<Snmp>().is_none());
    assert_eq!(
        disabled_decoded
            .layer::<Raw>()
            .expect("application payload preserved as Raw")
            .as_bytes(),
        snmp_payload
    );

    Ok(())
}

#[test]
fn snmp_public_api_composes_with_ip_udp_ethernet_and_pcap(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let ipv4_snmp = snmp_get_request(100)?;
    let ipv4_payload_len = ipv4_snmp.compile()?.len();
    let ipv4_packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST)
        / Udp::new().sport(DOC_CLIENT_PORT).dport(SNMP_PORT)
        / ipv4_snmp;
    let ipv4_bytes = ipv4_packet.compile()?;
    let ipv4_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4_bytes.as_bytes())?;
    assert!(ipv4_decoded.layer::<Ipv4>().is_some());
    assert_decoded_snmp_stack(&ipv4_decoded, ipv4_payload_len);

    let ipv6_snmp = snmp_get_request(101)?;
    let ipv6_payload_len = ipv6_snmp.compile()?.len();
    let ipv6_packet = Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST)
        / Udp::new().sport(SNMP_TRAP_PORT).dport(DOC_CLIENT_PORT)
        / ipv6_snmp;
    let ipv6_bytes = ipv6_packet.compile()?;
    let ipv6_decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6_bytes.as_bytes())?;
    assert!(ipv6_decoded.layer::<Ipv6>().is_some());
    assert_decoded_snmp_stack(&ipv6_decoded, ipv6_payload_len);

    let ethernet_ipv4_snmp = snmp_get_request(102)?;
    let ethernet_ipv4_payload_len = ethernet_ipv4_snmp.compile()?.len();
    let ethernet_ipv4 = Ethernet::with_addresses(DOC_SRC_MAC, DOC_DST_MAC)
        / Ipv4::new().src(DOC_SRC).dst(DOC_DST)
        / Udp::new().sport(DOC_CLIENT_PORT).dport(SNMP_PORT)
        / ethernet_ipv4_snmp;
    let ethernet_ipv4_decoded =
        Packet::decode_from_link(LinkType::Ethernet, ethernet_ipv4.compile()?.as_bytes())?;
    assert!(ethernet_ipv4_decoded.layer::<Ethernet>().is_some());
    assert!(ethernet_ipv4_decoded.layer::<Ipv4>().is_some());
    assert_decoded_snmp_stack(&ethernet_ipv4_decoded, ethernet_ipv4_payload_len);

    let ethernet_ipv6_snmp = snmp_get_request(103)?;
    let ethernet_ipv6_payload_len = ethernet_ipv6_snmp.compile()?.len();
    let ethernet_ipv6 = Ethernet::with_addresses(DOC_SRC_MAC, DOC_DST_MAC)
        / Ipv6::new().src(DOC_V6_SRC).dst(DOC_V6_DST)
        / Udp::new().sport(DOC_CLIENT_PORT).dport(SNMP_TRAP_PORT)
        / ethernet_ipv6_snmp;
    let ethernet_ipv6_decoded =
        Packet::decode_from_link(LinkType::Ethernet, ethernet_ipv6.compile()?.as_bytes())?;
    assert!(ethernet_ipv6_decoded.layer::<Ethernet>().is_some());
    assert!(ethernet_ipv6_decoded.layer::<Ipv6>().is_some());
    assert_decoded_snmp_stack(&ethernet_ipv6_decoded, ethernet_ipv6_payload_len);

    let mut pcap = Vec::new();
    {
        let options = PcapWriterOptions::new(PcapLinkType::Ethernet)
            .precision(TimestampPrecision::Microseconds);
        let mut writer = PcapWriter::from_writer_with_options(&mut pcap, options)?;
        writer.write_packet_with_timestamp(&ethernet_ipv4, PcapTimestamp::micros(1, 2)?)?;
        writer.write_packet_with_timestamp(&ethernet_ipv6, PcapTimestamp::micros(1, 3)?)?;
        writer.flush()?;
    }
    let packets = PcapReader::from_reader(pcap.as_slice())?.collect_packets()?;
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0].pcap_link_type(), PcapLinkType::Ethernet);
    assert_decoded_snmp_stack(packets[0].packet(), ethernet_ipv4_payload_len);
    assert!(packets[0].packet().layer::<Ipv4>().is_some());
    assert_decoded_snmp_stack(packets[1].packet(), ethernet_ipv6_payload_len);
    assert!(packets[1].packet().layer::<Ipv6>().is_some());

    Ok(())
}

#[test]
fn snmp_public_api_packet_composition_preserves_explicit_overrides() -> crafter::Result<()> {
    let pdu = SnmpPdu::get_request(200, SnmpVarBindList::empty())?.length(0);
    let snmp = Snmp::v2c_get_request(b"public".to_vec(), 200, SnmpVarBindList::empty())?
        .with_pdu(pdu)
        .length(3);
    assert_eq!(snmp.explicit_length(), Some(3));
    assert_eq!(snmp.pdu().explicit_length(), Some(0));

    let packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST)
        / Udp::new()
            .sport(DOC_CLIENT_PORT)
            .dport(SNMP_PORT)
            .length(0x1234)
            .checksum(0xbeef)
        / snmp;
    let bytes = packet.compile()?;
    let bytes = bytes.as_bytes();
    let udp_offset = usize::from(bytes[0] & 0x0f) * 4;
    let snmp_offset = udp_offset + UDP_HEADER_LEN;
    let snmp_payload = &bytes[snmp_offset..];

    assert_eq!(
        &bytes[udp_offset + 4..udp_offset + 6],
        &0x1234u16.to_be_bytes()
    );
    assert_eq!(
        &bytes[udp_offset + 6..udp_offset + 8],
        &0xbeefu16.to_be_bytes()
    );
    assert_eq!(snmp_payload[0], 0x30);
    assert_eq!(snmp_payload[1], 3);

    let pdu_identifier = 0xa0 | SNMP_PDU_TAG_GET_REQUEST;
    let pdu_offset = snmp_payload
        .iter()
        .position(|byte| *byte == pdu_identifier)
        .expect("GetRequest PDU tag");
    assert_eq!(snmp_payload[pdu_offset + 1], 0);

    Ok(())
}
