use std::net::Ipv4Addr;

use super::ipv4::{extract_ipv4_fragment, Ipv4FragmentPassThroughReason};
use super::ipv6::{
    extract_ipv6_fragment, Ipv6FragmentPassThroughReason,
    IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE,
};
use super::{IpDefrag, IpFragment};
use crate::pcap::PcapLinkType;
use crate::wire::record::PacketRecord;
use crate::wire::WireError;
use crate::{CrafterError, Ipv4, Raw, IPPROTO_IPV6_AH, IPPROTO_IPV6_FRAGMENT, IPPROTO_UDP};

fn raw_ip_record(bytes: Vec<u8>) -> PacketRecord {
    PacketRecord::new(Raw::from_bytes(&bytes))
        .with_pcap_link_type(PcapLinkType::RawIp)
        .with_captured_bytes(bytes)
}

fn pcap_record(bytes: Vec<u8>, link_type: PcapLinkType) -> PacketRecord {
    PacketRecord::new(Raw::from_bytes(&bytes))
        .with_pcap_link_type(link_type)
        .with_captured_bytes(bytes)
}

fn ipv4_fragment_bytes(flags_fragment: u16, total_len: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20 + payload.len());
    bytes.push(0x45);
    bytes.push(0);
    bytes.extend_from_slice(&total_len.to_be_bytes());
    bytes.extend_from_slice(&0x1234u16.to_be_bytes());
    bytes.extend_from_slice(&flags_fragment.to_be_bytes());
    bytes.push(64);
    bytes.push(253);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    bytes.extend_from_slice(&[198, 51, 100, 2]);
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv6_fragment_bytes(payload_len: u16, fragment_bytes: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(40 + fragment_bytes.len());
    bytes.extend_from_slice(&[0x60, 0, 0, 0]);
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.push(IPPROTO_IPV6_FRAGMENT);
    bytes.push(64);
    bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(fragment_bytes);
    bytes
}

fn ipv6_unsupported_ah_fragment_bytes() -> Vec<u8> {
    let mut bytes = ipv6_fragment_bytes(
        16,
        &[
            IPPROTO_UDP,
            0,
            0,
            1,
            0x10,
            0x20,
            0x30,
            0x40,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    bytes[6] = IPPROTO_IPV6_AH;
    bytes[40] = IPPROTO_IPV6_FRAGMENT;
    bytes
}

fn expect_buffer_too_short(error: CrafterError, context: &'static str) {
    match error {
        CrafterError::BufferTooShort {
            context: actual,
            required,
            available,
        } => {
            assert_eq!(actual, context);
            assert!(
                required > available,
                "BufferTooShort must require more bytes than are available"
            );
        }
        other => panic!("expected BufferTooShort for {context}, got {other:?}"),
    }
}

fn expect_invalid_field(error: CrafterError, field: &'static str) {
    match error {
        CrafterError::InvalidFieldValue {
            field: actual,
            reason,
        } => {
            assert_eq!(actual, field);
            assert!(!reason.is_empty());
        }
        other => panic!("expected InvalidFieldValue for {field}, got {other:?}"),
    }
}

fn expect_wire_packet_error(error: WireError) -> CrafterError {
    match error {
        WireError::Packet(error) => error,
        other => panic!("expected packet error, got {other:?}"),
    }
}

#[test]
fn truncated_ipv4_fragment_header_returns_buffer_too_short() {
    let mut bytes = ipv4_fragment_bytes(0x2000, 20, &[]);
    bytes.truncate(19);
    let record = raw_ip_record(bytes);

    let error = extract_ipv4_fragment(&record).unwrap_err();
    expect_buffer_too_short(error, "ipv4 header");

    let mut transform = IpDefrag::new();
    let error = transform.defrag_record(record).unwrap_err();
    expect_buffer_too_short(expect_wire_packet_error(error), "ipv4 header");
}

#[test]
fn truncated_ipv6_fragment_header_returns_buffer_too_short() {
    let bytes = ipv6_fragment_bytes(4, &[IPPROTO_UDP, 0, 0, 1]);
    let record = raw_ip_record(bytes);

    let error = extract_ipv6_fragment(&record).unwrap_err();
    expect_buffer_too_short(error, "ipv6 fragment header");

    let mut transform = IpDefrag::new();
    let error = transform.defrag_record(record).unwrap_err();
    expect_buffer_too_short(expect_wire_packet_error(error), "ipv6 fragment header");
}

#[test]
fn fragment_payload_length_mismatches_return_structured_errors() {
    let ipv4 = raw_ip_record(ipv4_fragment_bytes(0x2000, 32, &[0xaa; 8]));
    let error = extract_ipv4_fragment(&ipv4).unwrap_err();
    expect_buffer_too_short(error, "ipv4 packet");

    let ipv6 = raw_ip_record(ipv6_fragment_bytes(8, &[IPPROTO_UDP, 0, 0, 1]));
    let error = extract_ipv6_fragment(&ipv6).unwrap_err();
    expect_buffer_too_short(error, "ipv6 packet");
}

#[test]
fn impossible_ipv4_fragment_offset_returns_invalid_field_value() {
    let payload = [0x5a; 16];
    let record = PacketRecord::new(
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 2))
            .protocol(253)
            .fragment_offset(0x1fff)
            / Raw::from_bytes(payload),
    );
    let mut transform = IpFragment::new(28);

    let error = transform.fragment_record(record).unwrap_err();
    expect_invalid_field(expect_wire_packet_error(error), "ipv4.fragment_offset");
}

#[test]
fn unsupported_wrappers_pass_through_without_panic() {
    let bytes = ipv4_fragment_bytes(0x2000, 28, &[0xaa; 8]);
    let record = pcap_record(bytes.clone(), PcapLinkType::Ieee80211);

    let extracted = extract_ipv4_fragment(&record).unwrap();
    assert_eq!(
        extracted.pass_through().map(|pass| pass.reason()),
        Some(Ipv4FragmentPassThroughReason::UnsupportedWrapper)
    );

    let mut defrag = IpDefrag::new();
    let output = defrag.defrag_record(record.clone()).unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(
        output.records()[0].metadata().captured_bytes(),
        Some(bytes.as_slice())
    );

    let mut fragment = IpFragment::new(1280);
    let output = fragment.fragment_record(record).unwrap();
    assert_eq!(output.len(), 1);
    assert_eq!(
        output.records()[0].metadata().captured_bytes(),
        Some(bytes.as_slice())
    );
}

#[test]
fn unsupported_ipv6_fragment_scope_remains_traceable_pass_through() {
    let bytes = ipv6_unsupported_ah_fragment_bytes();
    let record = raw_ip_record(bytes);

    let extracted = extract_ipv6_fragment(&record).unwrap();
    assert_eq!(
        extracted.pass_through().map(|pass| pass.reason()),
        Some(Ipv6FragmentPassThroughReason::UnsupportedExtensionChain)
    );

    let mut defrag = IpDefrag::new();
    let output = defrag.defrag_record(record).unwrap();
    assert_eq!(output.len(), 1);
    let traces = output.records()[0].metadata().transforms();
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0].name(), "ip-defrag");
    assert_eq!(
        traces[0].note(),
        Some(IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE)
    );
}
