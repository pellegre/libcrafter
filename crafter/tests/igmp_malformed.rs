//! Malformed IGMP bootstrap fixtures.
//!
//! These cases keep the current fixed-header surface honest: malformed IGMP
//! payloads return structured errors, while valid enclosing IPv4 packets with
//! unsupported or surplus IGMP bytes remain byte-preserving.

#[macro_use]
mod support;

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 60);
const DOC_QUERY_SOURCE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 60);
const DOC_QUERY_SOURCE_ALT: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 60);
const DOC_MCAST: Ipv4Addr = Ipv4Addr::new(233, 252, 0, 60);
const DOC_NON_MULTICAST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 61);

struct ErrorCase {
    name: &'static str,
    hex: &'static str,
    context: &'static str,
    required: usize,
    available: usize,
}

const ERROR_CASES: &[ErrorCase] = &[
    ErrorCase {
        name: "ipv4-igmp-empty-payload",
        hex: fixture_str!("malformed/ipv4-igmp-empty-payload.hex"),
        context: "igmp header",
        required: IGMP_FIXED_HEADER_LEN,
        available: 0,
    },
    ErrorCase {
        name: "ipv4-igmp-short-fixed-header",
        hex: fixture_str!("malformed/ipv4-igmp-short-fixed-header.hex"),
        context: "igmp header",
        required: IGMP_FIXED_HEADER_LEN,
        available: 3,
    },
    ErrorCase {
        name: "ipv4-igmp-invalid-wrapper-length",
        hex: fixture_str!("malformed/ipv4-igmp-invalid-wrapper-length.hex"),
        context: "ipv4 packet",
        required: 29,
        available: 27,
    },
    ErrorCase {
        name: "ipv4-igmp-trailing-bytes",
        hex: fixture_str!("malformed/ipv4-igmp-trailing-bytes.hex"),
        context: "igmp v3 query source list",
        required: 195528,
        available: 12,
    },
];

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let mut compact = String::new();
    for line in hex.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        compact.extend(line.chars().filter(|ch| !ch.is_whitespace()));
    }

    assert!(
        compact.len() % 2 == 0,
        "hex fixture {name} must have even length"
    );
    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("hex fixture {name} should be UTF-8"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("hex fixture {name} has invalid hex byte {byte}"))
        })
        .collect()
}

fn decode_l3_fixture(name: &str, hex: &str) -> crafter::Result<Packet> {
    let bytes = parse_hex(name, hex);
    Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)
}

fn decode_l3_bytes(name: &str, bytes: &[u8]) -> crafter::Result<Packet> {
    std::panic::catch_unwind(|| Packet::decode_from_l3(NetworkLayer::Ipv4, bytes))
        .unwrap_or_else(|_| panic!("{name} panicked during decode"))
}

fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn ipv4(id: u16, dst: Ipv4Addr) -> Ipv4 {
    Ipv4::new()
        .src(DOC_SRC)
        .dst(dst)
        .id(id)
        .ttl(1)
        .ipv4_protocol(Ipv4Protocol::Igmp)
}

fn assert_buffer_error(case: &ErrorCase) {
    let result = std::panic::catch_unwind(|| decode_l3_fixture(case.name, case.hex))
        .unwrap_or_else(|_| panic!("{} panicked during decode", case.name));
    match result {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(
                context, case.context,
                "{} returned the wrong buffer context",
                case.name
            );
            assert_eq!(
                required, case.required,
                "{} returned the wrong required byte count",
                case.name
            );
            assert_eq!(
                available, case.available,
                "{} returned the wrong available byte count",
                case.name
            );
            assert!(
                required > available,
                "{} should be a real underrun",
                case.name
            );
        }
        Ok(packet) => panic!("{} decoded unexpectedly as {}", case.name, packet.summary()),
        Err(other) => panic!("{} expected BufferTooShort, got {other:?}", case.name),
    }
}

fn assert_buffer_too_short_bytes(
    name: &str,
    bytes: &[u8],
    expected_context: &'static str,
    expected_required: usize,
    expected_available: usize,
) {
    match decode_l3_bytes(name, bytes) {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(
                context, expected_context,
                "{name} returned the wrong buffer context"
            );
            assert_eq!(
                required, expected_required,
                "{name} returned the wrong required byte count"
            );
            assert_eq!(
                available, expected_available,
                "{name} returned the wrong available byte count"
            );
            assert!(required > available, "{name} should be a real underrun");
        }
        Ok(packet) => panic!("{name} decoded unexpectedly as {}", packet.summary()),
        Err(other) => panic!("{name} expected BufferTooShort, got {other:?}"),
    }
}

fn assert_raw_tail_fixture(
    name: &str,
    hex: &str,
    expected_type: IgmpType,
    expected_tail: &[u8],
) -> crafter::Result<()> {
    let bytes = parse_hex(name, hex);
    let result = std::panic::catch_unwind(|| Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes))
        .unwrap_or_else(|_| panic!("{name} panicked during decode"));
    let packet = result?;
    let igmp = packet.layer::<Igmp>().expect("decoded IGMP header");
    let raw = packet.layer::<Raw>().expect("decoded raw IGMP tail");

    assert_eq!(packet.len(), 3, "{name} should decode as IPv4 / IGMP / Raw");
    assert_eq!(igmp.igmp_type(), expected_type);
    assert_eq!(raw.as_bytes(), expected_tail);
    assert_eq!(
        packet.compile()?.as_bytes(),
        bytes.as_slice(),
        "{name} should roundtrip without byte loss"
    );

    Ok(())
}

#[test]
fn igmp_malformed_fixed_header_errors_are_structured() {
    for case in ERROR_CASES {
        assert_buffer_error(case);
    }
}

fn assert_v2_override_roundtrip(
    name: &str,
    packet: Packet,
    expected_type: IgmpType,
    expected_code: u8,
    expected_checksum: u16,
    expected_group: Ipv4Addr,
) -> crafter::Result<()> {
    let bytes = packet.compile()?;
    let decoded = decode_l3_bytes(name, bytes.as_bytes())?;
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP v2 header");

    assert_eq!(igmp.igmp_type(), expected_type);
    assert_eq!(igmp.code_value(), expected_code);
    assert_eq!(igmp.code_meta().status, IgmpTypeStatus::Unassigned);
    assert_eq!(igmp.checksum_value(), Some(expected_checksum));
    assert_eq!(igmp.checksum_state(), FieldState::User);
    assert_eq!(igmp.group_address_value(), expected_group);
    if expected_group == DOC_NON_MULTICAST {
        assert_eq!(igmp.group_address_class_name(), "non-multicast");
        assert!(!igmp.group_address_is_multicast());
    }
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());

    Ok(())
}

#[test]
fn igmp_v3_query_source_count_overrun_is_structural_error() -> crafter::Result<()> {
    let query =
        IgmpQuery::group_and_source_specific(vec![DOC_QUERY_SOURCE]).with_number_of_sources(2);
    let packet = ipv4(0x2705, DOC_MCAST) / Igmp::v3_membership_query(100, DOC_MCAST, query);
    let bytes = packet.compile()?;

    assert_buffer_too_short_bytes(
        "igmp-v3-query-source-count-too-large",
        bytes.as_bytes(),
        "igmp v3 query source list",
        IGMP_V3_QUERY_MIN_LEN + 2 * 4,
        IGMP_V3_QUERY_MIN_LEN + 4,
    );

    Ok(())
}

#[test]
fn igmp_v3_query_extra_octets_are_preserved_as_raw() -> crafter::Result<()> {
    let packet = ipv4(0x2705, DOC_MCAST)
        / Igmp::v3_group_specific_query(100, DOC_MCAST)
        / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
    let bytes = packet.compile()?;

    let decoded = decode_l3_bytes("igmp-v3-query-extra-octets", bytes.as_bytes())?;
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP header");
    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded IGMPv3 query body");
    let raw = decoded.layer::<Raw>().expect("decoded extra query bytes");

    assert_eq!(decoded.len(), 4);
    assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(query.number_of_sources_value(), 0);
    assert!(query.source_addresses().is_empty());
    assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());

    Ok(())
}

#[test]
fn igmp_v3_query_extra_source_tail_is_preserved_as_raw() -> crafter::Result<()> {
    let packet = ipv4(0x2706, DOC_MCAST)
        / Igmp::v3_group_and_source_specific_query(100, DOC_MCAST, vec![DOC_QUERY_SOURCE])
        / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
    let bytes = packet.compile()?;

    let decoded = decode_l3_bytes("igmp-v3-query-extra-octets-after-sources", bytes.as_bytes())?;
    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded IGMPv3 query body");
    let raw = decoded.layer::<Raw>().expect("decoded extra query bytes");

    assert_eq!(decoded.len(), 4);
    assert_eq!(query.number_of_sources_value(), 1);
    assert_eq!(query.source_addresses(), &[DOC_QUERY_SOURCE]);
    assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());

    Ok(())
}

#[test]
fn igmp_v3_query_invalid_ipv4_wrapper_length_is_structural_error() -> crafter::Result<()> {
    let packet = ipv4(0x2707, DOC_MCAST) / Igmp::v3_group_specific_query(100, DOC_MCAST);
    let compiled = packet.compile()?;
    let mut bytes = compiled.as_bytes().to_vec();
    let declared_total_len = bytes.len() + 1;
    write_u16_at(&mut bytes, 2, declared_total_len as u16);

    assert_buffer_too_short_bytes(
        "igmp-v3-query-invalid-ipv4-wrapper-length",
        &bytes,
        "ipv4 packet",
        declared_total_len,
        bytes.len(),
    );

    Ok(())
}

#[test]
fn igmp_v3_query_explicit_wrong_checksum_is_inspectable() -> crafter::Result<()> {
    let packet = ipv4(0x2708, DOC_MCAST)
        / Igmp::membership_query()
            .with_max_response_code(100)
            .with_group_address(DOC_MCAST)
            .checksum(0x1234)
        / IgmpQuery::group_and_source_specific(vec![DOC_QUERY_SOURCE]);
    let bytes = packet.compile()?;

    let decoded = decode_l3_bytes("igmp-v3-query-explicit-wrong-checksum", bytes.as_bytes())?;
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP header");
    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded IGMPv3 query body");

    assert_eq!(decoded.len(), 3);
    assert_eq!(igmp.igmp_type(), IgmpType::MembershipQuery);
    assert_eq!(igmp.checksum_value(), Some(0x1234));
    assert_eq!(igmp.checksum_state(), FieldState::User);
    assert_eq!(query.source_addresses(), &[DOC_QUERY_SOURCE]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());

    Ok(())
}

#[test]
fn igmp_v3_query_unknown_flag_bits_are_inspectable_and_preserved() -> crafter::Result<()> {
    let query = IgmpQuery::group_and_source_specific(vec![DOC_QUERY_SOURCE_ALT])
        .with_unassigned_query_flags(IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK)
        .with_querier_robustness_variable(5);
    let packet = ipv4(0x2709, DOC_MCAST) / Igmp::v3_membership_query(100, DOC_MCAST, query);
    let bytes = packet.compile()?;

    let decoded = decode_l3_bytes("igmp-v3-query-unknown-flag-bits", bytes.as_bytes())?;
    let query = decoded
        .layer::<IgmpQuery>()
        .expect("decoded IGMPv3 query body");

    assert_eq!(decoded.len(), 3);
    assert_eq!(query.raw_flags_qrv_value(), 0x75);
    assert_eq!(
        query.query_flags_value(),
        IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK
    );
    assert_eq!(
        query.unassigned_query_flags_value(),
        IGMP_V3_QUERY_FLAGS_UNASSIGNED_MASK
    );
    assert!(!query.extension_flag());
    assert_eq!(query.querier_robustness_variable(), 5);
    assert_eq!(query.source_addresses(), &[DOC_QUERY_SOURCE_ALT]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());

    Ok(())
}

#[test]
fn igmp_unknown_type_payload_is_preserved_as_raw() -> crafter::Result<()> {
    assert_raw_tail_fixture(
        "ipv4-igmp-unknown-type-payload",
        fixture_str!("malformed/ipv4-igmp-unknown-type-payload.hex"),
        IgmpType::Unassigned(IGMP_TYPE_UNASSIGNED_FIRST),
        &[0x01, 0x02, 0x03, 0x04],
    )
}

#[test]
fn igmp_malformed_v2_report_overrides_are_inspectable() -> crafter::Result<()> {
    let packet = ipv4(0x2701, DOC_NON_MULTICAST)
        / Igmp::v2_membership_report(DOC_NON_MULTICAST)
            .with_code(0x7f)
            .checksum(0x1234);

    assert_v2_override_roundtrip(
        "igmp-v2-report-overrides",
        packet,
        IgmpType::V2MembershipReport,
        0x7f,
        0x1234,
        DOC_NON_MULTICAST,
    )
}

#[test]
fn igmp_malformed_v2_leave_overrides_are_inspectable() -> crafter::Result<()> {
    let packet = ipv4(0x2702, DOC_NON_MULTICAST)
        / Igmp::v2_leave_group(DOC_NON_MULTICAST)
            .with_code(0x80)
            .checksum(0xabcd);

    assert_v2_override_roundtrip(
        "igmp-v2-leave-overrides",
        packet,
        IgmpType::V2LeaveGroup,
        0x80,
        0xabcd,
        DOC_NON_MULTICAST,
    )
}

#[test]
fn igmp_malformed_v2_trailing_payload_is_preserved_as_raw() -> crafter::Result<()> {
    let packet = ipv4(0x2703, DOC_MCAST)
        / Igmp::v2_membership_report(DOC_MCAST)
        / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]);
    let bytes = packet.compile()?;

    let decoded = decode_l3_bytes("igmp-v2-trailing-payload", bytes.as_bytes())?;
    let igmp = decoded.layer::<Igmp>().expect("decoded IGMP v2 report");
    let raw = decoded.layer::<Raw>().expect("decoded trailing raw bytes");

    assert_eq!(decoded.len(), 3);
    assert_eq!(igmp.igmp_type(), IgmpType::V2MembershipReport);
    assert_eq!(igmp.group_address_value(), DOC_MCAST);
    assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_bytes());

    Ok(())
}

#[test]
fn igmp_malformed_v2_short_payload_is_structural_error() -> crafter::Result<()> {
    let packet = ipv4(0x2704, DOC_MCAST)
        / Raw::from_bytes([IGMP_TYPE_V2_MEMBERSHIP_REPORT, 0, 0, 0, 233, 252, 0]);
    let bytes = packet.compile()?;

    match decode_l3_bytes("igmp-v2-short-payload", bytes.as_bytes()) {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(context, "igmp header");
            assert_eq!(required, IGMP_FIXED_HEADER_LEN);
            assert_eq!(available, IGMP_FIXED_HEADER_LEN - 1);
            Ok(())
        }
        Ok(packet) => panic!("igmp-v2-short-payload decoded as {}", packet.summary()),
        Err(other) => panic!("igmp-v2-short-payload returned {other:?}"),
    }
}
