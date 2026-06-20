//! Malformed IGMP bootstrap fixtures.
//!
//! These cases keep the current fixed-header surface honest: malformed IGMP
//! payloads return structured errors, while valid enclosing IPv4 packets with
//! unsupported or surplus IGMP bytes remain byte-preserving.

#[macro_use]
mod support;

use crafter::prelude::*;

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
            assert!(required > available, "{} should be a real underrun", case.name);
        }
        Ok(packet) => panic!("{} decoded unexpectedly as {}", case.name, packet.summary()),
        Err(other) => panic!("{} expected BufferTooShort, got {other:?}", case.name),
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

#[test]
fn igmp_trailing_bytes_are_preserved_as_raw() -> crafter::Result<()> {
    assert_raw_tail_fixture(
        "ipv4-igmp-trailing-bytes",
        fixture_str!("malformed/ipv4-igmp-trailing-bytes.hex"),
        IgmpType::MembershipQuery,
        &[0xde, 0xad, 0xbe, 0xef],
    )
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
