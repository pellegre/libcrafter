//! QUIC malformed input coverage.
//!
//! These tests stay offline and use documentation address space when an IP/UDP
//! wrapper is needed to reach the public decode path.

use crafter::protocols::quic::{QuicFrame, QuicFrameKind, QuicHandshakeDoneFrame, QuicHeader};
use crafter::{
    CrafterError, Ipv4, NetworkLayer, Packet, QuicLongHeaderPacket, QuicPacket, QuicPacketNumber,
    QuicRetryPacket, Raw, Udp,
};
use std::net::Ipv4Addr;

fn assert_buffer_too_short(
    err: CrafterError,
    context: &'static str,
    required: usize,
    available: usize,
) {
    assert_eq!(
        err,
        CrafterError::buffer_too_short(context, required, available)
    );
}

fn udp_ipv4_quic_payload(payload: &[u8]) -> crafter::Result<Vec<u8>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(49_152).dport(4433)
        / Raw::from_bytes(payload);
    Ok(packet.compile()?.as_bytes().to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicFrameMalformedTarget {
    Sequence,
    HandshakeDone,
    RawFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QuicFrameMalformedExpected {
    BufferTooShort {
        context: String,
        required: usize,
        available: usize,
    },
    InvalidFieldValue {
        field: String,
    },
    Decodes {
        marker: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuicFrameMalformedCase {
    name: String,
    target: QuicFrameMalformedTarget,
    expected: QuicFrameMalformedExpected,
    bytes: Vec<u8>,
}

#[test]
fn quic_header_truncation_parser_boundaries() -> crafter::Result<()> {
    assert_buffer_too_short(
        QuicHeader::from_decoded_bytes([]).unwrap_err(),
        "quic.header",
        1,
        0,
    );

    assert_buffer_too_short(
        QuicPacket::decode([0xc0]).unwrap_err(),
        "quic.header.long.version",
        5,
        1,
    );
    assert_buffer_too_short(
        QuicPacket::decode([0xc0, 0x00, 0x00, 0x00]).unwrap_err(),
        "quic.header.long.version",
        5,
        4,
    );
    assert_buffer_too_short(
        QuicPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01]).unwrap_err(),
        "quic.header.long.dcid_len",
        6,
        5,
    );
    assert_buffer_too_short(
        QuicPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x04, 0xaa]).unwrap_err(),
        "quic.header.long.dcid",
        10,
        7,
    );

    assert_buffer_too_short(
        QuicLongHeaderPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]).unwrap_err(),
        "quic.initial.token_length",
        8,
        7,
    );
    assert_buffer_too_short(
        QuicLongHeaderPacket::decode([0xc0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40])
            .unwrap_err(),
        "quic.long_header.length",
        10,
        9,
    );
    assert_buffer_too_short(
        QuicLongHeaderPacket::decode([0xe1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0xaa])
            .unwrap_err(),
        "quic.long_header.packet_number",
        10,
        9,
    );
    assert_buffer_too_short(
        QuicRetryPacket::decode([0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]).unwrap_err(),
        "quic.retry.integrity_tag",
        23,
        8,
    );

    let initial = QuicLongHeaderPacket::initial_builder()
        .packet_number(QuicPacketNumber::new(1))
        .payload([0xbe])
        .build()?;
    let malformed_handshake = [0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x02, 0xef];
    let mut coalesced = initial.as_bytes().to_vec();
    coalesced.extend_from_slice(&malformed_handshake);
    let wrapped = udp_ipv4_quic_payload(&coalesced)?;

    assert_buffer_too_short(
        Packet::decode_from_l3(NetworkLayer::Ipv4, &wrapped).unwrap_err(),
        "quic.long_header.protected_payload",
        11,
        malformed_handshake.len(),
    );

    Ok(())
}

#[test]
fn quic_frame_malformed_corpus_reports_structured_outcomes() {
    let cases = quic_frame_malformed_cases();
    assert_required_quic_frame_malformed_cases(&cases);

    for case in cases {
        std::panic::catch_unwind(|| assert_quic_frame_malformed_case(&case))
            .unwrap_or_else(|_| panic!("QUIC frame malformed corpus case {} panicked", case.name));
    }
}

fn quic_frame_malformed_cases() -> Vec<QuicFrameMalformedCase> {
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/malformed/quic-frame-corpus.hex"
    ))
    .lines()
    .enumerate()
    .filter_map(|(line_number, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let parts = line.split('|').map(str::trim).collect::<Vec<_>>();
        assert_eq!(
            parts.len(),
            7,
            "QUIC frame malformed corpus line {} must have 7 fields",
            line_number + 1
        );
        let name = parts[0].to_string();
        let target = parse_quic_frame_malformed_target(&name, parts[1]);
        let expected = parse_quic_frame_malformed_expected(&name, &parts);
        let bytes = parse_hex(&name, parts[6]);
        Some(QuicFrameMalformedCase {
            name,
            target,
            expected,
            bytes,
        })
    })
    .collect()
}

fn parse_quic_frame_malformed_target(name: &str, target: &str) -> QuicFrameMalformedTarget {
    match target {
        "sequence" => QuicFrameMalformedTarget::Sequence,
        "handshake-done" => QuicFrameMalformedTarget::HandshakeDone,
        "raw-frame" => QuicFrameMalformedTarget::RawFrame,
        _ => panic!("QUIC frame malformed corpus case {name} has unknown target {target}"),
    }
}

fn parse_quic_frame_malformed_expected(name: &str, parts: &[&str]) -> QuicFrameMalformedExpected {
    match parts[2] {
        "buffer-too-short" => QuicFrameMalformedExpected::BufferTooShort {
            context: parts[3].to_string(),
            required: parts[4]
                .parse()
                .unwrap_or_else(|_| panic!("case {name} has invalid required byte count")),
            available: parts[5]
                .parse()
                .unwrap_or_else(|_| panic!("case {name} has invalid available byte count")),
        },
        "invalid-field-value" => {
            assert_eq!(parts[4], "-", "case {name} must use '-' for required");
            assert_eq!(parts[5], "-", "case {name} must use '-' for available");
            QuicFrameMalformedExpected::InvalidFieldValue {
                field: parts[3].to_string(),
            }
        }
        "decodes" => {
            assert_eq!(parts[4], "-", "case {name} must use '-' for required");
            assert_eq!(parts[5], "-", "case {name} must use '-' for available");
            QuicFrameMalformedExpected::Decodes {
                marker: parts[3].to_string(),
            }
        }
        expected => panic!("QUIC frame malformed corpus case {name} has unknown kind {expected}"),
    }
}

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex.split_whitespace().collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "QUIC frame malformed corpus case {name} has odd hex length"
    );
    hex.as_bytes()
        .chunks_exact(2)
        .map(|byte| {
            let byte = std::str::from_utf8(byte)
                .unwrap_or_else(|_| panic!("case {name} contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("case {name} has invalid hex byte {byte}"))
        })
        .collect()
}

fn assert_required_quic_frame_malformed_cases(cases: &[QuicFrameMalformedCase]) {
    for required in [
        "frame-type-truncated",
        "ack-range-length-truncated",
        "reset-stream-final-size-truncated",
        "stop-sending-error-code-truncated",
        "crypto-data-overrun",
        "new-token-overrun",
        "stream-data-overrun",
        "max-data-varint-truncated",
        "max-stream-data-varint-truncated",
        "max-streams-varint-truncated",
        "data-blocked-varint-truncated",
        "stream-data-blocked-varint-truncated",
        "streams-blocked-varint-truncated",
        "new-connection-id-zero-length",
        "new-connection-id-cid-truncated",
        "new-connection-id-reset-token-truncated",
        "retire-connection-id-varint-truncated",
        "path-challenge-underrun",
        "path-response-underrun",
        "connection-close-reason-overrun",
        "connection-close-frame-type-truncated",
        "handshake-done-trailing-bytes",
        "provisional-frame-tail-preserved",
        "ping-with-caller-bounded-tail",
    ] {
        assert!(
            cases.iter().any(|case| case.name == required),
            "QUIC frame malformed corpus missing required case {required}"
        );
    }
}

fn assert_quic_frame_malformed_case(case: &QuicFrameMalformedCase) {
    match &case.expected {
        QuicFrameMalformedExpected::BufferTooShort {
            context,
            required,
            available,
        } => {
            let err = decode_quic_frame_malformed_error(case);
            match err {
                CrafterError::BufferTooShort {
                    context: got_context,
                    required: got_required,
                    available: got_available,
                } => {
                    assert_eq!(got_context, context.as_str(), "case {}", case.name);
                    assert_eq!(got_required, *required, "case {}", case.name);
                    assert_eq!(got_available, *available, "case {}", case.name);
                }
                other => panic!(
                    "QUIC frame malformed corpus case {} expected BufferTooShort, got {other:?}",
                    case.name
                ),
            }
        }
        QuicFrameMalformedExpected::InvalidFieldValue { field } => {
            let err = decode_quic_frame_malformed_error(case);
            match err {
                CrafterError::InvalidFieldValue { field: got, reason } => {
                    assert_eq!(got, field.as_str(), "case {}", case.name);
                    assert!(
                        !reason.is_empty(),
                        "case {} InvalidFieldValue must carry a reason",
                        case.name
                    );
                }
                other => panic!(
                    "QUIC frame malformed corpus case {} expected InvalidFieldValue, got {other:?}",
                    case.name
                ),
            }
        }
        QuicFrameMalformedExpected::Decodes { marker } => {
            assert_quic_frame_malformed_decode_marker(case, marker);
        }
    }
}

fn decode_quic_frame_malformed_error(case: &QuicFrameMalformedCase) -> CrafterError {
    match case.target {
        QuicFrameMalformedTarget::Sequence => QuicFrame::decode_sequence(&case.bytes)
            .map(|_| ())
            .unwrap_err(),
        QuicFrameMalformedTarget::HandshakeDone => QuicHandshakeDoneFrame::decode(&case.bytes)
            .map(|_| ())
            .unwrap_err(),
        QuicFrameMalformedTarget::RawFrame => {
            panic!("raw-frame case {} cannot be expected to error", case.name)
        }
    }
}

fn assert_quic_frame_malformed_decode_marker(case: &QuicFrameMalformedCase, marker: &str) {
    match (case.target, marker) {
        (QuicFrameMalformedTarget::Sequence, "unknown-tail") => {
            let frames = QuicFrame::decode_sequence(&case.bytes)
                .unwrap_or_else(|err| panic!("case {} should decode: {err}", case.name));
            assert_eq!(frames.len(), 1, "case {}", case.name);
            let unknown = frames[0]
                .unknown_frame()
                .unwrap_or_else(|err| panic!("case {} unknown frame failed: {err}", case.name))
                .unwrap_or_else(|| panic!("case {} should be an unknown frame", case.name));
            assert!(
                !unknown.raw_following_bytes().is_empty(),
                "case {} should preserve unknown following bytes",
                case.name
            );
        }
        (QuicFrameMalformedTarget::RawFrame, "unknown-kind") => {
            let frame = QuicFrame::from_bytes(&case.bytes);
            assert_eq!(frame.kind(), QuicFrameKind::Unknown, "case {}", case.name);
            assert_eq!(
                frame.as_bytes(),
                case.bytes.as_slice(),
                "case {}",
                case.name
            );
        }
        _ => panic!(
            "QUIC frame malformed corpus case {} has unsupported decode marker {marker}",
            case.name
        ),
    }
}
