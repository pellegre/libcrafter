//! QUIC golden header fixtures.
//!
//! Fixture comments cite the source-backed QUIC notes in `.agents/docs/`.
//! These tests stay offline and exercise raw QUIC packet bytes directly.

use crafter::protocols::quic::grease_transport_parameter_id;
use crafter::protocols::quic::header::QuicLongPacketKind;
use crafter::{
    CrafterError, Packet, Quic, QuicConnectionId, QuicDatagramFrame, QuicFrame,
    QuicIntegerTransportParameter, QuicKnownTransportParameter, QuicLongHeaderPacket, QuicPacket,
    QuicPacketNumber, QuicRetryPacket, QuicShortHeaderPacket, QuicTransportParameter,
    QuicTransportParameterKind, QuicVarInt, QuicVersionNegotiationPacket, QUIC_VERSION_1,
    QUIC_VERSION_2,
};

const VERSION_NEGOTIATION: &str = include_str!("fixtures/bytes/quic-version-negotiation.hex");
const RETRY: &str = include_str!("fixtures/bytes/quic-retry.hex");
const V1_INITIAL: &str = include_str!("fixtures/bytes/quic-v1-initial.hex");
const V1_INITIAL_FRAMES: &str = include_str!("fixtures/bytes/quic-v1-initial-frames.hex");
const V2_INITIAL: &str = include_str!("fixtures/bytes/quic-v2-initial.hex");
const HANDSHAKE: &str = include_str!("fixtures/bytes/quic-handshake.hex");
const ZERO_RTT: &str = include_str!("fixtures/bytes/quic-zero-rtt.hex");
const SHORT_HEADER: &str = include_str!("fixtures/bytes/quic-short-header.hex");
const FRAMES: &str = include_str!("fixtures/bytes/quic-frames.hex");
const TRANSPORT_PARAMETERS: &str = include_str!("fixtures/bytes/quic-transport-parameters.hex");
const MALFORMED_TRANSPORT_PARAMETERS: &str =
    include_str!("fixtures/malformed/quic-transport-parameters-corpus.hex");

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedHexFixtureCase {
    name: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MalformedTransportParameterExpected {
    BufferTooShort {
        context: String,
        required: usize,
        available: usize,
    },
    InvalidFieldValue {
        field: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MalformedTransportParameterCase {
    name: String,
    expected: MalformedTransportParameterExpected,
    bytes: Vec<u8>,
}

fn fixture_bytes(contents: &str) -> Vec<u8> {
    let mut hex = String::new();
    for line in contents.lines() {
        let bytes = line.split('#').next().unwrap_or_default();
        hex.extend(bytes.chars().filter(|ch| !ch.is_ascii_whitespace()));
    }
    assert_eq!(hex.len() % 2, 0, "fixture hex must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid fixture hex"))
        .collect()
}

fn named_hex_fixture_cases(contents: &str, fixture_name: &str) -> Vec<NamedHexFixtureCase> {
    contents
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
                3,
                "{fixture_name} line {} must have 3 fields",
                line_number + 1
            );
            Some(NamedHexFixtureCase {
                name: parts[0].to_string(),
                bytes: parse_named_hex(fixture_name, parts[0], parts[2]),
            })
        })
        .collect()
}

fn malformed_transport_parameter_cases() -> Vec<MalformedTransportParameterCase> {
    MALFORMED_TRANSPORT_PARAMETERS
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
                6,
                "QUIC transport-parameter malformed corpus line {} must have 6 fields",
                line_number + 1
            );
            let name = parts[0].to_string();
            Some(MalformedTransportParameterCase {
                expected: parse_malformed_transport_parameter_expected(&name, &parts),
                bytes: parse_named_hex(
                    "QUIC transport-parameter malformed corpus",
                    &name,
                    parts[5],
                ),
                name,
            })
        })
        .collect()
}

fn parse_malformed_transport_parameter_expected(
    name: &str,
    parts: &[&str],
) -> MalformedTransportParameterExpected {
    match parts[1] {
        "buffer-too-short" => MalformedTransportParameterExpected::BufferTooShort {
            context: parts[2].to_string(),
            required: parts[3]
                .parse()
                .unwrap_or_else(|_| panic!("case {name} has invalid required byte count")),
            available: parts[4]
                .parse()
                .unwrap_or_else(|_| panic!("case {name} has invalid available byte count")),
        },
        "invalid-field-value" => {
            assert_eq!(parts[3], "-", "case {name} must use '-' for required");
            assert_eq!(parts[4], "-", "case {name} must use '-' for available");
            MalformedTransportParameterExpected::InvalidFieldValue {
                field: parts[2].to_string(),
            }
        }
        expected => {
            panic!(
                "QUIC transport-parameter malformed corpus case {name} has unknown kind {expected}"
            )
        }
    }
}

fn parse_named_hex(fixture_name: &str, case_name: &str, hex: &str) -> Vec<u8> {
    let hex = hex.split_whitespace().collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "{fixture_name} case {case_name} has odd hex length"
    );
    hex.as_bytes()
        .chunks_exact(2)
        .map(|byte| {
            let byte = std::str::from_utf8(byte)
                .unwrap_or_else(|_| panic!("{fixture_name} case {case_name} has non-UTF8 hex"));
            u8::from_str_radix(byte, 16).unwrap_or_else(|_| {
                panic!("{fixture_name} case {case_name} has invalid hex {byte}")
            })
        })
        .collect()
}

fn assert_packet_roundtrip(packet: QuicPacket, expected: &[u8]) -> crafter::Result<()> {
    let compiled = Packet::from_layer(Quic::from_packets([packet])).compile()?;
    assert_eq!(compiled.as_bytes(), expected);
    Ok(())
}

fn cid_fixture() -> QuicConnectionId {
    QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0])
}

fn scid_fixture() -> QuicConnectionId {
    QuicConnectionId::from_bytes([0xaa])
}

fn retry_integrity_fixture() -> [u8; 16] {
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ]
}

fn fixture_case<'a>(cases: &'a [NamedHexFixtureCase], required: &str) -> &'a [u8] {
    cases
        .iter()
        .find(|case| case.name == required)
        .unwrap_or_else(|| panic!("missing fixture case {required}"))
        .bytes
        .as_slice()
}

#[test]
fn quic_header_golden_fixtures_decode_and_roundtrip() -> crafter::Result<()> {
    let version_negotiation = fixture_bytes(VERSION_NEGOTIATION);
    let packet = QuicPacket::decode(&version_negotiation)?;
    assert!(packet.is_version_negotiation());
    assert_eq!(
        packet.version_negotiation().unwrap().supported_versions(),
        [QUIC_VERSION_1, QUIC_VERSION_2]
    );
    assert_packet_roundtrip(packet, &version_negotiation)?;

    let retry = fixture_bytes(RETRY);
    let packet = QuicPacket::decode(&retry)?;
    assert!(packet.is_retry());
    assert_eq!(packet.retry().unwrap().token(), [0xde, 0xad, 0xbe]);
    assert_packet_roundtrip(packet, &retry)?;

    let v1_initial = fixture_bytes(V1_INITIAL);
    let packet = QuicPacket::decode(&v1_initial)?;
    let long = packet.long_header().expect("v1 Initial long header");
    assert_eq!(long.version(), QUIC_VERSION_1);
    assert_eq!(long.packet_kind(), QuicLongPacketKind::Initial);
    assert_eq!(long.protected_payload(), [0xbe, 0xef]);
    assert_packet_roundtrip(packet, &v1_initial)?;

    let v2_initial = fixture_bytes(V2_INITIAL);
    let packet = QuicPacket::decode(&v2_initial)?;
    let long = packet.long_header().expect("v2 Initial long header");
    assert_eq!(long.version(), QUIC_VERSION_2);
    assert_eq!(long.packet_kind(), QuicLongPacketKind::Initial);
    assert_eq!(long.protected_payload(), [0xbe, 0xef]);
    assert_packet_roundtrip(packet, &v2_initial)?;

    let handshake = fixture_bytes(HANDSHAKE);
    let packet = QuicPacket::decode(&handshake)?;
    let long = packet.long_header().expect("Handshake long header");
    assert_eq!(long.packet_kind(), QuicLongPacketKind::Handshake);
    assert_eq!(long.protected_payload(), [0xca, 0xfe]);
    assert_packet_roundtrip(packet, &handshake)?;

    let zero_rtt = fixture_bytes(ZERO_RTT);
    let packet = QuicPacket::decode(&zero_rtt)?;
    let long = packet.long_header().expect("0-RTT long header");
    assert_eq!(long.packet_kind(), QuicLongPacketKind::ZeroRtt);
    assert_eq!(long.protected_payload(), [0x0b, 0xad]);
    assert_packet_roundtrip(packet, &zero_rtt)?;

    let short_header = fixture_bytes(SHORT_HEADER);
    let short = QuicShortHeaderPacket::decode(&short_header, 4)?;
    assert_eq!(
        short.destination_connection_id().as_bytes(),
        [0x83, 0x94, 0xc8, 0xf0]
    );
    assert_eq!(short.packet_number().value(), 0x1234);
    assert_eq!(short.protected_payload(), [0xbe, 0xef]);
    assert_packet_roundtrip(QuicPacket::from_short_header(short), &short_header)?;

    Ok(())
}

#[test]
fn quic_packet_builder_golden_fixtures() -> crafter::Result<()> {
    let version_negotiation = fixture_bytes(VERSION_NEGOTIATION);
    let vn = QuicVersionNegotiationPacket::builder()
        .destination_connection_id(cid_fixture())
        .source_connection_id(scid_fixture())
        .supported_versions([QUIC_VERSION_1, QUIC_VERSION_2])
        .build()?;
    assert_eq!(vn.as_bytes(), version_negotiation);
    assert_packet_roundtrip(
        QuicPacket::from_version_negotiation(vn),
        &version_negotiation,
    )?;

    let retry = fixture_bytes(RETRY);
    let retry_packet = QuicRetryPacket::builder()
        .version(QUIC_VERSION_1)
        .destination_connection_id(cid_fixture())
        .source_connection_id(scid_fixture())
        .token([0xde, 0xad, 0xbe])
        .integrity_tag(retry_integrity_fixture())
        .build()?;
    assert_eq!(retry_packet.as_bytes(), retry);
    assert_packet_roundtrip(QuicPacket::from_retry(retry_packet), &retry)?;

    let initial_with_frames = fixture_bytes(V1_INITIAL_FRAMES);
    let frame_cases = named_hex_fixture_cases(FRAMES, "QUIC frame fixtures");
    let initial = QuicLongHeaderPacket::initial_builder()
        .destination_connection_id(cid_fixture())
        .source_connection_id(scid_fixture())
        .packet_number(QuicPacketNumber::new(1))
        .frames([
            QuicFrame::ping(),
            QuicFrame::crypto(QuicVarInt::from_u64_unchecked(0), [0xaa])?,
        ])
        .build()?;
    assert_eq!(
        initial.protected_payload(),
        fixture_case(&frame_cases, "initial-ping-crypto")
    );
    assert_eq!(initial.as_bytes(), initial_with_frames);
    assert_packet_roundtrip(QuicPacket::from_long_header(initial), &initial_with_frames)?;

    let handshake = fixture_bytes(HANDSHAKE);
    let handshake_packet = QuicLongHeaderPacket::handshake_builder()
        .destination_connection_id(cid_fixture())
        .source_connection_id(scid_fixture())
        .packet_number(QuicPacketNumber::new(2))
        .payload([0xca, 0xfe])
        .build()?;
    assert_eq!(handshake_packet.as_bytes(), handshake);
    assert_packet_roundtrip(QuicPacket::from_long_header(handshake_packet), &handshake)?;

    let short_header = fixture_bytes(SHORT_HEADER);
    let short = QuicShortHeaderPacket::builder()
        .destination_connection_id(cid_fixture())
        .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
        .payload([0xbe, 0xef])
        .build()?;
    assert_eq!(short.as_bytes(), short_header);
    assert_packet_roundtrip(QuicPacket::from_short_header(short), &short_header)?;

    Ok(())
}

#[test]
fn quic_frame_golden_fixtures_decode_and_roundtrip() -> crafter::Result<()> {
    let cases = named_hex_fixture_cases(FRAMES, "QUIC frame fixtures");
    assert_required_frame_fixture_cases(&cases);

    for case in &cases {
        let frames = QuicFrame::decode_sequence(&case.bytes)?;
        assert_eq!(
            QuicFrame::encode_sequence(frames.clone()),
            case.bytes,
            "case {}",
            case.name
        );

        match case.name.as_str() {
            "initial-ping-crypto" => assert_ping_crypto_frame_fixture(&frames)?,
            "datagram-len" => assert_datagram_len_frame_fixture(&frames, &case.bytes)?,
            "datagram-no-len" => assert_datagram_no_len_frame_fixture(&frames, &case.bytes)?,
            name => panic!("unexpected QUIC frame fixture case {name}"),
        }
    }

    Ok(())
}

fn assert_required_frame_fixture_cases(cases: &[NamedHexFixtureCase]) {
    for required in ["initial-ping-crypto", "datagram-len", "datagram-no-len"] {
        assert!(
            cases.iter().any(|case| case.name == required),
            "QUIC frame fixtures missing required case {required}"
        );
    }
}

fn assert_ping_crypto_frame_fixture(frames: &[QuicFrame]) -> crafter::Result<()> {
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].frame_type_value(), Some(0x01));
    let crypto = frames[1].crypto_frame()?.expect("CRYPTO frame");
    assert_eq!(crypto.offset().value(), 0);
    assert_eq!(crypto.data(), [0xaa]);
    Ok(())
}

fn assert_datagram_len_frame_fixture(frames: &[QuicFrame], expected: &[u8]) -> crafter::Result<()> {
    assert_eq!(frames.len(), 1);
    let datagram = frames[0].datagram_frame()?.expect("DATAGRAM_LEN frame");
    assert!(datagram.has_length());
    assert_eq!(datagram.frame_type_value(), 0x31);
    assert_eq!(datagram.length()?.unwrap().value(), 2);
    assert_eq!(datagram.data(), [0xde, 0xad]);
    assert_eq!(QuicFrame::datagram([0xde, 0xad])?.as_bytes(), expected);
    Ok(())
}

fn assert_datagram_no_len_frame_fixture(
    frames: &[QuicFrame],
    expected: &[u8],
) -> crafter::Result<()> {
    assert_eq!(frames.len(), 1);
    let datagram = frames[0].datagram_frame()?.expect("DATAGRAM frame");
    assert!(!datagram.has_length());
    assert_eq!(datagram.frame_type_value(), 0x30);
    assert_eq!(datagram.length()?, None);
    assert_eq!(datagram.data(), [0xde, 0xad]);
    assert_eq!(
        QuicFrame::from_datagram_frame(QuicDatagramFrame::new([0xde, 0xad]).without_length())?
            .as_bytes(),
        expected
    );
    Ok(())
}

#[test]
fn quic_transport_parameter_fixtures() -> crafter::Result<()> {
    let cases = named_hex_fixture_cases(TRANSPORT_PARAMETERS, "QUIC transport-parameter fixtures");
    assert_required_transport_parameter_fixture_cases(&cases);

    for case in &cases {
        assert_transport_parameter_fixture_case(case)?;
    }

    let malformed = malformed_transport_parameter_cases();
    assert_required_malformed_transport_parameter_cases(&malformed);

    for case in &malformed {
        assert_malformed_transport_parameter_case(case);
    }

    Ok(())
}

fn assert_required_transport_parameter_fixture_cases(cases: &[NamedHexFixtureCase]) {
    for required in [
        "common-v1",
        "datagram-extension",
        "version-information-v2",
        "preferred-address",
        "unknown-grease-duplicates",
    ] {
        assert!(
            cases.iter().any(|case| case.name == required),
            "QUIC transport-parameter fixtures missing required case {required}"
        );
    }
}

fn assert_transport_parameter_fixture_case(case: &NamedHexFixtureCase) -> crafter::Result<()> {
    let parameters = QuicTransportParameter::decode_sequence(&case.bytes)?;
    assert_eq!(
        QuicTransportParameter::encode_sequence(parameters.clone())?,
        case.bytes,
        "case {}",
        case.name
    );

    match case.name.as_str() {
        "common-v1" => assert_common_v1_transport_parameters(&parameters)?,
        "datagram-extension" => assert_datagram_transport_parameter(&parameters)?,
        "version-information-v2" => assert_version_information_transport_parameter(&parameters)?,
        "preferred-address" => assert_preferred_address_transport_parameter(&parameters)?,
        "unknown-grease-duplicates" => assert_unknown_grease_duplicate_parameters(&parameters)?,
        name => panic!("unexpected QUIC transport-parameter fixture case {name}"),
    }

    Ok(())
}

fn assert_common_v1_transport_parameters(
    parameters: &[QuicTransportParameter],
) -> crafter::Result<()> {
    assert_eq!(parameters.len(), 7);
    assert_eq!(
        transport_parameter_summaries(parameters),
        [
            "id=0xf kind=initial_source_connection_id value_len=4",
            "id=0x1 kind=max_idle_timeout value_len=1",
            "id=0x3 kind=max_udp_payload_size value_len=2",
            "id=0x4 kind=initial_max_data value_len=2",
            "id=0x8 kind=initial_max_streams_bidi value_len=1",
            "id=0xa kind=ack_delay_exponent value_len=1",
            "id=0xe kind=active_connection_id_limit value_len=1",
        ]
    );
    assert_eq!(
        parameters[0].known_type(),
        Some(QuicKnownTransportParameter::InitialSourceConnectionId)
    );
    assert_eq!(
        parameters[0].connection_id_value(),
        Some(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
    );
    assert_eq!(
        parameters[1].integer_type(),
        Some(QuicIntegerTransportParameter::MaxIdleTimeout)
    );
    assert_eq!(
        parameters[1].integer_value()?,
        Some(QuicVarInt::from_u64_unchecked(30))
    );
    assert_eq!(
        parameters[2].integer_value()?,
        Some(QuicVarInt::from_u64_unchecked(1200))
    );
    assert_eq!(
        parameters[3].integer_value()?,
        Some(QuicVarInt::from_u64_unchecked(100))
    );
    assert!(QuicTransportParameter::duplicate_identifiers(parameters).is_empty());
    Ok(())
}

fn assert_datagram_transport_parameter(
    parameters: &[QuicTransportParameter],
) -> crafter::Result<()> {
    assert_eq!(parameters.len(), 1);
    assert_eq!(
        parameters[0].integer_type(),
        Some(QuicIntegerTransportParameter::MaxDatagramFrameSize)
    );
    assert_eq!(
        parameters[0].integer_value()?,
        Some(QuicVarInt::from_u64_unchecked(1200))
    );
    assert_eq!(
        parameters[0].summary(),
        "id=0x20 kind=max_datagram_frame_size value_len=2"
    );
    Ok(())
}

fn assert_version_information_transport_parameter(
    parameters: &[QuicTransportParameter],
) -> crafter::Result<()> {
    assert_eq!(parameters.len(), 1);
    let version_information = parameters[0]
        .version_information_value()?
        .expect("version_information value");
    assert_eq!(version_information.chosen_version(), QUIC_VERSION_2);
    assert_eq!(version_information.available_versions(), &[QUIC_VERSION_1]);
    assert_eq!(
        parameters[0].summary(),
        "id=0x11 kind=version_information chosen_version=0x6b3343cf available_versions=0x00000001"
    );
    Ok(())
}

fn assert_preferred_address_transport_parameter(
    parameters: &[QuicTransportParameter],
) -> crafter::Result<()> {
    assert_eq!(parameters.len(), 1);
    let preferred = parameters[0]
        .preferred_address_value()?
        .expect("preferred_address value");
    assert_eq!(preferred.ipv4_address().to_string(), "192.0.2.10");
    assert_eq!(preferred.ipv4_port(), 4433);
    assert_eq!(preferred.ipv6_address().to_string(), "2001:db8::10");
    assert_eq!(preferred.ipv6_port(), 4434);
    assert_eq!(
        preferred.connection_id(),
        &QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0])
    );
    assert_eq!(
        parameters[0].summary(),
        "id=0xd kind=preferred_address ipv4=192.0.2.10:4433 ipv6=[2001:db8::10]:4434 connection_id_len=4 connection_id=8394c8f0"
    );
    Ok(())
}

fn assert_unknown_grease_duplicate_parameters(
    parameters: &[QuicTransportParameter],
) -> crafter::Result<()> {
    assert_eq!(parameters.len(), 3);
    assert_eq!(
        parameters[0].identifier(),
        Some(grease_transport_parameter_id(0)?)
    );
    assert_eq!(parameters[0].kind(), QuicTransportParameterKind::Grease);
    assert_eq!(parameters[0].value(), [0xaa, 0xbb, 0xcc]);
    assert_eq!(
        parameters[1].identifier(),
        Some(QuicVarInt::from_u64_unchecked(0x173e))
    );
    assert_eq!(parameters[1].kind(), QuicTransportParameterKind::Unknown);
    assert_eq!(parameters[1].value(), [0xde, 0xad]);
    assert_eq!(parameters[2].kind(), QuicTransportParameterKind::Unknown);

    let duplicates = QuicTransportParameter::duplicate_identifiers(parameters);
    assert_eq!(duplicates.len(), 1);
    assert_eq!(
        duplicates[0].identifier(),
        QuicVarInt::from_u64_unchecked(0x173e)
    );
    assert_eq!(duplicates[0].first_index(), 1);
    assert_eq!(duplicates[0].duplicate_index(), 2);
    assert_eq!(
        transport_parameter_summaries(parameters),
        [
            "id=0x1b kind=grease value_len=3",
            "id=0x173e kind=unknown value_len=2",
            "id=0x173e kind=unknown value_len=0",
        ]
    );
    Ok(())
}

fn transport_parameter_summaries(parameters: &[QuicTransportParameter]) -> Vec<String> {
    parameters
        .iter()
        .map(QuicTransportParameter::summary)
        .collect()
}

fn assert_required_malformed_transport_parameter_cases(cases: &[MalformedTransportParameterCase]) {
    for required in [
        "tuple-value-truncated",
        "integer-surplus",
        "stateless-reset-token-short",
        "preferred-address-token-truncated",
        "version-information-short",
        "version-information-unaligned",
        "grease-quic-bit-nonempty",
    ] {
        assert!(
            cases.iter().any(|case| case.name == required),
            "QUIC transport-parameter malformed corpus missing required case {required}"
        );
    }
}

fn assert_malformed_transport_parameter_case(case: &MalformedTransportParameterCase) {
    let err = QuicTransportParameter::decode_sequence(&case.bytes)
        .map(|_| ())
        .unwrap_err();
    match &case.expected {
        MalformedTransportParameterExpected::BufferTooShort {
            context,
            required,
            available,
        } => match err {
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
                "QUIC transport-parameter malformed corpus case {} expected BufferTooShort, got {other:?}",
                case.name
            ),
        },
        MalformedTransportParameterExpected::InvalidFieldValue { field } => match err {
            CrafterError::InvalidFieldValue {
                field: got,
                reason,
            } => {
                assert_eq!(got, field.as_str(), "case {}", case.name);
                assert!(
                    !reason.is_empty(),
                    "case {} InvalidFieldValue must carry a reason",
                    case.name
                );
            }
            other => panic!(
                "QUIC transport-parameter malformed corpus case {} expected InvalidFieldValue, got {other:?}",
                case.name
            ),
        },
    }
}
