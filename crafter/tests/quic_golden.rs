//! QUIC golden header fixtures.
//!
//! Fixture comments cite the source-backed QUIC notes in `.agents/docs/`.
//! These tests stay offline and exercise raw QUIC packet bytes directly.

use crafter::protocols::quic::header::QuicLongPacketKind;
use crafter::{Packet, Quic, QuicPacket, QuicShortHeaderPacket, QUIC_VERSION_1, QUIC_VERSION_2};

const VERSION_NEGOTIATION: &str = include_str!("fixtures/bytes/quic-version-negotiation.hex");
const RETRY: &str = include_str!("fixtures/bytes/quic-retry.hex");
const V1_INITIAL: &str = include_str!("fixtures/bytes/quic-v1-initial.hex");
const V2_INITIAL: &str = include_str!("fixtures/bytes/quic-v2-initial.hex");
const HANDSHAKE: &str = include_str!("fixtures/bytes/quic-handshake.hex");
const ZERO_RTT: &str = include_str!("fixtures/bytes/quic-zero-rtt.hex");
const SHORT_HEADER: &str = include_str!("fixtures/bytes/quic-short-header.hex");

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

fn assert_packet_roundtrip(packet: QuicPacket, expected: &[u8]) -> crafter::Result<()> {
    let compiled = Packet::from_layer(Quic::from_packets([packet])).compile()?;
    assert_eq!(compiled.as_bytes(), expected);
    Ok(())
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
