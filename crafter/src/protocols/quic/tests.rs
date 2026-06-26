use std::net::Ipv4Addr;

use crate::error::CrafterError;
use crate::field::FieldState;
use crate::packet::{Layer, NetworkLayer, Packet, Raw};
use crate::protocols::ip::v4::Ipv4;
use crate::protocols::transport::Udp;

use super::decode::{append_quic_packet, decode_quic_datagram};
use super::{
    Quic, QuicConnectionId, QuicFrame, QuicLongHeaderPacket, QuicPacket, QuicPacketNumber,
};

#[test]
fn quic_module_skeleton_layer_compiles_raw_payload() -> crate::Result<()> {
    let payload = [0xc3, 0xfa, 0xce, 0xfe, 0xed, 0x00, 0x00, 0xaa, 0xbb];
    let quic = Quic::from_bytes(payload);
    let packet = Packet::from_layer(quic.clone());
    let compiled = packet.compile()?;

    assert_eq!(compiled.as_bytes(), payload);
    assert_eq!(quic.payload_state(), FieldState::User);
    assert_eq!(quic.payload_bytes(), payload);
    assert_eq!(
        quic.summary(),
        "Quic(raw_len=9, packets=0, header=long kind=UnknownVersion first_byte=0xc3 fixed_bit=true quic_bit=set version=0xfacefeed(unknown version 0xfacefeed) dcid=len=0 value=<empty> scid=len=0 value=<empty> protected_or_raw_len=2, frames=0, transport_parameters=0)"
    );
    Ok(())
}

#[test]
fn quic_module_skeleton_explicit_decode_stub_preserves_payload() -> crate::Result<()> {
    let payload = [0xc3, 0xfa, 0xce, 0xfe, 0xed, 0x00, 0x00, 0xaa, 0xbb];
    let packet = append_quic_packet(Packet::new(), &payload)?;
    let quic = packet.layer::<Quic>().expect("QUIC placeholder layer");

    assert_eq!(quic.payload_state(), FieldState::User);
    assert_eq!(quic.payload_bytes(), payload);
    assert_eq!(packet.compile()?.as_bytes(), payload);
    Ok(())
}

#[test]
fn quic_module_skeleton_empty_decode_returns_structured_error() {
    let err = decode_quic_datagram(&[]).expect_err("empty QUIC datagram is malformed");

    assert_eq!(
        err,
        CrafterError::BufferTooShort {
            context: "quic.datagram",
            required: 1,
            available: 0,
        }
    );
}

#[test]
fn quic_module_skeleton_udp_payload_remains_raw_without_dispatch() -> crate::Result<()> {
    let quic_like_payload = [0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(49_152).dport(4_433)
        / Raw::from_bytes(quic_like_payload);
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    assert!(decoded.layer::<Quic>().is_none());
    assert_eq!(
        decoded
            .layer::<Raw>()
            .expect("unsupported UDP payload remains raw")
            .as_bytes(),
        quic_like_payload
    );
    Ok(())
}

#[test]
fn quic_unknown_payload_preservation_unknown_version_datagram_roundtrips() -> crate::Result<()> {
    let payload = [0xc3, 0xfa, 0xce, 0xfe, 0xed, 0x00, 0x00, 0xaa, 0xbb];

    let quic = decode_quic_datagram(&payload)?;

    assert_eq!(quic.payload_bytes(), payload);
    assert!(quic.summary().contains("UnknownVersion"));
    assert_eq!(Packet::from_layer(quic).compile()?.as_bytes(), payload);
    Ok(())
}

#[test]
fn quic_unknown_payload_preservation_unknown_version_packet_entry_roundtrips() -> crate::Result<()>
{
    let payload = [0xc3, 0xfa, 0xce, 0xfe, 0xed, 0x00, 0x00, 0xaa, 0xbb];

    let packet = QuicPacket::decode(payload)?;

    assert!(!packet.is_long_header());
    assert_eq!(packet.as_bytes(), payload);
    assert!(packet.summary().contains("UnknownVersion"));
    assert_eq!(
        Packet::from_layer(Quic::new().packet(packet))
            .compile()?
            .as_bytes(),
        payload
    );
    Ok(())
}

#[test]
fn quic_unknown_payload_preservation_encrypted_initial_payload_roundtrips() -> crate::Result<()> {
    let initial = QuicLongHeaderPacket::initial_builder()
        .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
        .payload([0x40, 0xaf, 0xde, 0xad])
        .build()?;
    let packet = QuicPacket::decode(initial.as_bytes())?;

    assert!(packet.is_long_header());
    assert_eq!(
        packet.long_header().unwrap().protected_payload(),
        [0x40, 0xaf, 0xde, 0xad]
    );
    assert_eq!(
        Packet::from_layer(Quic::new().packet(packet))
            .compile()?
            .as_bytes(),
        initial.as_bytes()
    );
    Ok(())
}

#[test]
fn quic_unknown_payload_preservation_unsupported_frame_bytes_stay_protected() -> crate::Result<()> {
    let frame_bytes = [0x3f, 0xde, 0xad, 0xbe, 0xef];
    let initial = QuicLongHeaderPacket::initial_builder()
        .frame(QuicFrame::from_bytes(frame_bytes))
        .build()?;
    let decoded = QuicLongHeaderPacket::decode(initial.as_bytes())?;

    assert_eq!(decoded.protected_payload(), frame_bytes);
    assert_eq!(
        Packet::from_layer(Quic::from_packets([QuicPacket::from_long_header(decoded)]))
            .compile()?
            .as_bytes(),
        initial.as_bytes()
    );
    Ok(())
}

#[test]
fn quic_encrypted_payload_raw_default_keeps_packet_payloads_opaque() -> crate::Result<()> {
    let dcid = QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]);
    let frame_like_payload = [0x01, 0x06, 0x00, 0x01, 0xaa];

    let initial = QuicLongHeaderPacket::initial_builder()
        .destination_connection_id(dcid.clone())
        .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
        .protected_payload(frame_like_payload)
        .build()?;
    let initial_packet = QuicPacket::decode(initial.as_bytes())?;
    assert_long_payload_stays_raw(initial_packet, initial.as_bytes(), frame_like_payload)?;

    let handshake = QuicLongHeaderPacket::handshake_builder()
        .destination_connection_id(dcid.clone())
        .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
        .protected_payload(frame_like_payload)
        .build()?;
    let handshake_packet = QuicPacket::decode(handshake.as_bytes())?;
    assert_long_payload_stays_raw(handshake_packet, handshake.as_bytes(), frame_like_payload)?;

    let zero_rtt = QuicLongHeaderPacket::zero_rtt_builder()
        .destination_connection_id(dcid.clone())
        .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
        .protected_payload(frame_like_payload)
        .build()?;
    let zero_rtt_packet = QuicPacket::decode(zero_rtt.as_bytes())?;
    assert_long_payload_stays_raw(zero_rtt_packet, zero_rtt.as_bytes(), frame_like_payload)?;

    let short = super::QuicShortHeaderBuilder::new()
        .destination_connection_id(dcid.clone())
        .packet_number(QuicPacketNumber::new(0x1234).with_encoded_len(2))
        .protected_payload(frame_like_payload)
        .build()?;
    let short_with_context = QuicPacket::decode_short_header(short.as_bytes(), dcid.len())?;
    let short_header = short_with_context
        .short_header()
        .expect("caller-context short header");
    assert_eq!(short_header.protected_payload(), frame_like_payload);
    assert_eq!(short_with_context.as_bytes(), short.as_bytes());
    let short_quic = Quic::from_packets([short_with_context]);
    assert_eq!(short_quic.frame_count(), 0);
    assert_eq!(
        Packet::from_layer(short_quic).compile()?.as_bytes(),
        short.as_bytes()
    );

    let default_short = QuicPacket::decode(short.as_bytes())?;
    assert!(!default_short.is_short_header());
    assert_eq!(default_short.as_bytes(), short.as_bytes());

    Ok(())
}

fn assert_long_payload_stays_raw(
    packet: QuicPacket,
    expected_packet_bytes: &[u8],
    expected_payload: [u8; 5],
) -> crate::Result<()> {
    let long = packet.long_header().expect("long header packet");
    assert_eq!(long.protected_payload(), expected_payload);
    assert_eq!(packet.as_bytes(), expected_packet_bytes);

    let quic = Quic::from_packets([packet]);
    assert_eq!(quic.frame_count(), 0);
    assert_eq!(quic.transport_parameter_count(), 0);
    assert!(quic.summary().contains("frames=0"));
    assert_eq!(
        Packet::from_layer(quic).compile()?.as_bytes(),
        expected_packet_bytes
    );

    Ok(())
}
