//! Public QUIC API smoke tests.
//!
//! These tests use only offline construction with documentation address space
//! and import QUIC symbols through `crafter::prelude::*`.

use crafter::prelude::*;
use std::net::Ipv4Addr;

#[test]
fn exports_quic_symbols() -> crafter::Result<()> {
    assert_eq!(QUIC_VERSION_NEGOTIATION, 0x0000_0000);
    assert_eq!(QUIC_VERSION_1, 0x0000_0001);
    assert_eq!(QUIC_VERSION_2, 0x6b33_43cf);
    assert_eq!(crafter::QUIC_VERSION_1, QUIC_VERSION_1);

    let cid = QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]);
    assert_eq!(cid.as_bytes(), &[0x83, 0x94, 0xc8, 0xf0]);

    let varint = QuicVarInt::from_u64_unchecked(QUIC_VERSION_1 as u64);
    assert_eq!(varint.value(), QUIC_VERSION_1 as u64);

    let packet_number = QuicPacketNumber::new(0x1234).with_encoded_len(2);
    assert_eq!(packet_number.value(), 0x1234);
    assert_eq!(packet_number.encoded_len_value(), Some(2));

    let frame = QuicFrame::from_bytes([0x01]);
    assert_eq!(frame.as_bytes(), &[0x01]);
    assert_eq!(frame.kind(), QuicFrameKind::Known(QuicKnownFrameType::Ping));

    let ack = QuicAckFrame::from_values(1, 0, 0, [QuicAckRange::from_values(0, 0)?])?
        .with_ecn_counts(QuicAckEcnCounts::from_values(1, 2, 3)?);
    assert_eq!(
        QuicFrame::from_ack_frame(ack)?.frame_type_value(),
        Some(0x03)
    );
    let reset_stream = QuicResetStreamFrame::from_values(4, 0x1234, 99)?;
    assert_eq!(
        QuicFrame::from_reset_stream_frame(reset_stream)?.frame_type_value(),
        Some(0x04)
    );
    let stop_sending = QuicStopSendingFrame::from_values(4, 0x1234)?;
    assert_eq!(
        QuicFrame::from_stop_sending_frame(stop_sending)?.frame_type_value(),
        Some(0x05)
    );
    let crypto = QuicCryptoFrame::from_values(0, [0x16, 0x03, 0x03])?;
    assert_eq!(
        QuicFrame::from_crypto_frame(crypto)?.frame_type_value(),
        Some(0x06)
    );
    let new_token = QuicNewTokenFrame::new([0xde, 0xad]);
    assert_eq!(
        QuicFrame::from_new_token_frame(new_token)?.frame_type_value(),
        Some(0x07)
    );
    let stream = QuicStreamFrame::from_values(1, [0xaa])?.with_fin(true);
    assert_eq!(
        QuicFrame::from_stream_frame(stream)?.frame_type_value(),
        Some(0x0b)
    );
    let max_data = QuicMaxDataFrame::from_value(1024)?;
    assert_eq!(
        QuicFrame::from_max_data_frame(max_data)?.frame_type_value(),
        Some(0x10)
    );
    let max_stream_data = QuicMaxStreamDataFrame::from_values(1, 1024)?;
    assert_eq!(
        QuicFrame::from_max_stream_data_frame(max_stream_data)?.frame_type_value(),
        Some(0x11)
    );
    let max_streams = QuicMaxStreamsFrame::from_value(QuicStreamDirection::Bidirectional, 8)?;
    assert_eq!(
        QuicFrame::from_max_streams_frame(max_streams)?.frame_type_value(),
        Some(0x12)
    );
    assert_eq!(
        QuicFrame::max_streams_unidirectional(QuicVarInt::from_u64_unchecked(8))?
            .frame_type_value(),
        Some(0x13)
    );
    let data_blocked = QuicDataBlockedFrame::from_value(1024)?;
    assert_eq!(
        QuicFrame::from_data_blocked_frame(data_blocked)?.frame_type_value(),
        Some(0x14)
    );
    let stream_data_blocked = QuicStreamDataBlockedFrame::from_values(1, 1024)?;
    assert_eq!(
        QuicFrame::from_stream_data_blocked_frame(stream_data_blocked)?.frame_type_value(),
        Some(0x15)
    );
    let streams_blocked =
        QuicStreamsBlockedFrame::from_value(QuicStreamDirection::Bidirectional, 8)?;
    assert_eq!(
        QuicFrame::from_streams_blocked_frame(streams_blocked)?.frame_type_value(),
        Some(0x16)
    );
    assert_eq!(
        QuicFrame::streams_blocked_unidirectional(QuicVarInt::from_u64_unchecked(8))?
            .frame_type_value(),
        Some(0x17)
    );
    let new_connection_id = QuicNewConnectionIdFrame::new(
        QuicVarInt::from_u64_unchecked(1),
        QuicVarInt::from_u64_unchecked(0),
        QuicConnectionId::from_bytes([0xaa]),
        [0xab; 16],
    );
    assert_eq!(
        QuicFrame::from_new_connection_id_frame(new_connection_id)?.frame_type_value(),
        Some(0x18)
    );
    let retire_connection_id = QuicRetireConnectionIdFrame::from_value(1)?;
    assert_eq!(
        QuicFrame::from_retire_connection_id_frame(retire_connection_id)?.frame_type_value(),
        Some(0x19)
    );
    assert_eq!(
        QuicFrame::from_path_challenge_frame(QuicPathChallengeFrame::new([0xaa; 8]))?
            .frame_type_value(),
        Some(0x1a)
    );
    assert_eq!(
        QuicFrame::from_path_response_frame(QuicPathResponseFrame::new([0xbb; 8]))?
            .frame_type_value(),
        Some(0x1b)
    );
    let connection_close = QuicConnectionCloseFrame::transport(
        QUIC_TRANSPORT_ERROR_FRAME_ENCODING_ERROR,
        QuicVarInt::from_u64_unchecked(0x08),
        b"bad",
    );
    assert_eq!(connection_close.kind(), QuicConnectionCloseKind::Transport);
    assert_eq!(
        QuicFrame::from_connection_close_frame(connection_close)?.frame_type_value(),
        Some(0x1c)
    );
    assert_eq!(QUIC_TRANSPORT_ERROR_NO_ERROR.value(), 0);
    assert_eq!(
        QuicFrame::from_handshake_done_frame(QuicHandshakeDoneFrame::new())?.frame_type_value(),
        Some(0x1e)
    );

    let parameter = QuicTransportParameter::raw(varint, [0xde, 0xad]);
    assert_eq!(parameter.identifier(), Some(varint));
    assert_eq!(parameter.value(), &[0xde, 0xad]);

    let quic_payload = [0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
    let quic = Quic::from_bytes(quic_payload);
    let quic_packet = QuicPacket::from_bytes(quic_payload);
    assert_eq!(quic_packet.as_bytes(), quic_payload);
    let short = QuicShortHeaderBuilder::new()
        .packet_number(QuicPacketNumber::new(1))
        .build()?;
    assert_eq!(short.as_bytes(), [0x40, 0x01]);

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(443).dport(443)
        / quic;
    let compiled = packet.compile()?;
    assert!(compiled.as_bytes().ends_with(&quic_payload));
    assert!(packet.summary().contains("Quic"));

    let root_quic: crafter::Quic = Quic::raw([]);
    assert!(root_quic.is_empty());

    Ok(())
}

#[test]
fn quic_version_negotiation_build_public_api() -> crafter::Result<()> {
    let vn = QuicVersionNegotiationPacket::new(
        QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]),
        QuicConnectionId::from_bytes([0xaa]),
        [QUIC_VERSION_1, QUIC_VERSION_2],
    )?;
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(443).dport(443)
        / Quic::new().packet(QuicPacket::from_version_negotiation(vn.clone()));

    let compiled = packet.compile()?;
    assert!(compiled.as_bytes().ends_with(vn.as_bytes()));
    assert_eq!(
        QuicVersionNegotiationPacket::decode(vn.as_bytes())?.supported_versions(),
        &[QUIC_VERSION_1, QUIC_VERSION_2],
    );
    assert!(packet.summary().contains("VersionNegotiation"));

    Ok(())
}
