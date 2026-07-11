//! Public QUIC API smoke tests.
//!
//! These tests use only offline construction with documentation address space
//! and import QUIC symbols through `crafter::prelude::*`.

use crafter::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn public_api_initial(payload: impl AsRef<[u8]>) -> crafter::Result<QuicLongHeaderPacket> {
    let crypto = QuicFrame::crypto(QuicVarInt::from_u64_unchecked(0), payload)?;
    QuicLongHeaderPacket::initial_builder()
        .destination_connection_id(QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]))
        .source_connection_id(QuicConnectionId::from_bytes([0xaa]))
        .packet_number(QuicPacketNumber::new(1))
        .frames([crypto])
        .build()
}

#[test]
fn quic_packet_number_reconstructs_full_values() -> crafter::Result<()> {
    // RFC 9000 Appendix A.3 example: largest authenticated packet is
    // 0xa82f30ea, so the expected next value is 0xa82f30eb.
    let example = QuicPacketNumber::new(0x9b32).with_encoded_len(2);
    assert_eq!(example.reconstruct(0xa82f30eb)?, 0xa82f9b32);

    let width_vectors = [
        (1, 0xabu64, 0x1234u64, 0x12abu64),
        (2, 0xcdef, 0x12_d000, 0x12_cdef),
        (3, 0x12_3456, 0x1234_5678, 0x1212_3456),
        (4, 0x1234_5678, 0x1234_5678_9abc, 0x1234_1234_5678),
    ];
    for (encoded_len, truncated, expected, reconstructed) in width_vectors {
        assert_eq!(
            QuicPacketNumber::new(truncated)
                .with_encoded_len(encoded_len)
                .reconstruct(expected)?,
            reconstructed
        );
    }

    // The lower edge is inclusive and moves to the next window; the upper
    // edge is inclusive in the current window and moves only when exceeded.
    assert_eq!(
        QuicPacketNumber::new(0x02)
            .with_encoded_len(1)
            .reconstruct(0xaa82)?,
        0xab02
    );
    assert_eq!(
        QuicPacketNumber::new(0x80)
            .with_encoded_len(1)
            .reconstruct(0xaa00)?,
        0xaa80
    );
    assert_eq!(
        QuicPacketNumber::new(0x81)
            .with_encoded_len(1)
            .reconstruct(0xaa00)?,
        0xa981
    );
    assert_eq!(
        QuicPacketNumber::new(0xff)
            .with_encoded_len(1)
            .reconstruct(0)?,
        0xff
    );
    assert_eq!(
        QuicPacketNumber::new(0)
            .with_encoded_len(1)
            .reconstruct((1u64 << 62) - 2)?,
        (1u64 << 62) - 256
    );

    assert!(matches!(
        QuicPacketNumber::new(0).reconstruct(1u64 << 62),
        Err(CrafterError::InvalidFieldValue {
            field: "quic.packet_number.expected_next",
            ..
        })
    ));
    assert!(matches!(
        QuicPacketNumber::new(0).with_encoded_len(0).reconstruct(0),
        Err(CrafterError::InvalidFieldValue {
            field: "quic.packet_number.length",
            ..
        })
    ));

    Ok(())
}

#[test]
fn exports_quic_symbols() -> crafter::Result<()> {
    assert_eq!(QUIC_VERSION_NEGOTIATION, 0x0000_0000);
    assert_eq!(QUIC_VERSION_1, 0x0000_0001);
    assert_eq!(QUIC_VERSION_2, 0x6b33_43cf);
    assert_eq!(crafter::QUIC_VERSION_1, QUIC_VERSION_1);

    let cid = QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]);
    assert_eq!(cid.as_bytes(), &[0x83, 0x94, 0xc8, 0xf0]);
    assert_eq!(QUIC_INITIAL_SECRET_LEN, 32);
    assert_eq!(QUIC_INITIAL_AES_128_KEY_LEN, 16);
    assert_eq!(QUIC_INITIAL_IV_LEN, 12);
    assert_eq!(QUIC_INITIAL_HP_KEY_LEN, 16);
    assert_eq!(QUIC_INITIAL_AEAD_TAG_LEN, 16);
    assert_eq!(QUIC_HEADER_PROTECTION_SAMPLE_LEN, 16);
    assert_eq!(QUIC_HEADER_PROTECTION_MASK_LEN, 5);
    assert_eq!(QUIC_AES128_HEADER_PROTECTION_KEY_LEN, 16);
    assert_eq!(QUIC_CHACHA20_HEADER_PROTECTION_KEY_LEN, 32);
    assert_eq!(QuicHeaderProtectionAlgorithm::Aes128.label(), "aes128");
    assert_eq!(QuicInitialPacketDirection::Client.label(), "client");
    assert_eq!(QuicInitialPacketDirection::Server.label(), "server");
    assert_eq!(
        QuicFixedBitStatus::GreasedCleared.label(),
        "greased_cleared"
    );
    assert_eq!(quic_fixed_bit_label(false), "greased_cleared");
    assert_eq!(
        quic_fixed_bit_status(quic_clear_fixed_bit(0xc0)),
        QuicFixedBitStatus::GreasedCleared
    );
    assert_eq!(quic_set_fixed_bit(0x80), 0xc0);
    assert_eq!(QuicRetryIntegrityStatus::Valid.label(), "valid");
    assert_eq!(
        QuicRetryIntegrityStatus::UnsupportedVersion.label(),
        "unsupported_version"
    );
    assert_eq!(QUIC_STATELESS_RESET_MIN_LEN, 21);
    let reset_candidate = QuicStatelessResetCandidate::decode([
        0x40, 0, 1, 2, 3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
        0xcc, 0xcc, 0xcc, 0xcc,
    ])?;
    assert!(reset_candidate.token_matches([0xcc; QUIC_STATELESS_RESET_TOKEN_LEN]));
    assert_eq!(quic_initial_salt(QUIC_VERSION_1)?, &QUIC_V1_INITIAL_SALT);
    assert_eq!(crafter::QUIC_V2_INITIAL_SALT.len(), 20);
    let initial_secrets = derive_quic_initial_secrets(QUIC_VERSION_1, &cid)?;
    let initial_keys = initial_secrets.client_packet_keys()?;
    assert_eq!(
        initial_secrets.client_initial_secret().len(),
        QUIC_INITIAL_SECRET_LEN
    );
    assert_eq!(initial_keys.key().len(), QUIC_INITIAL_AES_128_KEY_LEN);
    assert_eq!(
        quic_initial_payload_nonce(initial_keys.iv(), 0),
        *initial_keys.iv()
    );
    let protected = quic_initial_aes128gcm_protect_payload(&initial_keys, 0, b"aad", b"payload")?;
    assert_eq!(
        quic_initial_aes128gcm_unprotect_payload(&initial_keys, 0, b"aad", &protected)?,
        b"payload"
    );
    assert_eq!(
        initial_keys.protect_payload(0, b"aad", b"payload")?.len(),
        23
    );
    assert_eq!(
        quic_aes128_header_protection_mask([0u8; 16], [0u8; 16])?.len(),
        QUIC_HEADER_PROTECTION_MASK_LEN
    );
    assert_eq!(
        quic_chacha20_header_protection_mask([0u8; 32], [0u8; 16])?.len(),
        QUIC_HEADER_PROTECTION_MASK_LEN
    );

    let varint = QuicVarInt::from_u64_unchecked(QUIC_VERSION_1 as u64);
    assert_eq!(varint.value(), QUIC_VERSION_1 as u64);

    let packet_number = QuicPacketNumber::new(0x1234).with_encoded_len(2);
    assert_eq!(packet_number.value(), 0x1234);
    assert_eq!(packet_number.encoded_len_value(), Some(2));
    let greased_header = QuicHeader::new()
        .header_form(QuicHeaderForm::Long)
        .fixed_bit(true)
        .grease_quic_bit();
    assert_eq!(
        greased_header.quic_bit_label_value(),
        Some("greased_cleared")
    );

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
    let datagram = QuicDatagramFrame::new([0xde, 0xad]);
    assert_eq!(
        QuicFrame::from_datagram_frame(datagram)?.frame_type_value(),
        Some(0x31)
    );
    assert_eq!(
        QuicFrame::datagram_without_length([0xde, 0xad])?
            .datagram_frame()?
            .unwrap()
            .data(),
        &[0xde, 0xad]
    );
    let unknown = QuicUnknownFrame::new(QuicVarInt::from_u64_unchecked(0xaf), [0xde, 0xad]);
    let unknown_frame = QuicFrame::from_unknown_frame(unknown)?;
    assert_eq!(unknown_frame.kind(), QuicFrameKind::Unknown);
    assert_eq!(
        unknown_frame
            .unknown_frame()?
            .unwrap()
            .raw_following_bytes(),
        &[0xde, 0xad]
    );

    let parameter = QuicTransportParameter::raw(varint, [0xde, 0xad]);
    assert_eq!(parameter.identifier(), Some(varint));
    assert_eq!(parameter.value(), &[0xde, 0xad]);
    let known_parameter =
        QuicTransportParameter::known(QuicKnownTransportParameter::MaxIdleTimeout, [0x03]);
    assert_eq!(
        known_parameter.kind(),
        QuicTransportParameterKind::Known(QuicKnownTransportParameter::MaxIdleTimeout)
    );
    assert!(is_grease_transport_parameter_id(
        QuicVarInt::from_u64_unchecked(27)
    ));
    assert_eq!(grease_transport_parameter_id(1)?.value(), 58);
    assert_eq!(
        QuicTransportParameter::grease(1, [0xde, 0xad])?
            .identifier()
            .unwrap()
            .value(),
        58
    );
    assert_eq!(
        QuicTransportParameter::grease_quic_bit().grease_quic_bit_value()?,
        Some(())
    );
    let integer_parameter =
        QuicTransportParameter::max_udp_payload_size(QuicVarInt::from_u64_unchecked(1199))?;
    assert_eq!(
        integer_parameter.integer_type(),
        Some(QuicIntegerTransportParameter::MaxUdpPayloadSize)
    );
    assert_eq!(
        integer_parameter.integer_validation_finding()?,
        Some(QuicIntegerTransportParameterValidation::MaxUdpPayloadSizeBelowMinimum)
    );
    let connection_id_parameter =
        QuicTransportParameter::initial_source_connection_id(QuicConnectionId::from_bytes([0xaa]));
    assert_eq!(
        connection_id_parameter.connection_id_type(),
        Some(QuicConnectionIdTransportParameter::InitialSourceConnectionId)
    );
    assert_eq!(
        connection_id_parameter
            .connection_id_value()
            .unwrap()
            .as_bytes(),
        &[0xaa]
    );
    assert_eq!(QUIC_STATELESS_RESET_TOKEN_LEN, 16);
    let reset_token = QuicStatelessResetToken::new([0xcc; QUIC_STATELESS_RESET_TOKEN_LEN]);
    let reset_token_parameter = QuicTransportParameter::stateless_reset_token(reset_token);
    assert!(reset_token_parameter.is_stateless_reset_token());
    assert_eq!(
        reset_token_parameter.stateless_reset_token_value()?,
        Some(reset_token)
    );
    let preferred_address = QuicPreferredAddress::new(
        Ipv4Addr::new(192, 0, 2, 10),
        4433,
        Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010),
        4434,
        QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]),
        reset_token,
    );
    let preferred_parameter = QuicTransportParameter::preferred_address(preferred_address)?;
    assert_eq!(
        preferred_parameter
            .preferred_address_value()?
            .unwrap()
            .validation_findings(),
        Vec::<QuicPreferredAddressValidation>::new()
    );
    let version_information =
        QuicVersionInformation::new(QUIC_VERSION_1, [QUIC_VERSION_2, QUIC_VERSION_1]);
    assert_eq!(version_information.chosen_version_label(), "QUIC v1");
    assert_eq!(
        version_information.available_version_labels(),
        vec!["QUIC v2".to_string(), "QUIC v1".to_string()]
    );
    let version_parameter = QuicTransportParameter::version_information(version_information);
    assert_eq!(
        version_parameter
            .version_information_value()?
            .unwrap()
            .available_versions(),
        &[QUIC_VERSION_2, QUIC_VERSION_1]
    );
    assert_eq!(
        QuicVersionInformation::v2_with_v1_available().available_versions(),
        &[QUIC_VERSION_1]
    );
    assert_eq!(
        QuicVersionInformation::new(0, [0])
            .validation_findings()
            .len(),
        2
    );

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
fn ipv4_udp_quic_public_api_compile_decode_offline() -> crafter::Result<()> {
    let initial = public_api_initial([0x16, 0x03, 0x03])?;
    let initial_bytes = initial.as_bytes().to_vec();
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(49_152).dport(4433)
        / Quic::new().packet(QuicPacket::from_long_header(initial));

    let compiled = packet.compile()?;
    assert!(compiled.as_bytes().ends_with(&initial_bytes));

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let quic = decoded.layer::<Quic>().expect("typed QUIC layer");
    assert_eq!(quic.len(), initial_bytes.len());
    assert_eq!(quic.packets().len(), 1);
    assert!(quic.packets()[0].is_long_header());
    assert_eq!(
        quic.packets()[0].long_header().unwrap().version(),
        QUIC_VERSION_1
    );
    assert!(decoded.layer::<Raw>().is_none());

    let summary = decoded.summary();
    assert!(summary.contains("Ipv4("), "{summary}");
    assert!(summary.contains("Udp("), "{summary}");
    assert!(summary.contains("Quic("), "{summary}");
    assert!(summary.contains("packets=1"), "{summary}");
    Ok(())
}

#[test]
fn ipv6_udp_quic_public_api_compile_decode_offline() -> crafter::Result<()> {
    let initial = public_api_initial([0x01])?;
    let initial_bytes = initial.as_bytes().to_vec();
    let packet = Ipv6::new()
        .src(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010))
        .dst(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0020))
        / Udp::new().sport(49_153).dport(4433)
        / Quic::new().packet(QuicPacket::from_long_header(initial));

    let compiled = packet.compile()?;
    assert!(compiled.as_bytes().ends_with(&initial_bytes));

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let quic = decoded.layer::<Quic>().expect("typed QUIC layer");
    assert_eq!(quic.len(), initial_bytes.len());
    assert_eq!(quic.packets().len(), 1);
    assert!(quic.packets()[0].is_long_header());
    assert_eq!(
        quic.packets()[0].long_header().unwrap().version(),
        QUIC_VERSION_1
    );
    assert!(decoded.layer::<Raw>().is_none());

    let summary = decoded.summary();
    assert!(summary.contains("Ipv6("), "{summary}");
    assert!(summary.contains("Udp("), "{summary}");
    assert!(summary.contains("Quic("), "{summary}");
    assert!(summary.contains("packets=1"), "{summary}");
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
