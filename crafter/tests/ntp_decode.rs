use std::net::Ipv4Addr;

use crafter::prelude::*;

fn udp_123_packet_bytes(payload: &[u8]) -> crafter::Result<Vec<u8>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 123))
        / Udp::new().source_port(NTP_PORT).destination_port(NTP_PORT)
        / Raw::from_bytes(payload.to_vec());

    Ok(packet.compile()?.into_bytes())
}

fn decode_udp_123_payload(payload: &[u8]) -> crafter::Result<Packet> {
    let bytes = udp_123_packet_bytes(payload)?;
    Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)
}

fn assert_ntp_raw_fallback(payload: &[u8]) -> crafter::Result<()> {
    let decoded = decode_udp_123_payload(payload)?;

    assert!(decoded.layer::<Ntp>().is_none());
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), payload);
    Ok(())
}

#[test]
fn ntp_raw_fallback_preserves_too_short_udp_123_payload() -> crafter::Result<()> {
    let payload = [0x23, 0x00, 0x00, 0x00];

    match Ntp::decode(&payload).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ntp.header");
            assert_eq!(required, NTP_FIXED_HEADER_LEN);
            assert_eq!(available, payload.len());
        }
        other => panic!("unexpected NTP decode error: {other:?}"),
    }

    assert!(!looks_like_ntp_payload(&payload));
    assert_ntp_raw_fallback(&payload)
}

#[test]
fn ntp_raw_fallback_preserves_random_shape_invalid_udp_123_payload() -> crafter::Result<()> {
    let payload = [
        0x05, 0x8d, 0x4a, 0x73, 0x91, 0x02, 0xee, 0x19, 0x44, 0xb8, 0x6d, 0x0c, 0x37, 0xfa, 0x51,
        0x28, 0x90, 0xce, 0x11, 0x62, 0x5b, 0x07, 0xd4, 0x39, 0xac, 0x13, 0x55, 0x80, 0x0f, 0x24,
        0x6a, 0xbd, 0x71, 0x09, 0xc2, 0xef, 0x3e, 0x48, 0x84, 0x16, 0xd9, 0x5a, 0x22, 0x67, 0x9c,
        0x30, 0xab, 0xfe,
    ];

    assert!(!looks_like_ntp_payload(&payload));
    assert_ntp_raw_fallback(&payload)
}

#[test]
fn ntp_raw_fallback_preserves_shape_invalid_extension_tail() -> crafter::Result<()> {
    let mut payload = Packet::from_layer(Ntp::client()).compile()?.into_bytes();
    payload.extend_from_slice(&0x0204u16.to_be_bytes());
    payload.extend_from_slice(&12u16.to_be_bytes());
    payload.extend_from_slice(&[0; 8]);

    assert!(Ntp::decode(&payload).is_err());
    assert!(!looks_like_ntp_payload(&payload));
    assert_ntp_raw_fallback(&payload)
}

#[test]
fn ntp_registry_toggles_empty_registry_does_not_decode_ntp() -> crafter::Result<()> {
    let payload = Packet::from_layer(Ntp::client()).compile()?.into_bytes();
    let bytes = udp_123_packet_bytes(&payload)?;
    let registry = ProtocolRegistry::empty();

    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &bytes)?;

    assert!(decoded.layer::<Ntp>().is_none());
    assert!(decoded.layer::<Udp>().is_none());
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &bytes[20..]);
    Ok(())
}

#[test]
fn ntp_registry_toggles_custom_udp_binding_overrides_builtin() -> crafter::Result<()> {
    let payload = Packet::from_layer(Ntp::client()).compile()?.into_bytes();
    let bytes = udp_123_packet_bytes(&payload)?;
    let mut registry = ProtocolRegistry::new();
    registry.bind_udp_port(NTP_PORT, |packet, payload| {
        Ok(packet.push(Raw::from_bytes(payload)))
    });

    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &bytes)?;

    assert!(decoded.layer::<Udp>().is_some());
    assert!(decoded.layer::<Ntp>().is_none());
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), payload);
    Ok(())
}

#[test]
fn ntp_registry_toggles_application_decoding_false_preserves_raw() -> crafter::Result<()> {
    let payload = Packet::from_layer(Ntp::client()).compile()?.into_bytes();
    let bytes = udp_123_packet_bytes(&payload)?;
    let registry = ProtocolRegistry::new().application_decoding(false);

    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &bytes)?;

    assert!(decoded.layer::<Udp>().is_some());
    assert!(decoded.layer::<Ntp>().is_none());
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), payload);
    Ok(())
}

#[test]
fn ntpv3_sntp_compatibility_fixed_header_bytes_preserve_wire_values() -> crafter::Result<()> {
    let ntpv3_payload = [
        0x1c, 0x01, 0x06, 0xec, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0xc0, 0x00, b'L', b'O', b'C',
        b'L', 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
        0xa7, 0xa8, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
        0xc6, 0xc7, 0xc8,
    ];
    let sntp_payload = [
        0x23, 0x00, 0x06, 0xec, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe4, 0xe1, 0xce, 0x01, 0x12,
        0x34, 0x56, 0x78,
    ];

    let cases = [
        (
            "ntpv3",
            ntpv3_payload.as_slice(),
            0x1c,
            NtpVersion::from_wire(3),
            NtpMode::Server,
            NTP_STRATUM_PRIMARY,
            0x0001_8000,
            0x0000_c000,
            *b"LOCL",
            0xd1d2_d3d4_d5d6_d7d8,
            0xa1a2_a3a4_a5a6_a7a8,
            0xb1b2_b3b4_b5b6_b7b8,
            0xc1c2_c3c4_c5c6_c7c8,
        ),
        (
            "sntp",
            sntp_payload.as_slice(),
            0x23,
            NtpVersion::current(),
            NtpMode::Client,
            NTP_STRATUM_UNSPECIFIED,
            0,
            0,
            [0, 0, 0, 0],
            0,
            0,
            0,
            0xe4e1_ce01_1234_5678,
        ),
    ];

    for (
        name,
        payload,
        first_octet,
        version,
        mode,
        stratum,
        root_delay,
        root_dispersion,
        reference_id,
        reference_timestamp,
        origin_timestamp,
        receive_timestamp,
        transmit_timestamp,
    ) in cases
    {
        assert_eq!(payload.len(), NTP_FIXED_HEADER_LEN, "{name}");
        assert!(looks_like_ntp_payload(payload), "{name}");

        let decoded = decode_udp_123_payload(payload)?;

        let udp = decoded.layer::<Udp>().expect("decoded UDP layer");
        assert_eq!(udp.source_port_value(), NTP_PORT, "{name}");
        assert_eq!(udp.destination_port_value(), NTP_PORT, "{name}");

        let ntp = decoded.layer::<Ntp>().expect("decoded NTP layer");
        assert_eq!(ntp.first_octet_value(), first_octet, "{name}");
        assert_eq!(ntp.version_value_effective(), version, "{name}");
        assert_eq!(ntp.mode_value(), mode, "{name}");
        assert_eq!(ntp.stratum_value().value(), stratum, "{name}");
        assert_eq!(ntp.poll_value(), 6, "{name}");
        assert_eq!(ntp.precision_value(), -20, "{name}");
        assert_eq!(ntp.root_delay_value().raw(), root_delay, "{name}");
        assert_eq!(ntp.root_dispersion_value().raw(), root_dispersion, "{name}");
        assert_eq!(ntp.reference_id_value().bytes(), reference_id, "{name}");
        assert_eq!(
            ntp.reference_timestamp_value().raw(),
            reference_timestamp,
            "{name}"
        );
        assert_eq!(
            ntp.origin_timestamp_value().raw(),
            origin_timestamp,
            "{name}"
        );
        assert_eq!(
            ntp.receive_timestamp_value().raw(),
            receive_timestamp,
            "{name}"
        );
        assert_eq!(
            ntp.transmit_timestamp_value().raw(),
            transmit_timestamp,
            "{name}"
        );
        assert!(ntp.extension_fields_value().is_empty(), "{name}");
        assert!(ntp.legacy_mac_value().is_none(), "{name}");
        assert!(decoded.layer::<Raw>().is_none(), "{name}");

        let summary = decoded.summary();
        assert!(summary.contains(&format!("version={version}")), "{name}");
        assert!(summary.contains(&format!("mode={mode}")), "{name}");
        assert!(!summary.contains("request"), "{name}");
        assert!(!summary.contains("response"), "{name}");

        let show = decoded.show();
        assert!(show.contains(&format!("version: {version}")), "{name}");
        assert!(show.contains(&format!("mode: {mode}")), "{name}");
        assert!(!show.contains("request"), "{name}");
        assert!(!show.contains("response"), "{name}");
    }

    Ok(())
}
