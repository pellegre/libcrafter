use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

#[test]
fn ntp_header_golden_bytes_compile_decode_and_roundtrip() -> crafter::Result<()> {
    let ntp = Ntp::client()
        .poll(6)
        .precision(-20)
        .root_delay_raw(0x0001_0000)
        .root_dispersion_raw(0x0002_0000)
        .reference_id(*b"LOCL")
        .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678));

    let compiled = Packet::from_layer(ntp).compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN);
    assert_eq!(bytes[0], 0x23);
    assert_eq!(bytes[1], 0);
    assert_eq!(bytes[2], 6);
    assert_eq!(bytes[3], 0xec);
    assert_eq!(&bytes[4..8], &0x0001_0000u32.to_be_bytes());
    assert_eq!(&bytes[8..12], &0x0002_0000u32.to_be_bytes());
    assert_eq!(&bytes[12..16], b"LOCL");
    assert_eq!(&bytes[40..48], &0xecc0_0000_1234_5678u64.to_be_bytes());

    let decoded = Ntp::decode(bytes)?;
    assert_eq!(decoded.first_octet_value(), 0x23);
    assert_eq!(decoded.poll_value(), 6);
    assert_eq!(decoded.precision_value(), -20);
    assert_eq!(decoded.reference_id_value().bytes(), *b"LOCL");
    assert_eq!(
        decoded.transmit_timestamp_value().raw(),
        0xecc0_0000_1234_5678
    );
    assert_eq!(Packet::from_layer(decoded).compile()?.as_bytes(), bytes);
    Ok(())
}

#[test]
fn ntp_extension_fields_and_legacy_mac_roundtrip() -> crafter::Result<()> {
    let ntp = Ntp::client()
        .extension_field(NtpExtensionField::nts_cookie([1, 2, 3]))
        .legacy_mac(NtpLegacyMac::from_key_id_and_digest(
            0x0102_0304,
            [0xaa; 16],
        ));

    let compiled = Packet::from_layer(ntp).compile()?;
    let bytes = compiled.as_bytes();
    assert!(looks_like_ntp_payload(bytes));

    let decoded = Ntp::decode(bytes)?;
    assert_eq!(decoded.extension_fields_value().len(), 1);
    assert_eq!(decoded.extension_fields_value()[0].field_type(), 0x0204);
    assert_eq!(
        decoded.extension_fields_value()[0].declared_length_value(),
        Some(16)
    );
    assert_eq!(
        decoded.legacy_mac_value().and_then(NtpLegacyMac::key_id),
        Some(0x0102_0304)
    );
    assert_eq!(Packet::from_layer(decoded).compile()?.as_bytes(), bytes);
    Ok(())
}

#[test]
fn ntp_malformed_extension_length_is_structured_error() {
    let mut bytes = Packet::from_layer(Ntp::client())
        .compile()
        .unwrap()
        .into_bytes();
    bytes.extend_from_slice(&0x0204u16.to_be_bytes());
    bytes.extend_from_slice(&12u16.to_be_bytes());
    bytes.extend_from_slice(&[0; 8]);

    let err = Ntp::decode(&bytes).unwrap_err();
    assert_eq!(
        err,
        CrafterError::invalid_field_value(
            "ntp.extension.length",
            "extension length must be at least 16 bytes",
        )
    );
}

#[test]
fn ntp_final_extension_without_mac_uses_28_byte_rule() -> crafter::Result<()> {
    let mut payload = Packet::from_layer(Ntp::client()).compile()?.into_bytes();
    payload.extend_from_slice(&0x0204u16.to_be_bytes());
    payload.extend_from_slice(&16u16.to_be_bytes());
    payload.extend_from_slice(&[0; 12]);

    let err = Ntp::decode(&payload).unwrap_err();
    assert_eq!(
        err,
        CrafterError::invalid_field_value(
            "ntp.extension.length",
            "final extension without MAC must be at least 28 bytes",
        )
    );
    assert!(!looks_like_ntp_payload(&payload));

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().source_port(NTP_PORT).destination_port(NTP_PORT)
        / Raw::from_bytes(payload.clone());

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile()?.as_bytes())?;
    assert!(decoded.layer::<Ntp>().is_none());
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        payload.as_slice()
    );
    Ok(())
}

#[test]
fn ntp_udp_ipv4_and_ipv6_decode_through_registry() -> crafter::Result<()> {
    let ipv4 = ntp_ipv4_client_request(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
    );
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4.compile()?.as_bytes())?;
    assert!(decoded.layer::<Udp>().is_some());
    assert!(decoded.layer::<Ntp>().is_some());
    assert!(decoded.summary().contains("Ntp("));

    let ipv6 = ntp_ipv6_client_request(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
    );
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6.compile()?.as_bytes())?;
    assert!(decoded.layer::<Udp>().is_some());
    assert!(decoded.layer::<Ntp>().is_some());
    Ok(())
}

#[test]
fn ntp_udp_123_non_ntp_payload_stays_raw() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().source_port(NTP_PORT).destination_port(NTP_PORT)
        / Raw::from_bytes([1, 2, 3, 4]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile()?.as_bytes())?;
    assert!(decoded.layer::<Ntp>().is_none());
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[1, 2, 3, 4]);
    Ok(())
}

#[test]
fn ntp_public_api_is_available_from_prelude() {
    let packet = Ntp::client().transmit_timestamp(NtpTimestamp::from_raw(1));
    assert_eq!(packet.mode_value(), NtpMode::Client);
    assert_eq!(NTP_PORT, 123);
}
