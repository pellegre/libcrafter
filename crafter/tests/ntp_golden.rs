use crafter::prelude::*;

#[test]
fn ntp_header_golden_client_request_fixed_header() -> crafter::Result<()> {
    let ntp = Ntp::client()
        .poll(6)
        .precision(-20)
        .transmit_timestamp(0x0102_0304_0506_0708u64);

    let expected = vec![
        0x23, 0x00, 0x06, 0xec, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08,
    ];

    let compiled = Packet::from_layer(ntp).compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN);
    assert_eq!(bytes, expected.as_slice());

    let decoded = Ntp::decode(bytes)?;
    assert_eq!(decoded.first_octet_value(), 0x23);
    assert_eq!(decoded.leap_indicator_value(), NtpLeapIndicator::NoWarning);
    assert_eq!(decoded.version_value_effective(), NtpVersion::current());
    assert_eq!(decoded.mode_value(), NtpMode::Client);
    assert_eq!(decoded.stratum_value().value(), NTP_STRATUM_UNSPECIFIED);
    assert_eq!(decoded.poll_value(), 6);
    assert_eq!(decoded.precision_value(), -20);
    assert_eq!(decoded.root_delay_value().raw(), 0);
    assert_eq!(decoded.root_dispersion_value().raw(), 0);
    assert_eq!(
        decoded.reference_id_value().bytes(),
        [0; NTP_REFERENCE_ID_LEN]
    );
    assert_eq!(decoded.reference_timestamp_value().raw(), 0);
    assert_eq!(decoded.origin_timestamp_value().raw(), 0);
    assert_eq!(decoded.receive_timestamp_value().raw(), 0);
    assert_eq!(
        decoded.transmit_timestamp_value().raw(),
        0x0102_0304_0506_0708
    );
    assert!(decoded.extension_fields_value().is_empty());
    assert!(decoded.legacy_mac_value().is_none());

    Ok(())
}

#[test]
fn ntp_header_golden_server_response_fixed_header() -> crafter::Result<()> {
    let ntp = Ntp::server_response()
        .poll(6)
        .precision(-20)
        .root_delay_raw(0x0001_8000)
        .root_dispersion_raw(0x0000_c000)
        .reference_id(*b"GPS\0")
        .reference_timestamp(0x0102_0304_0506_0708u64)
        .origin_timestamp(0x1112_1314_1516_1718u64)
        .receive_timestamp(0x2122_2324_2526_2728u64)
        .transmit_timestamp(0x3132_3334_3536_3738u64);

    let expected = vec![
        0x24, 0x01, 0x06, 0xec, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0xc0, 0x00, b'G', b'P', b'S',
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38,
    ];

    let compiled = Packet::from_layer(ntp).compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN);
    assert_eq!(bytes, expected.as_slice());

    let decoded = Ntp::decode(bytes)?;
    assert_eq!(decoded.first_octet_value(), 0x24);
    assert_eq!(decoded.leap_indicator_value(), NtpLeapIndicator::NoWarning);
    assert_eq!(decoded.version_value_effective(), NtpVersion::current());
    assert_eq!(decoded.mode_value(), NtpMode::Server);
    assert_eq!(decoded.stratum_value().value(), NTP_STRATUM_PRIMARY);
    assert_eq!(decoded.poll_value(), 6);
    assert_eq!(decoded.precision_value(), -20);
    assert_eq!(decoded.root_delay_value().raw(), 0x0001_8000);
    assert_eq!(decoded.root_dispersion_value().raw(), 0x0000_c000);
    assert_eq!(decoded.reference_id_value().bytes(), *b"GPS\0");
    assert_eq!(
        decoded.reference_timestamp_value().raw(),
        0x0102_0304_0506_0708
    );
    assert_eq!(
        decoded.origin_timestamp_value().raw(),
        0x1112_1314_1516_1718
    );
    assert_eq!(
        decoded.receive_timestamp_value().raw(),
        0x2122_2324_2526_2728
    );
    assert_eq!(
        decoded.transmit_timestamp_value().raw(),
        0x3132_3334_3536_3738
    );
    assert!(decoded.extension_fields_value().is_empty());
    assert!(decoded.legacy_mac_value().is_none());

    Ok(())
}

#[test]
fn ntp_decode_golden_ntpv4_server_fixed_header_payload() -> crafter::Result<()> {
    let payload = [
        0x24, 0x02, 0x04, 0xe8, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 192, 0, 2, 123,
        0xe4, 0xe1, 0xcd, 0xdc, 0x12, 0x34, 0x56, 0x78, 0xe4, 0xe1, 0xce, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xe4, 0xe1, 0xce, 0x00, 0x80, 0x00, 0x00, 0x00, 0xe4, 0xe1, 0xce, 0x01, 0x00, 0x00,
        0x00, 0x00,
    ];

    let decoded = Ntp::decode(&payload)?;

    assert_eq!(payload.len(), NTP_FIXED_HEADER_LEN);
    assert_eq!(decoded.first_octet_value(), 0x24);
    assert_eq!(decoded.leap_indicator_value(), NtpLeapIndicator::NoWarning);
    assert_eq!(decoded.version_value_effective(), NtpVersion::current());
    assert_eq!(decoded.mode_value(), NtpMode::Server);
    assert_eq!(decoded.stratum_value().value(), 2);
    assert_eq!(decoded.poll_value(), 4);
    assert_eq!(decoded.precision_value(), -24);
    assert_eq!(decoded.root_delay_value().raw(), 0x0000_03e8);
    assert_eq!(decoded.root_dispersion_value().raw(), 0x0000_07d0);
    assert_eq!(decoded.reference_id_value().bytes(), [192, 0, 2, 123]);
    assert_eq!(
        decoded.reference_timestamp_value().raw(),
        0xe4e1_cddc_1234_5678
    );
    assert_eq!(
        decoded.origin_timestamp_value().raw(),
        0xe4e1_ce00_0000_0000
    );
    assert_eq!(
        decoded.receive_timestamp_value().raw(),
        0xe4e1_ce00_8000_0000
    );
    assert_eq!(
        decoded.transmit_timestamp_value().raw(),
        0xe4e1_ce01_0000_0000
    );
    assert!(decoded.extension_fields_value().is_empty());
    assert!(decoded.legacy_mac_value().is_none());

    let recompiled = Packet::from_layer(decoded).compile()?;
    assert_eq!(recompiled.as_bytes(), payload);

    Ok(())
}

#[test]
fn ntp_decode_golden_ntpv3_compatible_server_fixed_header_payload() -> crafter::Result<()> {
    let payload = [
        0x1c, 0x01, 0x06, 0xec, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0xc0, 0x00, b'L', b'O', b'C',
        b'L', 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6,
        0xa7, 0xa8, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
        0xc6, 0xc7, 0xc8,
    ];

    let decoded = Ntp::decode(&payload)?;

    assert_eq!(payload.len(), NTP_FIXED_HEADER_LEN);
    assert_eq!(decoded.first_octet_value(), 0x1c);
    assert_eq!(decoded.leap_indicator_value(), NtpLeapIndicator::NoWarning);
    assert_eq!(decoded.version_value_effective(), NtpVersion::from_wire(3));
    assert_eq!(decoded.mode_value(), NtpMode::Server);
    assert_eq!(decoded.stratum_value().value(), NTP_STRATUM_PRIMARY);
    assert_eq!(decoded.poll_value(), 6);
    assert_eq!(decoded.precision_value(), -20);
    assert_eq!(decoded.root_delay_value().raw(), 0x0001_8000);
    assert_eq!(decoded.root_dispersion_value().raw(), 0x0000_c000);
    assert_eq!(decoded.reference_id_value().bytes(), *b"LOCL");
    assert_eq!(
        decoded.reference_timestamp_value().raw(),
        0xd1d2_d3d4_d5d6_d7d8
    );
    assert_eq!(
        decoded.origin_timestamp_value().raw(),
        0xa1a2_a3a4_a5a6_a7a8
    );
    assert_eq!(
        decoded.receive_timestamp_value().raw(),
        0xb1b2_b3b4_b5b6_b7b8
    );
    assert_eq!(
        decoded.transmit_timestamp_value().raw(),
        0xc1c2_c3c4_c5c6_c7c8
    );
    assert!(decoded.extension_fields_value().is_empty());
    assert!(decoded.legacy_mac_value().is_none());

    let recompiled = Packet::from_layer(decoded).compile()?;
    assert_eq!(recompiled.as_bytes(), payload);

    Ok(())
}
