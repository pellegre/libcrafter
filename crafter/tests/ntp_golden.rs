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
