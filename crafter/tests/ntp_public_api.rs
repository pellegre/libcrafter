use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

#[test]
fn ntp_public_api_prelude_builds_decodes_and_exposes_helpers() -> crafter::Result<()> {
    let unique = NtpNtsUniqueIdentifierExtension::new([0x01, 0x02, 0x03, 0x04]);
    let checksum = NtpChecksumComplementExtension::from_complement(0xbeef);
    let authenticator =
        NtpNtsAuthenticatorExtension::from_parts([0xaa, 0xbb], [0xcc, 0xdd], [0xee, 0xff], [0])?;
    let mac = NtpMac::from_key_id_and_digest(0x0102_0304, [0x55; 16]);

    assert_eq!(
        unique.field_type(),
        NtpNtsUniqueIdentifierExtension::FIELD_TYPE
    );
    assert_eq!(checksum.complement_value(), Some(0xbeef));
    assert_eq!(mac.length_class(), NtpMacLengthClass::Legacy20Octet);

    let parts: NtpNtsAuthenticatorParts<'_> = authenticator.parts().unwrap();
    assert_eq!(parts.nonce(), &[0xaa, 0xbb]);
    assert_eq!(parts.tag(2), Some(&[0xee, 0xff][..]));

    let ntp = Ntp::client()
        .extension_field(unique.into_extension_field())
        .extension_field(NtpExtensionField::from(checksum))
        .extension_field(NtpExtensionField::from(authenticator))
        .legacy_mac(NtpLegacyMac::from_key_id_and_digest(
            mac.key_id(),
            mac.digest(),
        ));
    let bytes = Packet::from_layer(ntp).compile()?;

    assert!(looks_like_ntp_payload(bytes.as_bytes()));
    assert_eq!(decode_ntp(bytes.as_bytes())?.mode_value(), NtpMode::Client);
    assert_eq!(
        decode_ntp_payload(bytes.as_bytes())?.mode_value(),
        NtpMode::Client
    );
    assert_eq!(NTP_PORT, 123);
    assert_eq!(NTP_FIXED_HEADER_LEN, 48);
    Ok(())
}

#[test]
fn ntp_public_api_root_core_and_protocol_paths_resolve() -> crafter::Result<()> {
    let root: crafter::Ntp = crafter::Ntp::server().stratum(1);
    let core: crafter::core::Ntp = crafter::core::Ntp::client();
    let nested: crafter::protocols::ntp::Ntp = crafter::protocols::ntp::Ntp::broadcast();

    assert_eq!(root.mode_value(), crafter::NtpMode::Server);
    assert_eq!(core.mode_value(), crafter::core::NtpMode::Client);
    assert_eq!(
        nested.mode_value(),
        crafter::protocols::ntp::NtpMode::Broadcast
    );
    assert_eq!(
        crafter::core::ntp_extension_type(NtpNtsCookieExtension::FIELD_TYPE).category(),
        crafter::core::NtpExtensionFieldTypeCategory::Assigned
    );

    let ipv4 = ntp_ipv4_client_request(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 123),
    );
    let ipv6 = ntp_ipv6_client_request(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x123),
    );

    assert!(ipv4.compile()?.as_bytes().len() > NTP_FIXED_HEADER_LEN);
    assert!(ipv6.compile()?.as_bytes().len() > NTP_FIXED_HEADER_LEN);
    assert!(ntp_ipv4_documentation_client_request()
        .summary()
        .contains("Ntp("));
    assert!(ntp_ipv6_documentation_client_request()
        .summary()
        .contains("Ntp("));
    Ok(())
}

#[test]
fn ntp_constants_and_registry() {
    assert_eq!(NTP_SERVICE_NAME, "ntp");
    assert_eq!(NTP_PORT, 123);
    assert_eq!(NTP_UDP_PORT, NTP_PORT);
    assert_eq!(NTP_TCP_PORT, 123);
    assert_eq!(NTP_FIXED_HEADER_LEN, 48);
    assert_eq!(NTP_TIMESTAMP_LEN, 8);
    assert_eq!(NTP_REFERENCE_ID_LEN, 4);
    assert_eq!(NTP_DEFAULT_FIRST_OCTET, 0x23);

    let leap = ntp_leap_indicator_meta(NTP_LI_ALARM_UNSYNCHRONIZED);
    assert_eq!(leap.label, "alarm-unsynchronized");
    assert_eq!(leap.status, NtpRegistryStatus::Assigned);
    assert_eq!(
        ntp_leap_indicator_meta(4).status,
        NtpRegistryStatus::Unknown
    );

    let mode = ntp_mode_meta(NTP_MODE_CLIENT);
    assert_eq!(mode.label, "client");
    assert_eq!(mode.status, NtpRegistryStatus::Assigned);
    assert_eq!(
        ntp_mode_meta(NTP_MODE_PRIVATE).status,
        NtpRegistryStatus::PrivateOrExperimental
    );
    assert_eq!(ntp_mode_meta(9).status, NtpRegistryStatus::Unknown);

    assert_eq!(
        ntp_stratum_meta(NTP_STRATUM_UNSPECIFIED).label,
        "unspecified-or-invalid"
    );
    assert_eq!(ntp_stratum_meta(NTP_STRATUM_PRIMARY).label, "primary");
    assert_eq!(ntp_stratum_meta(12).label, "secondary");
    assert_eq!(
        ntp_stratum_meta(NTP_STRATUM_UNSYNCHRONIZED).label,
        "unsynchronized"
    );
    assert_eq!(ntp_stratum_meta(42).status, NtpRegistryStatus::Reserved);

    let gps = ntp_reference_id_meta(*b"GPS\0");
    assert_eq!(gps.label, "Global Position System");
    assert_eq!(gps.status, NtpRegistryStatus::Assigned);
    assert_eq!(gps.ascii_label().as_deref(), Some("GPS"));

    let private_refid = ntp_reference_id_meta(*b"XLAB");
    assert_eq!(
        private_refid.label,
        "refid-0x584C4142 (private-or-experimental)"
    );
    assert_eq!(
        private_refid.status,
        NtpRegistryStatus::PrivateOrExperimental
    );

    let rate = ntp_kiss_o_death_code_meta(*b"RATE");
    assert_eq!(rate.label, "Rate exceeded");
    assert_eq!(rate.status, NtpRegistryStatus::Assigned);
    assert_eq!(
        ntp_kiss_o_death_code_meta(*b"NOPE").status,
        NtpRegistryStatus::Unassigned
    );

    let nts_cookie = ntp_extension_type(NtpNtsCookieExtension::FIELD_TYPE);
    assert_eq!(nts_cookie.label(), "Autokey Message Request / NTS Cookie");
    assert_eq!(
        nts_cookie.category(),
        NtpExtensionFieldTypeCategory::Assigned
    );
    assert_eq!(nts_cookie.status(), NtpRegistryStatus::Assigned);
    assert_eq!(
        ntp_extension_field_type_meta(NtpChecksumComplementExtension::FIELD_TYPE).label,
        "UDP Checksum Complement"
    );
    assert_eq!(
        ntp_nts_extension_field_type_meta(NtpNtsAuthenticatorExtension::FIELD_TYPE).label,
        "NTS Authenticator and Encrypted Extension Fields"
    );

    let unknown = ntp_extension_type(0x2222);
    assert_eq!(unknown.label(), "extension-field-0x2222");
    assert_eq!(
        unknown.category(),
        NtpExtensionFieldTypeCategory::UnknownOrUnassigned
    );
    assert_eq!(unknown.status(), NtpRegistryStatus::Unassigned);
}

#[test]
fn ntp_kiss_refid_labels_raw_bytes_summary_and_show() -> crafter::Result<()> {
    let cases = [
        (
            "assigned-kod",
            Ntp::kiss_o_death(*b"RATE"),
            *b"RATE",
            NTP_STRATUM_UNSPECIFIED,
            "RATE",
            "Rate exceeded",
            NtpRegistryStatus::Assigned,
        ),
        (
            "unknown-kod",
            Ntp::kiss_o_death(*b"NOPE"),
            *b"NOPE",
            NTP_STRATUM_UNSPECIFIED,
            "NOPE",
            "kod-0x4E4F5045",
            NtpRegistryStatus::Unassigned,
        ),
        (
            "assigned-primary-refid",
            Ntp::server().reference_id(NtpReferenceId::from_bytes(*b"GPS\0")),
            *b"GPS\0",
            NTP_STRATUM_PRIMARY,
            "GPS",
            "Global Position System",
            NtpRegistryStatus::Assigned,
        ),
        (
            "unknown-primary-refid",
            Ntp::server().reference_id(NtpReferenceId::from_bytes([0x80, 0, 0, 1])),
            [0x80, 0, 0, 1],
            NTP_STRATUM_PRIMARY,
            "",
            "refid-0x80000001",
            NtpRegistryStatus::Unassigned,
        ),
    ];

    for (name, ntp, bytes, stratum, ascii_label, refid_label, status) in cases {
        let reference_id = ntp.reference_id_value();
        assert_eq!(reference_id.bytes(), bytes, "{name}");
        assert_eq!(
            reference_id.label_for_stratum(ntp.stratum_value()),
            refid_label,
            "{name}"
        );
        if ascii_label.is_empty() {
            assert!(reference_id.ascii_label().is_none(), "{name}");
        } else {
            assert_eq!(
                reference_id.ascii_label().as_deref(),
                Some(ascii_label),
                "{name}"
            );
        }

        let meta = if stratum == NTP_STRATUM_UNSPECIFIED {
            ntp_kiss_o_death_code_meta(bytes)
        } else {
            ntp_reference_id_meta(bytes)
        };
        assert_eq!(meta.bytes, bytes, "{name}");
        assert_eq!(meta.label, refid_label, "{name}");
        assert_eq!(meta.status, status, "{name}");

        let compiled = Packet::from_layer(ntp).compile()?;
        assert_eq!(&compiled.as_bytes()[12..16], &bytes, "{name}");

        let decoded = Ntp::decode(compiled.as_bytes())?;
        assert_eq!(decoded.reference_id_value().bytes(), bytes, "{name}");
        assert_eq!(decoded.stratum_value().value(), stratum, "{name}");
        assert_eq!(
            decoded
                .reference_id_value()
                .label_for_stratum(decoded.stratum_value()),
            refid_label,
            "{name}"
        );

        let summary = decoded.summary();
        assert!(summary.contains(&format!("refid={refid_label}")), "{name}");
        assert!(summary.contains(&format!("stratum={}(", stratum)), "{name}");

        let show = Packet::from_layer(decoded).show();
        assert!(
            show.contains(&format!("reference_id: {refid_label}")),
            "{name}"
        );
        assert!(show.contains(&format!("stratum: {}", stratum)), "{name}");
    }

    Ok(())
}

#[test]
fn ntp_bitfield_packing() -> crafter::Result<()> {
    let cases = [
        (
            NtpLeapIndicator::NoWarning,
            NtpVersion::current(),
            NtpMode::Client,
            0x23,
        ),
        (
            NtpLeapIndicator::AlarmUnsynchronized,
            NtpVersion::from_wire(3),
            NtpMode::Server,
            0xdc,
        ),
        (
            NtpLeapIndicator::LastMinute61Seconds,
            NtpVersion::from_wire(1),
            NtpMode::SymmetricActive,
            0x49,
        ),
        (
            NtpLeapIndicator::LastMinute59Seconds,
            NtpVersion::from_wire(7),
            NtpMode::PrivateUse,
            0xbf,
        ),
    ];

    for (leap_indicator, version, mode, expected_first_octet) in cases {
        assert_eq!(
            ntp_pack_first_octet(leap_indicator, version, mode),
            expected_first_octet
        );

        let (parsed_leap_indicator, parsed_version, parsed_mode) =
            ntp_parse_first_octet(expected_first_octet);
        assert_eq!(parsed_leap_indicator, leap_indicator);
        assert_eq!(parsed_version, version);
        assert_eq!(parsed_mode, mode);

        let ntp = Ntp::new()
            .leap_indicator(leap_indicator)
            .version(version)
            .mode(mode);
        let bytes = Packet::from_layer(ntp).compile()?;
        assert_eq!(bytes.as_bytes()[0], expected_first_octet);

        let decoded = Ntp::decode(bytes.as_bytes())?;
        assert_eq!(decoded.first_octet_value(), expected_first_octet);
        assert_eq!(decoded.leap_indicator_value(), leap_indicator);
        assert_eq!(decoded.version_value_effective(), version);
        assert_eq!(decoded.mode_value(), mode);
    }

    let masked = Ntp::new()
        .leap_indicator(NtpLeapIndicator::Unknown(0xaa))
        .version(NtpVersion::from_wire(0x0f))
        .mode(NtpMode::Unknown(0x2a));
    let masked_first_octet = Packet::from_layer(masked).compile()?.as_bytes()[0];
    let (masked_leap_indicator, masked_version, masked_mode) =
        ntp_parse_first_octet(masked_first_octet);

    assert_eq!(masked_first_octet, 0xba);
    assert_eq!(masked_leap_indicator, NtpLeapIndicator::LastMinute59Seconds);
    assert_eq!(masked_version, NtpVersion::from_wire(7));
    assert_eq!(masked_mode, NtpMode::SymmetricPassive);
    Ok(())
}

#[test]
fn ntp_overrides_survive_compile() -> crafter::Result<()> {
    const IPV4_HEADER_LEN: usize = 20;
    const UDP_HEADER_LEN: usize = 8;
    const UDP_OFFSET: usize = IPV4_HEADER_LEN;
    const NTP_OFFSET: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN;

    let first_octet = ntp_pack_first_octet(
        NtpLeapIndicator::AlarmUnsynchronized,
        NtpVersion::from_wire(7),
        NtpMode::PrivateUse,
    );
    let stratum = 0xfe;
    let poll = -17i8;
    let precision = -42i8;
    let root_delay = 0xdead_beefu32;
    let root_dispersion = 0x8000_0001u32;
    let reference_id = *b"ODD!";
    let reference_timestamp = 0x0102_0304_0506_0708u64;
    let origin_timestamp = 0x1112_1314_1516_1718u64;
    let receive_timestamp = 0x2122_2324_2526_2728u64;
    let transmit_timestamp = 0x3132_3334_3536_3738u64;
    let extension_declared_length = 28u16;
    let udp_length = 0x1234u16;
    let udp_checksum = 0xbeefu16;

    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new()
            .sport(49_152)
            .dport(NTP_PORT)
            .length(udp_length)
            .checksum(udp_checksum)
        / Ntp::new()
            .leap_indicator(NtpLeapIndicator::AlarmUnsynchronized)
            .version(NtpVersion::from_wire(7))
            .mode(NtpMode::PrivateUse)
            .stratum(stratum)
            .poll(poll)
            .precision(precision)
            .root_delay_raw(root_delay)
            .root_dispersion_raw(root_dispersion)
            .reference_id(reference_id)
            .reference_timestamp(reference_timestamp)
            .origin_timestamp(origin_timestamp)
            .receive_timestamp(receive_timestamp)
            .transmit_timestamp(transmit_timestamp)
            .extension_field(
                NtpExtensionField::unknown(0xbeef, [0xaa, 0xbb, 0xcc, 0xdd])
                    .declared_length(extension_declared_length),
            );
    let bytes = packet.compile()?.into_bytes();
    let ntp = &bytes[NTP_OFFSET..];

    assert_eq!(
        &bytes[UDP_OFFSET + 4..UDP_OFFSET + 6],
        &udp_length.to_be_bytes()
    );
    assert_eq!(
        &bytes[UDP_OFFSET + 6..UDP_OFFSET + 8],
        &udp_checksum.to_be_bytes()
    );
    assert_eq!(ntp[0], first_octet);
    assert_eq!(ntp[1], stratum);
    assert_eq!(ntp[2], poll as u8);
    assert_eq!(ntp[3], precision as u8);
    assert_eq!(&ntp[4..8], &root_delay.to_be_bytes());
    assert_eq!(&ntp[8..12], &root_dispersion.to_be_bytes());
    assert_eq!(&ntp[12..16], &reference_id);
    assert_eq!(&ntp[16..24], &reference_timestamp.to_be_bytes());
    assert_eq!(&ntp[24..32], &origin_timestamp.to_be_bytes());
    assert_eq!(&ntp[32..40], &receive_timestamp.to_be_bytes());
    assert_eq!(&ntp[40..48], &transmit_timestamp.to_be_bytes());
    assert_eq!(
        &ntp[NTP_FIXED_HEADER_LEN + 2..NTP_FIXED_HEADER_LEN + 4],
        &extension_declared_length.to_be_bytes()
    );
    Ok(())
}
