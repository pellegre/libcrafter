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
