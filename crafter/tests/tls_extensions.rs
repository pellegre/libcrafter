//! TLS extension golden vectors.
//!
//! These tests pin exact extension encodings through the public typed extension
//! APIs. They use synthetic values only and do not depend on live traffic.

use crafter::prelude::*;

fn hex(input: &str) -> Vec<u8> {
    let hex = input
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(str::chars)
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<String>();
    assert_eq!(hex.len() % 2, 0, "hex fixture must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid hex fixture"))
        .collect()
}

fn assert_extension(
    name: &str,
    extension: TlsRawExtension,
    expected_hex: &str,
) -> crafter::Result<TlsRawExtension> {
    let expected = hex(expected_hex);
    assert_eq!(extension.encode_to_vec()?, expected, "{name} encode");

    let decoded = TlsRawExtension::decode(&expected)?;
    assert_eq!(decoded, extension, "{name} decode");
    assert_eq!(decoded.encode_to_vec()?, expected, "{name} recompile");
    assert!(!decoded.summary().is_empty(), "{name} summary");
    Ok(decoded)
}

#[test]
fn tls_extension_core_golden_vectors_roundtrip() -> crafter::Result<()> {
    let sni = assert_extension(
        "sni",
        TlsRawExtension::server_name(TlsServerNameList::from_host_name("example.com"))?,
        "00 00 00 10 00 0e 00 00 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d",
    )?;
    assert_eq!(sni.as_server_name_list()?.host_names(), vec!["example.com"]);

    let alpn = assert_extension(
        "alpn",
        TlsRawExtension::alpn(TlsAlpnProtocols::h2_then_http_1_1())?,
        "00 10 00 0e 00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31",
    )?;
    assert_eq!(
        alpn.as_alpn_protocols()?.protocol_bytes(),
        vec![b"h2".as_slice(), b"http/1.1".as_slice()]
    );

    let supported_versions_client = assert_extension(
        "supported_versions_client",
        TlsRawExtension::supported_versions_client(vec![
            TlsVersion::tls_1_3(),
            TlsVersion::tls_1_2(),
        ])?,
        "00 2b 00 05 04 03 04 03 03",
    )?;
    assert_eq!(
        supported_versions_client
            .as_supported_versions_client()?
            .versions()
            .expect("client supported_versions"),
        &[TlsVersion::tls_1_3(), TlsVersion::tls_1_2()]
    );

    let supported_versions_server = assert_extension(
        "supported_versions_server",
        TlsRawExtension::supported_versions_server(TlsVersion::tls_1_3())?,
        "00 2b 00 02 03 04",
    )?;
    assert_eq!(
        supported_versions_server
            .as_supported_versions_server()?
            .selected_version(),
        Some(TlsVersion::tls_1_3())
    );

    let supported_groups = assert_extension(
        "supported_groups",
        TlsRawExtension::supported_groups(TlsSupportedGroups::from_raws([
            TLS_NAMED_GROUP_X25519,
            TLS_NAMED_GROUP_SECP256R1,
        ]))?,
        "00 0a 00 06 00 04 00 1d 00 17",
    )?;
    assert_eq!(
        supported_groups.as_supported_groups()?.raw_values(),
        vec![TLS_NAMED_GROUP_X25519, TLS_NAMED_GROUP_SECP256R1]
    );

    let signature_algorithms = assert_extension(
        "signature_algorithms",
        TlsRawExtension::signature_algorithms(TlsSignatureAlgorithms::from_raws([
            TLS_SIGNATURE_SCHEME_ED25519,
            TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
            TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
        ]))?,
        "00 0d 00 08 00 06 08 07 08 04 04 03",
    )?;
    assert_eq!(
        signature_algorithms.as_signature_algorithms()?.raw_values(),
        vec![
            TLS_SIGNATURE_SCHEME_ED25519,
            TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
            TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
        ]
    );

    let key_share_client = assert_extension(
        "key_share_client",
        TlsRawExtension::key_share_client(vec![TlsKeyShareEntry::x25519([0xaa, 0xbb, 0xcc])])?,
        "00 33 00 09 00 07 00 1d 00 03 aa bb cc",
    )?;
    assert_eq!(
        key_share_client
            .as_key_share_client()?
            .key_exchange_lengths(),
        vec![3]
    );

    let key_share_server = assert_extension(
        "key_share_server",
        TlsRawExtension::key_share_server((TlsNamedGroup::X25519, vec![0xbb, 0xcc]))?,
        "00 33 00 06 00 1d 00 02 bb cc",
    )?;
    assert_eq!(
        key_share_server.as_key_share_server()?.raw_groups(),
        vec![TLS_NAMED_GROUP_X25519]
    );

    let key_share_hrr = assert_extension(
        "key_share_hello_retry_request",
        TlsRawExtension::key_share_hello_retry_request(TlsNamedGroup::SECP256R1)?,
        "00 33 00 02 00 17",
    )?;
    assert_eq!(
        key_share_hrr
            .as_key_share_hello_retry_request()?
            .selected_group(),
        Some(TlsNamedGroup::SECP256R1)
    );

    let psk_modes = assert_extension(
        "psk_key_exchange_modes",
        TlsRawExtension::psk_key_exchange_modes(TlsPskKeyExchangeModes::psk_ke_then_psk_dhe_ke())?,
        "00 2d 00 03 02 00 01",
    )?;
    assert_eq!(
        psk_modes.as_psk_key_exchange_modes()?.raw_values(),
        vec![
            TLS_PSK_KEY_EXCHANGE_MODE_PSK_KE,
            TLS_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE
        ]
    );

    Ok(())
}

#[test]
fn tls_extension_stateful_golden_vectors_roundtrip() -> crafter::Result<()> {
    let pre_shared_key_client = assert_extension(
        "pre_shared_key_client",
        TlsRawExtension::pre_shared_key_client(
            [TlsPskIdentity::new([0xde, 0xad, 0xbe, 0xef], 0x0102_0304)],
            [TlsPskBinderEntry::new([0x11; 32])],
        )?,
        "
        00 29 00 2f
        00 0a 00 04 de ad be ef 01 02 03 04
        00 21 20
        11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
        11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
        ",
    )?;
    let psk = pre_shared_key_client.as_pre_shared_key_client()?;
    assert_eq!(
        psk.identities().expect("psk identities").identity_lengths(),
        vec![4]
    );
    assert_eq!(
        psk.binders().expect("psk binders").binder_lengths(),
        vec![32]
    );

    let pre_shared_key_server = assert_extension(
        "pre_shared_key_server",
        TlsRawExtension::pre_shared_key_server(2)?,
        "00 29 00 02 00 02",
    )?;
    assert_eq!(
        pre_shared_key_server
            .as_pre_shared_key_server()?
            .selected_identity(),
        Some(2)
    );

    let cookie = assert_extension(
        "cookie",
        TlsRawExtension::cookie(TlsCookie::new([0x00, 0xff, 0x7a]))?,
        "00 2c 00 05 00 03 00 ff 7a",
    )?;
    assert_eq!(cookie.as_cookie()?.bytes(), &[0x00, 0xff, 0x7a]);

    let padding = assert_extension(
        "padding",
        TlsRawExtension::padding_bytes([0xaa, 0x00, 0xbb])?,
        "00 15 00 03 aa 00 bb",
    )?;
    assert_eq!(padding.as_padding()?.bytes(), &[0xaa, 0x00, 0xbb]);

    let record_size_limit = assert_extension(
        "record_size_limit",
        TlsRawExtension::record_size_limit(512)?,
        "00 1c 00 02 02 00",
    )?;
    assert_eq!(record_size_limit.as_record_size_limit()?.limit(), 512);

    let status_request = assert_extension(
        "status_request",
        TlsRawExtension::status_request(TlsStatusRequest::ocsp(TlsOcspStatusRequest::new(
            TlsOcspResponderIds::new([TlsOcspResponderId::new([0xaa, 0xbb])]),
            [0x30, 0x00],
        )))?,
        "00 05 00 0b 01 00 04 00 02 aa bb 00 02 30 00",
    )?;
    assert_eq!(
        status_request
            .as_status_request()?
            .ocsp_request()
            .expect("ocsp status_request")
            .request_extensions(),
        &[0x30, 0x00]
    );

    let certificate_authorities = assert_extension(
        "certificate_authorities",
        TlsRawExtension::certificate_authorities(TlsCertificateAuthorities::from_raws([
            &[0x30, 0x03, 0x31][..],
            &[0xaa, 0xbb][..],
        ]))?,
        "00 2f 00 0b 00 09 00 03 30 03 31 00 02 aa bb",
    )?;
    assert_eq!(
        certificate_authorities
            .as_certificate_authorities()?
            .distinguished_names()
            .iter()
            .map(TlsDistinguishedName::len)
            .collect::<Vec<_>>(),
        vec![3, 2]
    );

    Ok(())
}

#[test]
fn tls_extension_unknown_and_duplicate_golden_vectors_roundtrip() -> crafter::Result<()> {
    let unknown = assert_extension(
        "unknown",
        TlsRawExtension::from_raw(0xbeef, [0xde, 0xad, 0xfa, 0xce]),
        "be ef 00 04 de ad fa ce",
    )?;
    assert_eq!(unknown.raw_type(), 0xbeef);
    assert_eq!(unknown.body(), &[0xde, 0xad, 0xfa, 0xce]);

    let extensions = TlsExtensions::new(vec![
        TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]),
        TlsRawExtension::from_raw(TLS_EXTENSION_SUPPORTED_VERSIONS, [0x03, 0x04]),
        TlsRawExtension::from_raw(0xbeef, [0xfa, 0xce, 0x00]),
    ]);
    let expected = hex("
        00 13
        be ef 00 02 de ad
        00 2b 00 02 03 04
        be ef 00 03 fa ce 00
        ");
    assert_eq!(extensions.encode_to_vec()?, expected);

    let decoded = TlsExtensions::decode(&expected)?;
    assert_eq!(
        decoded.raw_types(),
        vec![0xbeef, TLS_EXTENSION_SUPPORTED_VERSIONS, 0xbeef]
    );
    assert_eq!(decoded.all_by_raw_type(0xbeef).len(), 2);
    assert_eq!(
        decoded
            .all_by_type(TlsExtensionType::supported_versions())
            .into_iter()
            .map(TlsRawExtension::body)
            .collect::<Vec<_>>(),
        vec![&[0x03, 0x04][..]]
    );
    assert_eq!(decoded.encode_to_vec()?, expected);
    assert!(decoded.summary().contains("unknown extension 0xbeef"));
    Ok(())
}
