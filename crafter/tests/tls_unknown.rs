//! TLS unknown-codepoint preservation fixtures.
//!
//! Unknown, unassigned, private-use, and future TLS registry values must stay
//! byte-exact after decode and remain visible through summaries and typed views.

use crafter::prelude::*;

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find {needle:?} in:\n{haystack}"
    );
}

#[test]
fn tls_unknown_record_handshake_and_alert_codepoints_roundtrip() -> crafter::Result<()> {
    let content_type = TlsContentType::from_u8(0xfa);
    assert_eq!(content_type.label(), "unassigned content type 0xfa");
    assert_contains(
        &content_type.summary(),
        "unassigned content type 0xfa raw=0xfa",
    );

    let record_bytes = [0xfa, 0x03, 0x03, 0x00, 0x02, 0xde, 0xad];
    let record = TlsRecord::decode(record_bytes)?;
    assert_eq!(record.raw_content_type(), 0xfa);
    assert_eq!(record.fragment(), &[0xde, 0xad]);
    assert_eq!(record.encode_to_vec()?, record_bytes);
    assert_contains(&record.summary(), "unassigned content type 0xfa");
    assert_contains(&record.summary(), "opaque bytes=2");

    let handshake_type = TlsHandshakeType::from_u8(0xfa);
    assert_eq!(handshake_type.label(), "unassigned handshake type 0xfa");
    assert_contains(
        &handshake_type.summary(),
        "unassigned handshake type 0xfa raw=0xfa",
    );

    let handshake_bytes = [0xfa, 0x00, 0x00, 0x03, 0xca, 0xfe, 0x00];
    let handshake = TlsHandshake::decode(handshake_bytes)?;
    assert_eq!(handshake.raw_handshake_type(), 0xfa);
    assert_eq!(handshake.body_bytes(), &[0xca, 0xfe, 0x00]);
    assert_eq!(handshake.encode_to_vec()?, handshake_bytes);
    assert_contains(&handshake.summary(), "unassigned handshake type 0xfa");
    assert_contains(&handshake.summary(), "opaque raw_body_bytes=3");

    let alert = TlsAlert::from_raw(0x02, 0xfe);
    assert_eq!(alert.encode_to_vec(), [0x02, 0xfe]);
    assert_eq!(TlsAlert::decode(alert.encode_to_vec())?, alert);
    assert_contains(&alert.summary(), "unassigned alert description 0xfe");

    let alert_record_bytes = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0xfe];
    let alert_record = TlsRecord::decode(alert_record_bytes)?;
    assert_eq!(alert_record.encode_to_vec()?, alert_record_bytes);
    assert_eq!(TlsAlert::decode(alert_record.fragment())?, alert);

    Ok(())
}

#[test]
fn tls_unknown_registry_lists_roundtrip_byte_exact() -> crafter::Result<()> {
    let cipher_suite = TlsCipherSuite::from_u16(0x1234);
    assert_eq!(cipher_suite.label(), "unknown cipher suite 0x1234");
    assert_eq!(cipher_suite.encode_to_vec(), [0x12, 0x34]);
    assert_eq!(TlsCipherSuite::decode([0x12, 0x34])?, cipher_suite);

    let cipher_suites = TlsCipherSuiteList::from_raws([0x1234, 0xbeef]);
    let cipher_suites_bytes = [0x00, 0x04, 0x12, 0x34, 0xbe, 0xef];
    let decoded = TlsCipherSuiteList::decode(cipher_suites_bytes)?;
    assert_eq!(decoded, cipher_suites);
    assert_eq!(decoded.encode_to_vec()?, cipher_suites_bytes);
    assert_contains(&decoded.summary(), "unknown cipher suite 0x1234");

    let named_group = TlsNamedGroup::from_u16(0xbeef);
    assert_eq!(named_group.label(), "unknown named group 0xbeef");
    let supported_groups = TlsSupportedGroups::from_raws([0xbeef]);
    let supported_groups_bytes = [0x00, 0x02, 0xbe, 0xef];
    let decoded = TlsSupportedGroups::decode(supported_groups_bytes)?;
    assert_eq!(decoded, supported_groups);
    assert_eq!(decoded.encode_to_vec()?, supported_groups_bytes);
    assert_eq!(decoded.raw_values(), vec![0xbeef]);
    assert_contains(&decoded.summary(), "unknown named group 0xbeef");

    let signature_scheme = TlsSignatureScheme::from_u16(0xbeef);
    assert_eq!(signature_scheme.label(), "unknown signature scheme 0xbeef");
    assert_eq!(signature_scheme.encode_to_vec(), [0xbe, 0xef]);
    assert_eq!(TlsSignatureScheme::decode([0xbe, 0xef])?, signature_scheme);

    let signature_algorithms = TlsSignatureAlgorithms::from_raws([0xbeef]);
    let signature_algorithms_bytes = [0x00, 0x02, 0xbe, 0xef];
    let decoded = TlsSignatureAlgorithms::decode(signature_algorithms_bytes)?;
    assert_eq!(decoded, signature_algorithms);
    assert_eq!(decoded.encode_to_vec()?, signature_algorithms_bytes);
    assert_contains(&decoded.summary(), "unknown signature scheme 0xbeef");

    let psk_mode = TlsPskKeyExchangeMode::from_u8(0x7a);
    assert_eq!(psk_mode.label(), "unassigned psk mode 0x7a");
    let psk_modes = TlsPskKeyExchangeModes::from_raws([0x7a]);
    let psk_modes_bytes = [0x01, 0x7a];
    let decoded = TlsPskKeyExchangeModes::decode(psk_modes_bytes)?;
    assert_eq!(decoded, psk_modes);
    assert_eq!(decoded.encode_to_vec()?, psk_modes_bytes);
    assert_contains(&decoded.summary(), "unassigned psk mode 0x7a");

    let unknown_extension = TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]);
    let unknown_extension_bytes = [0xbe, 0xef, 0x00, 0x02, 0xde, 0xad];
    let decoded = TlsRawExtension::decode(unknown_extension_bytes)?;
    assert_eq!(decoded, unknown_extension);
    assert_eq!(decoded.encode_to_vec()?, unknown_extension_bytes);
    assert_contains(&decoded.summary(), "unknown extension 0xbeef");

    assert_eq!(
        tls_cert_compression_algorithm_label(0x0004),
        "unassigned certificate compression algorithm 0x0004"
    );
    assert_eq!(
        tls_cert_compression_algorithm_status(0x0004),
        TlsCodepointStatus::Unassigned
    );

    Ok(())
}

#[test]
fn tls_client_hello_preserves_unknown_nested_codepoints() -> crafter::Result<()> {
    let supported_groups = TlsSupportedGroups::from_raws([0xbeef]);
    let signature_algorithms = TlsSignatureAlgorithms::from_raws([0xbeef]);
    let psk_modes = TlsPskKeyExchangeModes::from_raws([0x7a]);

    let client_hello = TlsClientHello::new()
        .with_random([0x66; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_raw_cipher_suites([0x1234])
        .with_extension(TlsRawExtension::supported_groups(supported_groups.clone())?)
        .with_extension(TlsRawExtension::signature_algorithms(
            signature_algorithms.clone(),
        )?)
        .with_extension(TlsRawExtension::psk_key_exchange_modes(psk_modes.clone())?)
        .with_extension(TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]));
    let handshake = TlsHandshake::from_client_hello(client_hello)?;
    let handshake_bytes = handshake.encode_to_vec()?;

    let decoded = TlsHandshake::decode(&handshake_bytes)?;
    assert_eq!(decoded.encode_to_vec()?, handshake_bytes);
    let hello = decoded.client_hello_body().expect("decoded ClientHello");

    assert_eq!(hello.cipher_suites().raw_values(), vec![0x1234]);
    assert_eq!(
        hello.cipher_suites().labels(),
        vec!["unknown cipher suite 0x1234"]
    );
    assert_contains(
        &hello.cipher_suites().summary(),
        "unknown cipher suite 0x1234",
    );
    assert_eq!(hello.extensions().len(), 4);
    assert_eq!(
        hello.extensions()[0].as_supported_groups()?,
        supported_groups
    );
    assert_eq!(
        hello.extensions()[1].as_signature_algorithms()?,
        signature_algorithms
    );
    assert_eq!(
        hello.extensions()[2].as_psk_key_exchange_modes()?,
        psk_modes
    );
    assert_eq!(hello.extensions()[3].raw_type(), 0xbeef);
    assert_eq!(hello.extensions()[3].body(), &[0xde, 0xad]);

    let summary = decoded.summary();
    assert_contains(&summary, "extensions=4");

    Ok(())
}
