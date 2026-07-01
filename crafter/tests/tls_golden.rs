//! TLS golden byte fixtures.
//!
//! These fixtures pin deterministic TLS handshake records built from public
//! packet-layer helpers. They are synthetic, offline-only inputs using reserved
//! `.test` names and opaque key-share bytes, not live captures.

use crafter::prelude::*;

const TLS12_CLIENT_HELLO: &str =
    include_str!("fixtures/bytes/tls-client-hello-tls12-compatible.hex");
const TLS13_CLIENT_HELLO: &str = include_str!("fixtures/bytes/tls-client-hello-tls13.hex");
const TLS12_SERVER_HELLO: &str = include_str!("fixtures/bytes/tls-server-hello-tls12.hex");
const TLS13_SERVER_HELLO: &str = include_str!("fixtures/bytes/tls-server-hello-tls13.hex");
const TLS13_HELLO_RETRY: &str = include_str!("fixtures/bytes/tls-hello-retry-request.hex");

fn fixture_bytes(contents: &str) -> Vec<u8> {
    let mut hex = String::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default();
        hex.extend(line.chars().filter(|ch| !ch.is_ascii_whitespace()));
    }
    assert_eq!(hex.len() % 2, 0, "fixture hex must have even length");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("valid fixture hex"))
        .collect()
}

fn hex_lines(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(16) {
        for (index, byte) in chunk.iter().enumerate() {
            if index > 0 {
                out.push(' ');
            }
            out.push_str(&format!("{byte:02x}"));
        }
        out.push('\n');
    }
    out
}

fn tls12_client_hello_record() -> crafter::Result<TlsRecord> {
    let hello = TlsClientHello::new()
        .with_random([0x12; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_session_id([0x12, 0x13, 0x14, 0x15])
        .with_raw_cipher_suites([
            TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ])
        .with_extensions(vec![
            TlsRawExtension::server_name(TlsServerNameList::from_host_name(
                "tls12.client.example.test",
            ))?,
            TlsRawExtension::alpn(TlsAlpnProtocols::h2_then_http_1_1())?,
            TlsRawExtension::supported_groups(TlsSupportedGroups::from_raws([
                TLS_NAMED_GROUP_SECP256R1,
                TLS_NAMED_GROUP_X25519,
            ]))?,
            TlsRawExtension::signature_algorithms(TlsSignatureAlgorithms::from_raws([
                TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
                TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
            ]))?,
        ]);
    TlsRecord::handshake_messages([TlsHandshake::from_client_hello(hello)?])
}

fn tls13_client_hello_record() -> crafter::Result<TlsRecord> {
    let hello = TlsClientHello::new()
        .with_random([0x13; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_session_id([
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ])
        .with_raw_cipher_suites([
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
        ])
        .with_extensions(vec![
            TlsRawExtension::server_name(TlsServerNameList::from_host_name(
                "tls13.client.example.test",
            ))?,
            TlsRawExtension::alpn(TlsAlpnProtocols::h2_then_http_1_1())?,
            TlsRawExtension::supported_versions_client(vec![
                TlsVersion::tls_1_3(),
                TlsVersion::tls_1_2(),
            ])?,
            TlsRawExtension::supported_groups(TlsSupportedGroups::from_raws([
                TLS_NAMED_GROUP_X25519,
                TLS_NAMED_GROUP_SECP256R1,
            ]))?,
            TlsRawExtension::signature_algorithms(TlsSignatureAlgorithms::from_raws([
                TLS_SIGNATURE_SCHEME_ED25519,
                TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
                TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
            ]))?,
            TlsRawExtension::key_share_client(vec![TlsKeyShareEntry::x25519([0x44; 32])])?,
        ]);
    TlsRecord::handshake_messages([TlsHandshake::from_client_hello(hello)?])
}

fn tls12_server_hello_record() -> crafter::Result<TlsRecord> {
    let hello = TlsServerHello::new()
        .with_random([0x22; TLS_SERVER_HELLO_RANDOM_LEN])
        .with_session_id_echo([0x12, 0x13, 0x14, 0x15])
        .with_raw_cipher_suite(TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        .with_extensions(Vec::new());
    TlsRecord::handshake_messages([TlsHandshake::from_server_hello(hello)?])
}

fn tls13_server_hello_record() -> crafter::Result<TlsRecord> {
    let hello = TlsServerHello::new()
        .with_random([0x23; TLS_SERVER_HELLO_RANDOM_LEN])
        .with_session_id_echo([
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ])
        .with_raw_cipher_suite(TLS_CIPHER_SUITE_AES_128_GCM_SHA256)
        .with_extensions(vec![
            TlsRawExtension::supported_versions_server(TlsVersion::tls_1_3())?,
            TlsRawExtension::key_share_server(TlsKeyShareEntry::x25519([0x55; 32]))?,
        ]);
    TlsRecord::handshake_messages([TlsHandshake::from_server_hello(hello)?])
}

fn tls13_hello_retry_request_record() -> crafter::Result<TlsRecord> {
    let hello = TlsServerHello::hello_retry_request()
        .with_session_id_echo([
            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ])
        .with_raw_cipher_suite(TLS_CIPHER_SUITE_AES_128_GCM_SHA256)
        .with_extensions(vec![
            TlsRawExtension::supported_versions_server(TlsVersion::tls_1_3())?,
            TlsRawExtension::key_share_hello_retry_request(TlsNamedGroup::SECP256R1)?,
        ]);
    TlsRecord::handshake_messages([TlsHandshake::from_server_hello(hello)?])
}

fn assert_client_hello_fixture(
    case_name: &str,
    fixture: &str,
    built: TlsRecord,
) -> crafter::Result<TlsClientHello> {
    let expected = fixture_bytes(fixture);
    assert_eq!(
        built.encode_to_vec()?,
        expected,
        "{case_name} builder bytes"
    );

    let decoded = TlsRecord::decode(&expected)?;
    assert_eq!(decoded.encode_to_vec()?, expected, "{case_name} recompile");
    assert_eq!(
        Packet::from_layer(Tls::from_record(decoded.clone()))
            .compile()?
            .as_bytes(),
        expected
    );
    assert_eq!(decoded.content_type(), TlsContentType::handshake());

    let messages = decoded
        .body()
        .handshake_messages()
        .expect("ClientHello fixture decodes as handshake body");
    assert_eq!(messages.len(), 1, "{case_name} message count");
    let hello = messages[0]
        .client_hello_body()
        .expect("ClientHello fixture decodes typed body")
        .clone();
    let rebuilt = TlsRecord::handshake_messages([TlsHandshake::from_client_hello(hello.clone())?])?;
    assert_eq!(
        rebuilt.encode_to_vec()?,
        expected,
        "{case_name} typed rebuild"
    );
    Ok(hello)
}

fn assert_server_hello_fixture(
    case_name: &str,
    fixture: &str,
    built: TlsRecord,
) -> crafter::Result<TlsServerHello> {
    let expected = fixture_bytes(fixture);
    assert_eq!(
        built.encode_to_vec()?,
        expected,
        "{case_name} builder bytes"
    );

    let decoded = TlsRecord::decode(&expected)?;
    assert_eq!(decoded.encode_to_vec()?, expected, "{case_name} recompile");
    assert_eq!(
        Packet::from_layer(Tls::from_record(decoded.clone()))
            .compile()?
            .as_bytes(),
        expected
    );
    assert_eq!(decoded.content_type(), TlsContentType::handshake());

    let messages = decoded
        .body()
        .handshake_messages()
        .expect("ServerHello fixture decodes as handshake body");
    assert_eq!(messages.len(), 1, "{case_name} message count");
    let hello = messages[0]
        .server_hello_body()
        .expect("ServerHello fixture decodes typed body")
        .clone();
    let rebuilt = TlsRecord::handshake_messages([TlsHandshake::from_server_hello(hello.clone())?])?;
    assert_eq!(
        rebuilt.encode_to_vec()?,
        expected,
        "{case_name} typed rebuild"
    );
    Ok(hello)
}

fn extension_types(extensions: &[TlsRawExtension]) -> Vec<u16> {
    extensions.iter().map(TlsRawExtension::raw_type).collect()
}

#[test]
fn tls_client_hello_tls12_compatible_golden_roundtrip() -> crafter::Result<()> {
    let hello = assert_client_hello_fixture(
        "tls-client-hello-tls12-compatible",
        TLS12_CLIENT_HELLO,
        tls12_client_hello_record()?,
    )?;

    assert_eq!(hello.legacy_version(), TlsVersion::tls_1_2());
    assert_eq!(hello.session_id(), &[0x12, 0x13, 0x14, 0x15]);
    assert_eq!(
        hello.cipher_suites().raw_values(),
        vec![
            TLS_CIPHER_SUITE_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]
    );
    assert_eq!(
        extension_types(hello.extensions()),
        vec![
            TLS_EXTENSION_SERVER_NAME,
            TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            TLS_EXTENSION_SUPPORTED_GROUPS,
            TLS_EXTENSION_SIGNATURE_ALGORITHMS,
        ]
    );
    assert_eq!(
        hello.extensions()[0].as_server_name_list()?.host_names(),
        vec!["tls12.client.example.test"]
    );
    assert_eq!(
        hello.extensions()[1].as_alpn_protocols()?.protocol_bytes(),
        vec![b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert_eq!(
        hello.extensions()[2].as_supported_groups()?.raw_values(),
        vec![TLS_NAMED_GROUP_SECP256R1, TLS_NAMED_GROUP_X25519]
    );
    assert_eq!(
        hello.extensions()[3]
            .as_signature_algorithms()?
            .raw_values(),
        vec![
            TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
            TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
        ]
    );
    Ok(())
}

#[test]
fn tls_client_hello_tls13_golden_roundtrip() -> crafter::Result<()> {
    let hello = assert_client_hello_fixture(
        "tls-client-hello-tls13",
        TLS13_CLIENT_HELLO,
        tls13_client_hello_record()?,
    )?;

    assert_eq!(hello.legacy_version(), TlsVersion::tls_1_2());
    assert_eq!(hello.session_id().len(), 12);
    assert_eq!(
        hello.cipher_suites().raw_values(),
        vec![
            TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
            TLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
        ]
    );
    assert_eq!(
        extension_types(hello.extensions()),
        vec![
            TLS_EXTENSION_SERVER_NAME,
            TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            TLS_EXTENSION_SUPPORTED_VERSIONS,
            TLS_EXTENSION_SUPPORTED_GROUPS,
            TLS_EXTENSION_SIGNATURE_ALGORITHMS,
            TLS_EXTENSION_KEY_SHARE,
        ]
    );
    assert_eq!(
        hello.extensions()[0].as_server_name_list()?.host_names(),
        vec!["tls13.client.example.test"]
    );
    assert_eq!(
        hello.extensions()[2]
            .as_supported_versions_client()?
            .versions()
            .expect("client supported_versions"),
        &[TlsVersion::tls_1_3(), TlsVersion::tls_1_2()]
    );
    assert_eq!(
        hello.extensions()[3].as_supported_groups()?.raw_values(),
        vec![TLS_NAMED_GROUP_X25519, TLS_NAMED_GROUP_SECP256R1]
    );
    assert_eq!(
        hello.extensions()[4]
            .as_signature_algorithms()?
            .raw_values(),
        vec![
            TLS_SIGNATURE_SCHEME_ED25519,
            TLS_SIGNATURE_SCHEME_RSA_PSS_RSAE_SHA256,
            TLS_SIGNATURE_SCHEME_ECDSA_SECP256R1_SHA256,
        ]
    );
    let key_share = hello.extensions()[5].as_key_share_client()?;
    assert_eq!(key_share.raw_groups(), vec![TLS_NAMED_GROUP_X25519]);
    assert_eq!(key_share.key_exchange_lengths(), vec![32]);
    Ok(())
}

#[test]
fn tls_server_hello_tls12_golden_roundtrip() -> crafter::Result<()> {
    let hello = assert_server_hello_fixture(
        "tls-server-hello-tls12",
        TLS12_SERVER_HELLO,
        tls12_server_hello_record()?,
    )?;
    let summary = hello.summary();

    assert_eq!(hello.form_label(), "server_hello");
    assert!(!hello.is_hello_retry_request());
    assert_eq!(hello.legacy_version(), TlsVersion::tls_1_2());
    assert_eq!(hello.session_id_echo(), &[0x12, 0x13, 0x14, 0x15]);
    assert_eq!(
        hello.raw_cipher_suite(),
        TLS_CIPHER_SUITE_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    );
    assert!(hello.extensions().is_empty());
    assert!(summary.contains("form=server_hello"));
    assert!(summary.contains("cipher_suite=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"));
    Ok(())
}

#[test]
fn tls_server_hello_tls13_golden_roundtrip() -> crafter::Result<()> {
    let hello = assert_server_hello_fixture(
        "tls-server-hello-tls13",
        TLS13_SERVER_HELLO,
        tls13_server_hello_record()?,
    )?;
    let summary = hello.summary();

    assert_eq!(hello.form_label(), "server_hello");
    assert!(!hello.is_hello_retry_request());
    assert_eq!(hello.legacy_version(), TlsVersion::tls_1_2());
    assert_eq!(hello.session_id_echo().len(), 12);
    assert_eq!(
        hello.raw_cipher_suite(),
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256
    );
    assert_eq!(
        extension_types(hello.extensions()),
        vec![TLS_EXTENSION_SUPPORTED_VERSIONS, TLS_EXTENSION_KEY_SHARE]
    );
    assert_eq!(
        hello.extensions()[0]
            .as_supported_versions_server()?
            .selected_version(),
        Some(TlsVersion::tls_1_3())
    );
    let key_share = hello.extensions()[1].as_key_share_server()?;
    assert_eq!(key_share.raw_groups(), vec![TLS_NAMED_GROUP_X25519]);
    assert_eq!(key_share.key_exchange_lengths(), vec![32]);
    assert!(summary.contains("form=server_hello"));
    assert!(summary.contains("cipher_suite=TLS_AES_128_GCM_SHA256"));
    assert!(summary.contains("extensions=2"));
    Ok(())
}

#[test]
fn tls_server_hello_hello_retry_request_golden_roundtrip() -> crafter::Result<()> {
    let hello = assert_server_hello_fixture(
        "tls-hello-retry-request",
        TLS13_HELLO_RETRY,
        tls13_hello_retry_request_record()?,
    )?;
    let summary = hello.summary();

    assert_eq!(hello.form_label(), "hello_retry_request");
    assert!(hello.is_hello_retry_request());
    assert_eq!(hello.legacy_version(), TlsVersion::tls_1_2());
    assert_eq!(hello.session_id_echo().len(), 12);
    assert_eq!(
        hello.raw_cipher_suite(),
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256
    );
    assert_eq!(
        extension_types(hello.extensions()),
        vec![TLS_EXTENSION_SUPPORTED_VERSIONS, TLS_EXTENSION_KEY_SHARE]
    );
    assert_eq!(
        hello.extensions()[0]
            .as_supported_versions_server()?
            .selected_version(),
        Some(TlsVersion::tls_1_3())
    );
    let key_share = hello.extensions()[1].as_key_share_hello_retry_request()?;
    assert_eq!(key_share.selected_group(), Some(TlsNamedGroup::SECP256R1));
    assert!(summary.contains("form=hello_retry_request"));
    assert!(summary.contains("extensions=2"));
    Ok(())
}

#[test]
#[ignore = "prints TLS ClientHello golden fixture bytes for checked-in updates"]
fn tls_client_hello_print_golden_fixture_bytes() -> crafter::Result<()> {
    println!(
        "tls-client-hello-tls12-compatible.hex:\n{}",
        hex_lines(&tls12_client_hello_record()?.encode_to_vec()?)
    );
    println!(
        "tls-client-hello-tls13.hex:\n{}",
        hex_lines(&tls13_client_hello_record()?.encode_to_vec()?)
    );
    Ok(())
}

#[test]
#[ignore = "prints TLS ServerHello golden fixture bytes for checked-in updates"]
fn tls_server_hello_print_golden_fixture_bytes() -> crafter::Result<()> {
    println!(
        "tls-server-hello-tls12.hex:\n{}",
        hex_lines(&tls12_server_hello_record()?.encode_to_vec()?)
    );
    println!(
        "tls-server-hello-tls13.hex:\n{}",
        hex_lines(&tls13_server_hello_record()?.encode_to_vec()?)
    );
    println!(
        "tls-hello-retry-request.hex:\n{}",
        hex_lines(&tls13_hello_retry_request_record()?.encode_to_vec()?)
    );
    Ok(())
}
