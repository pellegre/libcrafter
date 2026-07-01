//! TLS summary and inspection output coverage.
//!
//! These tests use documentation address space only and exercise the public
//! packet-layer `summary()` / `show()` surface instead of private helpers.

use std::net::Ipv4Addr;

use crafter::prelude::*;

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected to find {needle:?} in:\n{haystack}"
    );
}

fn assert_not_contains(haystack: &str, needle: &str) {
    assert!(
        !haystack.contains(needle),
        "did not expect to find {needle:?} in:\n{haystack}"
    );
}

fn tls_client_hello_layer() -> crafter::Result<Tls> {
    let client_hello = TlsClientHello::new()
        .with_random([0x44; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_raw_cipher_suites([TLS_CIPHER_SUITE_AES_128_GCM_SHA256])
        .with_extension(TlsRawExtension::alpn(TlsAlpnProtocols::new([
            TlsAlpnProtocol::h2(),
        ]))?);
    let handshake = TlsHandshake::from_client_hello(client_hello)?;
    Ok(Tls::from_record(TlsRecord::handshake_messages([
        handshake,
    ])?))
}

#[test]
fn tls_client_hello_summary_and_show_include_nested_handshake_details() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 70))
        .dst(Ipv4Addr::new(198, 51, 100, 70))
        / Tcp::new()
            .sport(49_152)
            .dport(TLS_PORT_HTTPS)
            .seq(0x7071_7273)
            .ack(0x8081_8283)
            .ack_segment()
        / tls_client_hello_layer()?;

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let summary = decoded.summary();
    let show = decoded.show();

    assert_contains(&summary, "TLS records=1");
    assert_contains(&summary, "content_type=handshake");
    assert_contains(&summary, "legacy_record_version=TLS 1.2");
    assert_contains(&summary, "handshake_type=client_hello");
    assert_contains(&summary, "client_hello legacy_version=TLS 1.2");
    assert_contains(&summary, "cipher_suites=1");
    assert_contains(&summary, "extensions=1");
    assert_contains(&show, "TLS");
    assert_contains(&show, "content_types: [handshake]");
    assert_contains(&show, "record: record content_type=handshake");
    assert_contains(&show, "body=handshake messages=1");
    assert_contains(&show, "handshake_type=client_hello");
    assert_contains(&show, "extensions=1");
    Ok(())
}

#[test]
fn tls_summary_covers_server_hello_alert_unknown_and_overrides() -> crafter::Result<()> {
    let server_hello = TlsServerHello::new()
        .with_random([0x55; TLS_SERVER_HELLO_RANDOM_LEN])
        .with_raw_cipher_suite(TLS_CIPHER_SUITE_AES_256_GCM_SHA384)
        .with_extension(TlsRawExtension::supported_versions_server(
            TlsVersion::tls_1_3(),
        )?);
    let server_record =
        TlsRecord::handshake_messages([TlsHandshake::from_server_hello(server_hello)?])?;
    let server_summary = Tls::from_record(server_record).summary();

    assert_contains(&server_summary, "handshake_type=server_hello");
    assert_contains(&server_summary, "server_hello form=server_hello");
    assert_contains(&server_summary, "cipher_suite=TLS_AES_256_GCM_SHA384");
    assert_contains(&server_summary, "extensions=1");

    let alert_summary = TlsAlert::decode_error().summary();
    assert_eq!(alert_summary, "alert level=fatal description=decode_error");

    let unknown = Tls::from_record(
        TlsRecord::from_fragment(0xfe, [0xde, 0xad]).with_raw_legacy_record_version(0x4242),
    );
    let unknown_summary = unknown.summary();
    assert_contains(&unknown_summary, "unassigned content type 0xfe");
    assert_contains(&unknown_summary, "unknown protocol version 0x4242");
    assert_contains(&unknown_summary, "opaque bytes=2");

    let override_summary =
        Tls::from_record(TlsRecord::application_data([0xaa]).with_length(0)).summary();
    assert_contains(&override_summary, "declared_length=0");
    assert_contains(&override_summary, "fragment_bytes=1");
    assert_contains(&override_summary, "application_data bytes=1");
    Ok(())
}

#[test]
fn tls_application_data_summary_and_show_stay_concise() {
    let tls = Tls::from_record(TlsRecord::application_data([0xde, 0xad, 0xbe, 0xef]));
    let packet = Packet::from_layer(tls);
    let summary = packet.summary();
    let show = packet.show();

    assert_contains(&summary, "application_data bytes=4");
    assert_contains(&show, "application_data bytes=4");
    assert_not_contains(&summary, "de ad be ef");
    assert_not_contains(&show, "de ad be ef");
}
