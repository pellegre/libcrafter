//! Public TLS API smoke tests.
//!
//! These tests import packet construction through `crafter::prelude::*` and
//! verify TLS also resolves through the crate root, `core`, and direct module
//! paths.

use std::net::Ipv4Addr;

use crafter::prelude::*;

#[test]
fn tls_public_api_exports_crate_root_core_and_prelude() -> crafter::Result<()> {
    let _: crafter::Tls = crafter::Tls::empty();
    let _: crafter::core::Tls =
        crafter::core::Tls::from_record(crafter::core::TlsRecord::standard_change_cipher_spec());
    let _: Tls = Tls::from_record(TlsRecord::application_data([0xaa]));

    assert_eq!(TLS_PORT_HTTPS, 443);
    assert_eq!(crafter::TLS_PORT_DNS_OVER_TLS, 853);
    assert_eq!(crafter::core::TLS_PORT_MQTT_OVER_TLS, 8883);
    assert_eq!(
        crafter::protocols::tls::TLS_CONTENT_TYPE_HANDSHAKE,
        TLS_CONTENT_TYPE_HANDSHAKE
    );
    assert_eq!(
        crafter::protocols::tls::TLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        TLS_CIPHER_SUITE_AES_128_GCM_SHA256
    );
    assert_eq!(
        crafter::protocols::tls::TLS_EXTENSION_SERVER_NAME,
        TLS_EXTENSION_SERVER_NAME
    );

    assert_eq!(
        tls_content_type_name(TLS_CONTENT_TYPE_HANDSHAKE),
        Some("handshake")
    );
    assert_eq!(
        tls_cipher_suite_name(TLS_CIPHER_SUITE_AES_128_GCM_SHA256),
        Some("TLS_AES_128_GCM_SHA256")
    );
    assert_eq!(
        tls_extension_name(TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION),
        Some("application_layer_protocol_negotiation")
    );

    assert_eq!(
        TlsContentType::from_u8(TLS_CONTENT_TYPE_HANDSHAKE),
        TlsContentType::handshake()
    );
    assert_eq!(
        TlsCipherSuite::from_u16(TLS_CIPHER_SUITE_AES_128_GCM_SHA256),
        TlsCipherSuite::aes_128_gcm_sha256()
    );
    assert_eq!(
        TlsHandshakeType::from_u8(TLS_HANDSHAKE_TYPE_CLIENT_HELLO),
        TlsHandshakeType::client_hello()
    );
    assert_eq!(
        TlsNamedGroup::from_u16(TLS_NAMED_GROUP_X25519),
        TlsNamedGroup::x25519()
    );
    assert_eq!(
        TlsSignatureScheme::from_u16(TLS_SIGNATURE_SCHEME_ED25519),
        TlsSignatureScheme::ed25519()
    );

    let _alert = TlsAlert::close_notify();
    let _version = TlsVersion::legacy_record();
    let _server_name = TlsServerName::host_name("example.test");
    let _raw_extension = TlsRawExtension::from_raw(TLS_EXTENSION_PADDING, [0x00, 0x00]);
    let heartbeat = TlsHeartbeat::request([0xaa], [0x55; TLS_HEARTBEAT_MIN_PADDING_LEN]);
    let heartbeat_record = TlsRecord::from_heartbeat(heartbeat)?;
    assert_eq!(heartbeat_record.content_type(), TlsContentType::heartbeat());

    Ok(())
}

#[test]
fn tls_public_api_prelude_builds_and_decodes_tls_packet() -> crafter::Result<()> {
    let client_hello = TlsClientHello::new()
        .with_random([0x33; TLS_CLIENT_HELLO_RANDOM_LEN])
        .with_raw_cipher_suites([TLS_CIPHER_SUITE_AES_128_GCM_SHA256])
        .without_extensions();
    let handshake = TlsHandshake::from_client_hello(client_hello)?;
    let record = TlsRecord::handshake_messages([handshake])?;
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 55))
        .dst(Ipv4Addr::new(198, 51, 100, 55))
        / Tcp::new()
            .sport(49_152)
            .dport(TLS_PORT_HTTPS)
            .seq(0x5152_5354)
            .ack(0x6162_6364)
            .ack_segment()
        / Tls::from_record(record);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let tls = decoded.layer::<Tls>().expect("decoded TLS layer");

    assert_eq!(tls.record_count(), 1);
    assert_eq!(tls.records()[0].content_type(), TlsContentType::handshake());
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}
