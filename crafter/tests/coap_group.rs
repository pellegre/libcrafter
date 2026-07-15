//! RFC 7252 and RFC 7390 group-communication integration coverage.
//!
//! These tests construct and decode packets only. They never join multicast
//! groups, open sockets, select interfaces, schedule responses, or contact a
//! network.

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const CLIENT_PORT: u16 = 49_152;
const IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 77);
const IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 88);
const IPV6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x77);
const IPV6_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x88);
const TOKEN: &[u8] = &[0xa1];

const GROUP_GET: &[u8] = &[
    0x51, 0x01, 0x77, 0x01, 0xa1, // V1, NON, TKL 1, GET, MID, token.
    0xb6, b's', b't', b'a', b't', b'u', b's', // Uri-Path 11.
    0x51, 0x10, // Hop-Limit 16: delta 5, one-byte value 16.
    0xd1, 0xe5, 0x10, // No-Response 258: delta 242, suppress 5.xx.
    0xd2, 0x15, 0x44, 0x55, // Request-Tag 292: delta 34, two bytes.
];

const GROUP_RESPONSE: &[u8] = &[
    0x51,
    0x45,
    0x88,
    0x02,
    0xa1, // V1, NON, TKL 1, 2.05, MID, token.
    0xc2,
    0x01,
    0x00, // Content-Format 12: application/coap-group+json (256).
    COAP_PAYLOAD_MARKER,
    b'{',
    b'}',
];

fn group_get(message_id: u16) -> Result<Coap> {
    Ok(Coap::get()
        .non_confirmable()
        .message_id(message_id)
        .token(CoapToken::from_bytes(TOKEN))
        .uri_path("status")
        .hop_limit(CoapHopLimit::initial())
        .no_response(CoapNoResponse::suppress_server_error())
        .request_tag(CoapRequestTag::try_new([0x44, 0x55])?))
}

fn group_response(message_id: u16) -> Coap {
    Coap::content()
        .non_confirmable()
        .message_id(message_id)
        .token(CoapToken::from_bytes(TOKEN))
        .content_format(CoapContentFormat::coap_group_json())
        .payload(b"{}".to_vec())
}

fn compile_coap(message: Coap) -> Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

#[test]
fn group_get_is_byte_exact_typed_and_inspectable() -> Result<()> {
    let built = group_get(0x7701)?;
    assert_eq!(compile_coap(built.clone())?, GROUP_GET);

    let decoded = decode_coap(GROUP_GET)?;
    assert_eq!(
        decoded.message_type_value(),
        CoapMessageType::NonConfirmable
    );
    assert_eq!(decoded.code_value(), CoapCode::get());
    assert_eq!(decoded.message_id_value(), 0x7701);
    assert_eq!(decoded.token_value().as_bytes(), TOKEN);
    assert_eq!(decoded.options_value().len(), 4);
    assert_eq!(
        decoded.options_value()[0].number().value(),
        COAP_OPTION_URI_PATH
    );
    assert_eq!(decoded.options_value()[0].value(), b"status");
    assert_eq!(
        decoded
            .hop_limit_value()
            .expect("Hop-Limit option")?
            .remaining(),
        16
    );
    assert!(decoded
        .no_response_value()
        .expect("No-Response option")?
        .suppresses_server_error());
    assert_eq!(
        decoded
            .request_tag_value()
            .expect("Request-Tag option")?
            .as_bytes(),
        [0x44, 0x55]
    );

    let metadata =
        CoapGroupMetadata::ipv4(IPV4_CLIENT, COAP_ALL_NODES_IPV4_MULTICAST, decoded.clone());
    assert!(metadata.is_group_request());
    assert!(!metadata.is_unicast_response());
    assert!(metadata.has_multicast_destination());
    assert!(metadata.validate_group_request().is_clean());
    assert_eq!(metadata.payload(), b"");

    assert_eq!(
        decoded.summary(),
        "Coap(version=1, type=non-confirmable, code=0.01(GET), mid=0x7701, token_len=1, options=4, marker=absent, payload=0 bytes)"
    );
    let show = Packet::from_layer(decoded.clone()).show();
    assert!(
        show.contains("Uri-Path(11,len=6,hex=737461747573)"),
        "{show}"
    );
    assert!(show.contains("Hop-Limit(16,len=1,hex=10)"), "{show}");
    assert!(show.contains("No-Response(258,len=1,hex=10)"), "{show}");
    assert!(show.contains("Request-Tag(292,len=2,hex=4455)"), "{show}");
    assert_eq!(compile_coap(decoded)?, GROUP_GET);

    Ok(())
}

#[test]
fn unicast_group_response_matches_by_token_and_is_byte_exact() -> Result<()> {
    let request = CoapGroupMetadata::ipv6(
        IPV6_CLIENT,
        COAP_ALL_NODES_IPV6_SITE_LOCAL_MULTICAST,
        group_get(0x7701)?,
    );
    let built = group_response(0x8802);
    assert_eq!(compile_coap(built.clone())?, GROUP_RESPONSE);

    let decoded = decode_coap(GROUP_RESPONSE)?;
    let response = CoapGroupMetadata::ipv6(IPV6_SERVER, IPV6_CLIENT, decoded.clone());
    assert!(response.is_unicast_response());
    assert!(!response.has_multicast_destination());
    assert!(response.validate_group_response().is_clean());
    assert_eq!(
        response
            .content_format()
            .expect("Content-Format option")?
            .value(),
        COAP_CONTENT_FORMAT_GROUP_JSON
    );
    assert_eq!(response.payload(), b"{}");

    let matched = request.match_response(&response);
    assert!(matched.request_is_group());
    assert!(matched.request_is_non_confirmable());
    assert!(matched.response_is_response());
    assert!(matched.response_is_unicast());
    assert!(matched.address_family_matches());
    assert!(matched.response_destination_matches_request_source());
    assert!(matched.token_matches());
    assert!(matched.is_match());
    assert_ne!(request.message_id(), response.message_id());

    assert_eq!(
        decoded.summary(),
        "Coap(version=1, type=non-confirmable, code=2.05(Content), mid=0x8802, token_len=1, options=1, marker=present, payload=2 bytes)"
    );
    let show = Packet::from_layer(decoded.clone()).show();
    assert!(show.contains("Content-Format(12,len=2,hex=0100)"), "{show}");
    assert!(show.contains("payload_length: 2"), "{show}");
    assert_eq!(compile_coap(decoded)?, GROUP_RESPONSE);

    Ok(())
}

#[test]
fn group_validation_reports_multicast_and_option_constraints() -> Result<()> {
    const INVALID_GROUP_GET: &[u8] = &[
        0x41, 0x01, 0x77, 0x03, 0xa1, // V1, CON, TKL 1, GET, MID, token.
        0x41, 0x01, // ETag 4.
        0x20, // Observe 6 registration.
    ];

    let invalid = Coap::get()
        .confirmable()
        .message_id(0x7703)
        .token(CoapToken::from_bytes(TOKEN))
        .etag(CoapEtag::try_new([0x01])?)
        .observe(CoapObserve::register());
    assert_eq!(compile_coap(invalid.clone())?, INVALID_GROUP_GET);
    let metadata = CoapGroupMetadata::ipv4(IPV4_CLIENT, COAP_ALL_NODES_IPV4_MULTICAST, invalid);
    let validation = metadata.validate_group_request();

    for field in [
        "coap.group.request.type",
        "coap.group.request.options.etag",
        "coap.group.request.options.observe",
    ] {
        assert!(
            validation.issues().iter().any(|issue| {
                issue.field() == field
                    && issue.category() == CoapValidationCategory::GroupCommunication
                    && issue.severity() == CoapValidationSeverity::Error
            }),
            "missing group validation finding for {field}"
        );
    }
    assert!(validation.has_errors());

    let unicast_destination = CoapGroupMetadata::ipv4(IPV4_CLIENT, IPV4_SERVER, group_get(0x7704)?);
    assert!(!unicast_destination.is_group_request());
    assert!(unicast_destination
        .validate_group_request()
        .issues()
        .iter()
        .any(|issue| issue.field() == "coap.group.request.destination"));

    let acknowledgement = CoapGroupMetadata::ipv4(
        IPV4_SERVER,
        IPV4_CLIENT,
        Coap::content()
            .acknowledgement()
            .message_id(0x7701)
            .token(CoapToken::from_bytes(TOKEN)),
    );
    assert!(acknowledgement
        .validate_group_response()
        .issues()
        .iter()
        .any(|issue| issue.field() == "coap.group.response.type"));

    Ok(())
}

#[test]
fn ipv4_and_ipv6_group_packets_roundtrip_without_network_io() -> Result<()> {
    let ipv4_packet = coap_ipv4_group_request(
        IPV4_CLIENT,
        COAP_ALL_NODES_IPV4_MULTICAST,
        group_get(0x7701)?,
    );
    let ipv4_bytes = ipv4_packet.compile()?;
    assert!(ipv4_bytes.as_bytes().ends_with(GROUP_GET));
    let decoded_ipv4 = Packet::decode_from_l3(NetworkLayer::Ipv4, ipv4_bytes.as_bytes())?;
    assert_eq!(
        decoded_ipv4.layer::<Ipv4>().expect("IPv4 layer").source(),
        IPV4_CLIENT
    );
    assert_eq!(
        decoded_ipv4
            .layer::<Ipv4>()
            .expect("IPv4 layer")
            .destination(),
        COAP_ALL_NODES_IPV4_MULTICAST
    );
    assert_eq!(
        decoded_ipv4
            .layer::<Udp>()
            .expect("UDP layer")
            .destination_port_value(),
        COAP_PORT
    );
    assert_eq!(decoded_ipv4.layer::<Coap>(), Some(&decode_coap(GROUP_GET)?));
    assert!(decoded_ipv4.layer::<Raw>().is_none());
    assert_eq!(decoded_ipv4.compile()?.as_bytes(), ipv4_bytes.as_bytes());

    let ipv6_packet = coap_ipv6_group_response(IPV6_SERVER, IPV6_CLIENT, group_response(0x8802));
    let ipv6_bytes = ipv6_packet.compile()?;
    assert!(ipv6_bytes.as_bytes().ends_with(GROUP_RESPONSE));
    let decoded_ipv6 = Packet::decode_from_l3(NetworkLayer::Ipv6, ipv6_bytes.as_bytes())?;
    assert_eq!(
        decoded_ipv6.layer::<Ipv6>().expect("IPv6 layer").source(),
        IPV6_SERVER
    );
    assert_eq!(
        decoded_ipv6
            .layer::<Ipv6>()
            .expect("IPv6 layer")
            .destination(),
        IPV6_CLIENT
    );
    assert_eq!(
        decoded_ipv6
            .layer::<Udp>()
            .expect("UDP layer")
            .source_port_value(),
        COAP_PORT
    );
    assert_eq!(
        decoded_ipv6.layer::<Coap>(),
        Some(&decode_coap(GROUP_RESPONSE)?)
    );
    assert!(decoded_ipv6.layer::<Raw>().is_none());
    assert_eq!(decoded_ipv6.compile()?.as_bytes(), ipv6_bytes.as_bytes());

    Ok(())
}

#[test]
fn protected_group_and_secure_port_payloads_remain_raw() -> Result<()> {
    const GROUP_CIPHERTEXT: &[u8] = &[0xd4, 0x9a, 0x70, 0x33, 0xe1, 0x6b, 0x08, 0xff];

    let cases = [
        (
            NetworkLayer::Ipv4,
            (Ipv4::with_addresses(IPV4_CLIENT, COAP_ALL_NODES_IPV4_MULTICAST)
                / Udp::new().sport(CLIENT_PORT).dport(COAPS_PORT)
                / Raw::from_bytes(GROUP_CIPHERTEXT))
            .compile()?,
            GROUP_CIPHERTEXT,
        ),
        (
            NetworkLayer::Ipv6,
            (Ipv6::with_addresses(IPV6_CLIENT, IPV6_SERVER)
                / Udp::new().sport(CLIENT_PORT).dport(COAPS_PORT)
                / Raw::from_bytes(GROUP_GET))
            .compile()?,
            GROUP_GET,
        ),
    ];

    for (network_layer, packet, expected_payload) in cases {
        let decoded = Packet::decode_from_l3(network_layer, packet.as_bytes())?;
        assert!(decoded.layer::<Coap>().is_none());
        assert_eq!(
            decoded
                .layer::<Raw>()
                .expect("protected application payload stays Raw")
                .as_bytes(),
            expected_payload
        );
    }

    Ok(())
}

#[test]
fn provisional_group_oscore_example_is_typed_opaque_and_byte_exact() -> Result<()> {
    // draft-ietf-core-oscore-groupcomm-28 Section 4.3.1 publishes this
    // compressed request option and fourteen-byte ciphertext. The document is
    // still in the RFC Editor queue, so these bytes are preserved as opaque
    // provisional evidence and do not authorize a serializer or transform.
    const OPTION: &[u8] = &[0x39, 0x05, 0x03, 0x44, 0x61, 0x6c, 0x25];
    const CIPHERTEXT: &[u8] = &[
        0xae, 0xa0, 0x15, 0x56, 0x67, 0x92, 0x4d, 0xff, 0x8a, 0x24, 0xe4, 0xcb, 0x35, 0xb9,
    ];
    const COUNTERSIGNATURE: &[u8] = &[
        0x66, 0xe6, 0xd9, 0xb0, 0xdb, 0x00, 0x9f, 0x3e, 0x10, 0x5a, 0x67, 0x3f, 0x88, 0x55, 0x61,
        0x17, 0x26, 0xca, 0xed, 0x57, 0xf5, 0x30, 0xf8, 0xca, 0xe9, 0xd0, 0xb1, 0x68, 0x51, 0x3a,
        0xb9, 0x49, 0xfe, 0xdc, 0x3e, 0x80, 0xa9, 0x6e, 0xbe, 0x94, 0xba, 0x08, 0xd3, 0xf8, 0xd3,
        0xbf, 0x83, 0x48, 0x74, 0x58, 0xe2, 0xab, 0x4c, 0x2f, 0x93, 0x6f, 0xf7, 0x8b, 0x50, 0xe3,
        0x3c, 0x88, 0x5e, 0x35,
    ];
    const EXTERNAL_DATA: &[u8] = &[0xa1, 0x01, 0x82, 0x02, 0x03];

    let message = Coap::post()
        .non_confirmable()
        .message_id(0x9001)
        .option(CoapOption::new(COAP_OPTION_OSCORE, OPTION))
        .payload(CIPHERTEXT);
    let expected = [
        &[0x50, 0x02, 0x90, 0x01, 0x97][..],
        OPTION,
        &[COAP_PAYLOAD_MARKER][..],
        CIPHERTEXT,
    ]
    .concat();
    assert_eq!(compile_coap(message.clone())?, expected);

    let countersignature = GroupOscoreCountersignature::new(
        GroupOscoreAlgorithmId::new(65_000),
        EXTERNAL_DATA,
        COUNTERSIGNATURE,
    );
    let metadata = GroupOscoreMetadata::inspect(message.clone(), countersignature.clone()).unwrap();
    assert!(metadata.has_group_flag());
    assert_eq!(metadata.oscore_option().as_bytes(), OPTION);
    assert_eq!(metadata.partial_iv(), Some([0x05].as_slice()));
    assert_eq!(metadata.group_identifier(), Some(b"Dal".as_slice()));
    assert_eq!(metadata.sender_id(), Some([0x25].as_slice()));
    assert_eq!(metadata.protected_payload(), CIPHERTEXT);
    assert_eq!(metadata.countersignature().external_data(), EXTERNAL_DATA);
    assert_eq!(metadata.countersignature().as_bytes(), COUNTERSIGNATURE);
    assert_eq!(metadata.clone().into_message(), message);
    assert_eq!(compile_coap(metadata.into_message())?, expected);

    assert_eq!(
        countersignature.verify().unwrap_err(),
        OscoreError::UnsupportedCountersignatureAlgorithm { id: 65_000 }
    );
    assert!(!countersignature.algorithm().is_supported());
    Ok(())
}

#[test]
fn provisional_group_oscore_tamper_and_diagnostics_remain_opaque_and_redacted() {
    let option = [0x39, 0x05, 0x03, 0x44, 0x61, 0x6c, 0x25];
    let payload = [0xde, 0xad, 0xbe, 0xef, 0x80, 0x01];
    let countersignature = GroupOscoreCountersignature::new(
        GroupOscoreAlgorithmId::new(-999),
        [0xca, 0xfe, 0xba, 0xbe],
        [0x11, 0x22, 0x33, 0x44],
    );
    let message = Coap::post()
        .option(CoapOption::new(COAP_OPTION_OSCORE, option))
        .payload(payload);
    let metadata = GroupOscoreMetadata::inspect(message, countersignature).unwrap();

    let mut tampered = metadata.protected_payload().to_vec();
    tampered[2] ^= 0xff;
    let tampered_message = metadata.message().clone().payload(tampered.clone());
    let tampered_metadata =
        GroupOscoreMetadata::inspect(tampered_message, metadata.countersignature().clone())
            .unwrap();
    assert_eq!(tampered_metadata.protected_payload(), tampered);
    assert_eq!(
        tampered_metadata.require_protection_support().unwrap_err(),
        OscoreError::UnsupportedGroupOscoreOperation {
            operation: "protect-or-unprotect",
        }
    );

    let rendered = format!("{tampered_metadata:?}").to_ascii_lowercase();
    for forbidden in ["39050344616c25", "deadbeef8001", "cafebabe", "11223344"] {
        assert!(!rendered.contains(forbidden), "{rendered}");
    }
}
