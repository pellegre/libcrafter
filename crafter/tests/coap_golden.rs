//! Source-backed golden request vectors for the CoAP datagram layer.
//!
//! The byte constants below were calculated from the wire grammar and registry
//! assignments, independently of `crafter`'s encoder. This fixture matrix
//! records the authority and arithmetic used to derive each vector:
//!
//! | Fixture | Sources | Independent derivation |
//! | --- | --- | --- |
//! | `CONFIRMABLE_GET` | [RFC 7252 sections 3, 5.4, and 5.10](https://www.rfc-editor.org/rfc/rfc7252.html); [IANA CoRE Parameters](https://www.iana.org/assignments/core-parameters/core-parameters.xhtml) | Header `01 00 0010` = `0x42`; GET = `0x01`; Message ID and token are literal; option `(delta,length)` pairs are `(11,7)`, `(0,4)`, `(4,7)`, `(2,1)`; application/json is Content-Format ID 50 = `0x32`. |
//! | `PAYLOAD_POST` | [RFC 7252 sections 3, 5.5, 5.8, and 5.10](https://www.rfc-editor.org/rfc/rfc7252.html); [IANA CoRE Parameters](https://www.iana.org/assignments/core-parameters/core-parameters.xhtml) | Header `01 00 0001` = `0x41`; POST = `0x02`; Uri-Path `(11,9)` = `0xb9`; Content-Format `(1,0)` = `0x10`; text/plain is ID 0 and therefore the canonical empty uint; payload begins after marker `0xff`. |
//!
//! The IANA assignments were reviewed in the repository's dated
//! `.agents/docs/coap-codepoints.md` snapshot. Network envelopes use only RFC
//! 5737 and RFC 3849 documentation addresses and never send traffic.

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const CLIENT_PORT: u16 = 49_152;
const GET_MESSAGE_ID: u16 = 0x1234;
const POST_MESSAGE_ID: u16 = 0xbeef;
const POST_PAYLOAD_MARKER_OFFSET: usize = 16;

const CONFIRMABLE_GET: &[u8] = &[
    // RFC 7252 section 3: version 1, CON, TKL 2; GET; Message ID 0x1234.
    0x42, 0x01, 0x12, 0x34, // Opaque two-byte token.
    0xaa, 0xbb, // Uri-Path 11, delta 11, length 7: "sensors".
    0xb7, b's', b'e', b'n', b's', b'o', b'r', b's',
    // Repeated Uri-Path 11, delta 0, length 4: "temp".
    0x04, b't', b'e', b'm', b'p', // Uri-Query 15, delta 4, length 7: "units=c".
    0x47, b'u', b'n', b'i', b't', b's', b'=', b'c',
    // Accept 17, delta 2, length 1: application/json Content-Format ID 50.
    0x21, 0x32,
];

const PAYLOAD_POST: &[u8] = &[
    // RFC 7252 section 3: version 1, CON, TKL 1; POST; Message ID 0xbeef.
    0x41, 0x02, 0xbe, 0xef, // Opaque one-byte token.
    0x10, // Uri-Path 11, delta 11, length 9: "telemetry".
    0xb9, b't', b'e', b'l', b'e', b'm', b'e', b't', b'r', b'y',
    // Content-Format 12, delta 1, length 0: text/plain ID 0.
    0x10, // RFC 7252 section 5.5 payload marker followed by the binary payload.
    0xff, b'o', b'n',
];

fn confirmable_get() -> Coap {
    Coap::get()
        .confirmable()
        .message_id(GET_MESSAGE_ID)
        .token(CoapToken::new([0xaa, 0xbb]).expect("two-byte token is valid"))
        .option(CoapOption::from_string(COAP_OPTION_URI_PATH, "sensors"))
        .option(CoapOption::from_string(COAP_OPTION_URI_PATH, "temp"))
        .option(CoapOption::from_string(COAP_OPTION_URI_QUERY, "units=c"))
        .option(CoapOption::from_uint(COAP_OPTION_ACCEPT, 50))
}

fn payload_post() -> Coap {
    Coap::post()
        .confirmable()
        .message_id(POST_MESSAGE_ID)
        .token(CoapToken::new([0x10]).expect("one-byte token is valid"))
        .option(CoapOption::from_string(COAP_OPTION_URI_PATH, "telemetry"))
        .option(CoapOption::from_uint(COAP_OPTION_CONTENT_FORMAT, 0))
        .payload(b"on".to_vec())
}

fn assert_recompile_equality(message: &Coap, golden: &[u8]) -> crafter::Result<()> {
    assert_eq!(
        Packet::from_layer(message.clone()).compile()?.as_bytes(),
        golden
    );
    Ok(())
}

#[test]
fn confirmable_get_matches_source_backed_request_bytes() -> crafter::Result<()> {
    let built = confirmable_get();
    assert_recompile_equality(&built, CONFIRMABLE_GET)?;

    let decoded = decode_coap(CONFIRMABLE_GET)?;
    assert_eq!(decoded.version_value(), CoapVersion::current());
    assert_eq!(decoded.message_type_value(), CoapMessageType::Confirmable);
    assert_eq!(decoded.code_value(), CoapCode::get());
    assert_eq!(decoded.message_id_value(), GET_MESSAGE_ID);
    assert_eq!(decoded.token_length_value()?.declared_len(), 2);
    assert_eq!(decoded.token_value().as_bytes(), [0xaa, 0xbb]);
    assert_eq!(decoded.payload_marker_value(), CoapPayloadMarker::Absent);
    assert!(decoded.payload_value().is_empty());

    let options = decoded.options_value();
    assert_eq!(options.len(), 4);
    assert_eq!(options[0].number().value(), COAP_OPTION_URI_PATH);
    assert_eq!(options[0].as_str()?, "sensors");
    assert_eq!(options[1].number().value(), COAP_OPTION_URI_PATH);
    assert_eq!(options[1].as_str()?, "temp");
    assert_eq!(options[2].number().value(), COAP_OPTION_URI_QUERY);
    assert_eq!(options[2].as_str()?, "units=c");
    assert_eq!(options[3].number().value(), COAP_OPTION_ACCEPT);
    assert_eq!(options[3].as_uint()?, 50);

    assert_recompile_equality(&decoded, CONFIRMABLE_GET)?;
    assert_eq!(
        decoded.summary(),
        "Coap(version=1, type=confirmable, code=0.01(GET), mid=0x1234, token_len=2, options=4, marker=absent, payload=0 bytes)"
    );
    assert_eq!(
        Packet::from_layer(decoded).show(),
        "Packet(len=29, layers=1)\n  [0] Coap\n      version: 1\n      type: confirmable\n      token_length: 2\n      code: 0.01(GET)\n      message_id: 0x1234\n      token: len=2 hex=aabb\n      options: 4 [Uri-Path(11,len=7,hex=73656e736f7273), Uri-Path(11,len=4,hex=74656d70), Uri-Query(15,len=7,hex=756e6974733d63), Accept(17,len=1,hex=32)]\n      payload_marker: absent\n      payload_length: 0"
    );

    Ok(())
}

#[test]
fn payload_post_matches_marker_boundary_and_recompiles() -> crafter::Result<()> {
    assert_eq!(PAYLOAD_POST[POST_PAYLOAD_MARKER_OFFSET], 0xff);
    assert_eq!(&PAYLOAD_POST[POST_PAYLOAD_MARKER_OFFSET + 1..], b"on");

    let built = payload_post();
    assert_recompile_equality(&built, PAYLOAD_POST)?;

    let decoded = decode_coap(PAYLOAD_POST)?;
    assert_eq!(decoded.message_type_value(), CoapMessageType::Confirmable);
    assert_eq!(decoded.code_value(), CoapCode::post());
    assert_eq!(decoded.message_id_value(), POST_MESSAGE_ID);
    assert_eq!(decoded.token_value().as_bytes(), [0x10]);
    assert_eq!(decoded.payload_marker_value(), CoapPayloadMarker::Present);
    assert_eq!(decoded.payload_value(), b"on");

    let options = decoded.options_value();
    assert_eq!(options.len(), 2);
    assert_eq!(options[0].number().value(), COAP_OPTION_URI_PATH);
    assert_eq!(options[0].as_str()?, "telemetry");
    assert_eq!(options[1].number().value(), COAP_OPTION_CONTENT_FORMAT);
    assert_eq!(options[1].value(), b"");
    assert_eq!(options[1].as_uint()?, 0);

    assert_recompile_equality(&decoded, PAYLOAD_POST)?;
    assert_eq!(
        decoded.summary(),
        "Coap(version=1, type=confirmable, code=0.02(POST), mid=0xbeef, token_len=1, options=2, marker=present, payload=2 bytes)"
    );
    let show = Packet::from_layer(decoded).show();
    assert!(show.contains("code: 0.02(POST)"), "{show}");
    assert!(show.contains("Content-Format(12,len=0,hex=)"), "{show}");
    assert!(show.contains("payload_marker: present"), "{show}");
    assert!(show.contains("payload_length: 2"), "{show}");

    Ok(())
}

#[test]
fn request_goldens_compile_inside_ipv4_and_ipv6_udp_stacks() -> crafter::Result<()> {
    let ipv4 = Ipv4::with_addresses(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(198, 51, 100, 20),
    ) / Udp::new()
        .source_port(CLIENT_PORT)
        .destination_port(COAP_PORT)
        / confirmable_get();
    let ipv4_bytes = ipv4.compile()?;
    assert_eq!(ipv4_bytes.as_bytes().len(), 20 + 8 + CONFIRMABLE_GET.len());
    assert!(ipv4_bytes.as_bytes().ends_with(CONFIRMABLE_GET));

    let ipv6 = Ipv6::with_addresses(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10),
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20),
    ) / Udp::new()
        .source_port(CLIENT_PORT)
        .destination_port(COAP_PORT)
        / payload_post();
    let ipv6_bytes = ipv6.compile()?;
    assert_eq!(ipv6_bytes.as_bytes().len(), 40 + 8 + PAYLOAD_POST.len());
    assert!(ipv6_bytes.as_bytes().ends_with(PAYLOAD_POST));

    Ok(())
}
