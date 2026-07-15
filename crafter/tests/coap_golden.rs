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
//! | `PIGGYBACKED_ACK_CONTENT`, `SEPARATE_CON_CHANGED`, `NON_CREATED` | [RFC 7252 sections 4.2, 5.2.1, 5.2.2, 5.3.1, 5.3.2, and 5.10](https://www.rfc-editor.org/rfc/rfc7252.html); [IANA CoRE Parameters](https://www.iana.org/assignments/core-parameters/core-parameters.xhtml) | ACK, CON, and NON set Type bits to `10`, `00`, and `01`; success codes 2.05, 2.04, and 2.01 are `0x45`, `0x44`, and `0x41`; Content-Format 0 is `0xc0`, ETag `(4,2)` is `0x42`, and Location-Path `(8,4)` is `0x84`. |
//! | `EMPTY_ACK`, `EMPTY_RESET` | [RFC 7252 sections 3, 4.1, 4.2, and 4.3](https://www.rfc-editor.org/rfc/rfc7252.html) | Empty ACK and Reset have TKL zero and Code `0x00`, so their complete bytes are the Type-specific first octet (`0x60` or `0x70`), the Empty code, and the matched Message ID. |
//! | `ACK_NOT_FOUND`, `NON_INTERNAL_ERROR`, `UNKNOWN_RESET_RESPONSE` | [RFC 7252 sections 3, 5.2, 5.3, and 5.9](https://www.rfc-editor.org/rfc/rfc7252.html); [IANA CoRE Parameters](https://www.iana.org/assignments/core-parameters/core-parameters.xhtml) | 4.04 and 5.00 are `0x84` and `0xa0`; Content-Format 0 is `0xc0`; following Max-Age 30 has `(delta,length)=(2,1)` and bytes `0x21 0x1e`; unassigned 2.29 is preserved as `0x5d`, including in the deliberately unusual Reset/type pairing. |
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

const PIGGYBACKED_REQUEST_MESSAGE_ID: u16 = 0x2301;
const SEPARATE_REQUEST_MESSAGE_ID: u16 = 0x3401;
const SEPARATE_RESPONSE_MESSAGE_ID: u16 = 0x3402;
const NON_REQUEST_MESSAGE_ID: u16 = 0x4501;
const NON_RESPONSE_MESSAGE_ID: u16 = 0x4502;
const RESET_MESSAGE_ID: u16 = 0x5601;
const PIGGYBACKED_TOKEN: &[u8] = &[0xaa];
const SEPARATE_TOKEN: &[u8] = &[0xde, 0xad];
const NON_TOKEN: &[u8] = &[0xbb];

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

const PIGGYBACKED_ACK_CONTENT: &[u8] = &[
    // Version 1, ACK, TKL 1; 2.05 Content; matched request Message ID/token.
    0x61, 0x45, 0x23, 0x01, 0xaa,
    // Content-Format 12, delta 12, empty uint value 0 (text/plain).
    0xc0, // Payload marker and opaque representation bytes.
    0xff, b'2', b'2', b'.', b'3', b' ', b'C',
];

const SEPARATE_CON_CHANGED: &[u8] = &[
    // Version 1, CON, TKL 2; 2.04 Changed; response-owned Message ID.
    0x42, 0x44, 0x34, 0x02, 0xde, 0xad, // ETag 4, delta 4, length 2.
    0x42, 0x10, 0x20,
];

const NON_CREATED: &[u8] = &[
    // Version 1, NON, TKL 1; 2.01 Created; response-owned Message ID.
    0x51, 0x41, 0x45, 0x02, 0xbb, // Location-Path 8, delta 8, length 4: "jobs".
    0x84, b'j', b'o', b'b', b's',
];

const EMPTY_ACK: &[u8] = &[
    // Version 1, ACK, TKL 0; Empty; matched request Message ID.
    0x60, 0x00, 0x34, 0x01,
];

const EMPTY_RESET: &[u8] = &[
    // Version 1, Reset, TKL 0; Empty; rejected message's Message ID.
    0x70, 0x00, 0x56, 0x01,
];

const ACK_NOT_FOUND: &[u8] = &[
    // Version 1, ACK, TKL 1; 4.04 Not Found.
    0x61, 0x84, 0x67, 0x01, 0xcc,
    // Content-Format 12, delta 12, empty uint value 0 (text/plain).
    0xc0, 0xff, b'm', b'i', b's', b's', b'i', b'n', b'g',
];

const NON_INTERNAL_ERROR: &[u8] = &[
    // Version 1, NON, TKL 1; 5.00 Internal Server Error.
    0x51, 0xa0, 0x67, 0x02, 0xdd,
    // Content-Format 12 = text/plain, followed by Max-Age 14 = 30 seconds.
    0xc0, 0x21, 0x1e, 0xff, b'r', b'e', b't', b'r', b'y',
];

const UNKNOWN_RESET_RESPONSE: &[u8] = &[
    // Structurally valid but semantically unusual: Reset, TKL 2, unassigned 2.29.
    0x72, 0x5d, 0x78, 0x01, 0x12, 0x34,
];

#[derive(Clone, Copy)]
struct ExpectedOption {
    number: u16,
    value: &'static [u8],
}

#[derive(Clone, Copy)]
struct ResponseGolden {
    name: &'static str,
    bytes: &'static [u8],
    build: fn() -> Coap,
    message_type: CoapMessageType,
    code: CoapCode,
    code_label: &'static str,
    message_id: u16,
    token: &'static [u8],
    options: &'static [ExpectedOption],
    marker: CoapPayloadMarker,
    payload: &'static [u8],
}

const NO_OPTIONS: &[ExpectedOption] = &[];
const CONTENT_FORMAT_TEXT_OPTION: &[ExpectedOption] = &[ExpectedOption {
    number: COAP_OPTION_CONTENT_FORMAT,
    value: b"",
}];
const ETAG_OPTION: &[ExpectedOption] = &[ExpectedOption {
    number: COAP_OPTION_ETAG,
    value: &[0x10, 0x20],
}];
const LOCATION_PATH_OPTION: &[ExpectedOption] = &[ExpectedOption {
    number: COAP_OPTION_LOCATION_PATH,
    value: b"jobs",
}];
const INTERNAL_ERROR_OPTIONS: &[ExpectedOption] = &[
    ExpectedOption {
        number: COAP_OPTION_CONTENT_FORMAT,
        value: b"",
    },
    ExpectedOption {
        number: COAP_OPTION_MAX_AGE,
        value: &[0x1e],
    },
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

fn piggybacked_ack_content() -> Coap {
    Coap::response(CoapCode::content())
        .acknowledgement()
        .message_id(PIGGYBACKED_REQUEST_MESSAGE_ID)
        .token(CoapToken::from_bytes(PIGGYBACKED_TOKEN))
        .option(CoapOption::from_uint(COAP_OPTION_CONTENT_FORMAT, 0))
        .payload(b"22.3 C".to_vec())
}

fn separate_con_changed() -> Coap {
    Coap::response(CoapCode::changed())
        .confirmable()
        .message_id(SEPARATE_RESPONSE_MESSAGE_ID)
        .token(CoapToken::from_bytes(SEPARATE_TOKEN))
        .option(CoapOption::from_opaque(COAP_OPTION_ETAG, [0x10, 0x20]))
}

fn non_created() -> Coap {
    Coap::response(CoapCode::created())
        .non_confirmable()
        .message_id(NON_RESPONSE_MESSAGE_ID)
        .token(CoapToken::from_bytes(NON_TOKEN))
        .option(CoapOption::from_string(COAP_OPTION_LOCATION_PATH, "jobs"))
}

fn empty_ack() -> Coap {
    Coap::empty()
        .acknowledgement()
        .message_id(SEPARATE_REQUEST_MESSAGE_ID)
}

fn empty_reset() -> Coap {
    Coap::empty().reset().message_id(RESET_MESSAGE_ID)
}

fn ack_not_found() -> Coap {
    Coap::response(CoapCode::not_found())
        .acknowledgement()
        .message_id(0x6701)
        .token(CoapToken::from_bytes([0xcc]))
        .option(CoapOption::from_uint(COAP_OPTION_CONTENT_FORMAT, 0))
        .payload(b"missing".to_vec())
}

fn non_internal_error() -> Coap {
    Coap::response(CoapCode::internal_server_error())
        .non_confirmable()
        .message_id(0x6702)
        .token(CoapToken::from_bytes([0xdd]))
        .option(CoapOption::from_uint(COAP_OPTION_CONTENT_FORMAT, 0))
        .option(CoapOption::from_uint(COAP_OPTION_MAX_AGE, 30))
        .payload(b"retry".to_vec())
}

fn unknown_reset_response() -> Coap {
    Coap::response(CoapCode::from_parts(2, 29))
        .reset()
        .message_id(0x7801)
        .token(CoapToken::from_bytes([0x12, 0x34]))
}

const RESPONSE_GOLDENS: &[ResponseGolden] = &[
    ResponseGolden {
        name: "piggybacked-ack-content",
        bytes: PIGGYBACKED_ACK_CONTENT,
        build: piggybacked_ack_content,
        message_type: CoapMessageType::Acknowledgement,
        code: CoapCode::content(),
        code_label: "2.05",
        message_id: PIGGYBACKED_REQUEST_MESSAGE_ID,
        token: PIGGYBACKED_TOKEN,
        options: CONTENT_FORMAT_TEXT_OPTION,
        marker: CoapPayloadMarker::Present,
        payload: b"22.3 C",
    },
    ResponseGolden {
        name: "separate-con-changed",
        bytes: SEPARATE_CON_CHANGED,
        build: separate_con_changed,
        message_type: CoapMessageType::Confirmable,
        code: CoapCode::changed(),
        code_label: "2.04",
        message_id: SEPARATE_RESPONSE_MESSAGE_ID,
        token: SEPARATE_TOKEN,
        options: ETAG_OPTION,
        marker: CoapPayloadMarker::Absent,
        payload: b"",
    },
    ResponseGolden {
        name: "non-created",
        bytes: NON_CREATED,
        build: non_created,
        message_type: CoapMessageType::NonConfirmable,
        code: CoapCode::created(),
        code_label: "2.01",
        message_id: NON_RESPONSE_MESSAGE_ID,
        token: NON_TOKEN,
        options: LOCATION_PATH_OPTION,
        marker: CoapPayloadMarker::Absent,
        payload: b"",
    },
    ResponseGolden {
        name: "empty-ack",
        bytes: EMPTY_ACK,
        build: empty_ack,
        message_type: CoapMessageType::Acknowledgement,
        code: CoapCode::empty(),
        code_label: "0.00",
        message_id: SEPARATE_REQUEST_MESSAGE_ID,
        token: b"",
        options: NO_OPTIONS,
        marker: CoapPayloadMarker::Absent,
        payload: b"",
    },
    ResponseGolden {
        name: "empty-reset",
        bytes: EMPTY_RESET,
        build: empty_reset,
        message_type: CoapMessageType::Reset,
        code: CoapCode::empty(),
        code_label: "0.00",
        message_id: RESET_MESSAGE_ID,
        token: b"",
        options: NO_OPTIONS,
        marker: CoapPayloadMarker::Absent,
        payload: b"",
    },
    ResponseGolden {
        name: "ack-not-found",
        bytes: ACK_NOT_FOUND,
        build: ack_not_found,
        message_type: CoapMessageType::Acknowledgement,
        code: CoapCode::not_found(),
        code_label: "4.04",
        message_id: 0x6701,
        token: &[0xcc],
        options: CONTENT_FORMAT_TEXT_OPTION,
        marker: CoapPayloadMarker::Present,
        payload: b"missing",
    },
    ResponseGolden {
        name: "non-internal-error",
        bytes: NON_INTERNAL_ERROR,
        build: non_internal_error,
        message_type: CoapMessageType::NonConfirmable,
        code: CoapCode::internal_server_error(),
        code_label: "5.00",
        message_id: 0x6702,
        token: &[0xdd],
        options: INTERNAL_ERROR_OPTIONS,
        marker: CoapPayloadMarker::Present,
        payload: b"retry",
    },
    ResponseGolden {
        name: "unknown-reset-response",
        bytes: UNKNOWN_RESET_RESPONSE,
        build: unknown_reset_response,
        message_type: CoapMessageType::Reset,
        code: CoapCode::from_parts(2, 29),
        code_label: "2.29",
        message_id: 0x7801,
        token: &[0x12, 0x34],
        options: NO_OPTIONS,
        marker: CoapPayloadMarker::Absent,
        payload: b"",
    },
];

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
fn response_and_empty_message_goldens_compile_decode_and_recompile() -> crafter::Result<()> {
    for case in RESPONSE_GOLDENS {
        let built = (case.build)();
        assert_recompile_equality(&built, case.bytes)
            .unwrap_or_else(|error| panic!("{} builder did not match golden: {error}", case.name));

        let decoded = decode_coap(case.bytes)
            .unwrap_or_else(|error| panic!("{} did not decode: {error}", case.name));
        assert_eq!(
            decoded.message_type_value(),
            case.message_type,
            "{}",
            case.name
        );
        assert_eq!(decoded.code_value(), case.code, "{}", case.name);
        assert_eq!(
            decoded.code_value().class(),
            case.code.class(),
            "{}",
            case.name
        );
        assert_eq!(
            decoded.code_value().detail(),
            case.code.detail(),
            "{}",
            case.name
        );
        assert_eq!(
            decoded.code_value().label(),
            case.code_label,
            "{}",
            case.name
        );
        assert_eq!(decoded.message_id_value(), case.message_id, "{}", case.name);
        assert_eq!(
            decoded.token_value().as_bytes(),
            case.token,
            "{}",
            case.name
        );
        assert_eq!(decoded.payload_marker_value(), case.marker, "{}", case.name);
        assert_eq!(decoded.payload_value(), case.payload, "{}", case.name);
        assert_eq!(
            decoded.options_value().len(),
            case.options.len(),
            "{}",
            case.name
        );
        for (actual, expected) in decoded.options_value().iter().zip(case.options) {
            assert_eq!(actual.number().value(), expected.number, "{}", case.name);
            assert_eq!(actual.value(), expected.value, "{}", case.name);
        }

        assert_recompile_equality(&decoded, case.bytes).unwrap_or_else(|error| {
            panic!("{} decoded value did not recompile: {error}", case.name)
        });
    }

    Ok(())
}

#[test]
fn response_goldens_preserve_code_registry_labels_and_option_views() -> crafter::Result<()> {
    for (code, class, detail, label) in [
        (CoapCode::created(), 2, 1, "Created"),
        (CoapCode::changed(), 2, 4, "Changed"),
        (CoapCode::content(), 2, 5, "Content"),
        (CoapCode::not_found(), 4, 4, "Not Found"),
        (
            CoapCode::internal_server_error(),
            5,
            0,
            "Internal Server Error",
        ),
    ] {
        assert_eq!(code.class(), class);
        assert_eq!(code.detail(), detail);
        assert!(code.is_response());
        assert_eq!(code.registry_meta().label, label);
        assert_eq!(code.registry_meta().status, CoapRegistryStatus::Assigned);
    }

    let piggybacked = decode_coap(PIGGYBACKED_ACK_CONTENT)?;
    assert_eq!(piggybacked.options_value()[0].as_uint()?, 0);
    assert_eq!(
        piggybacked.options_value()[0].registry_meta().label,
        "Content-Format"
    );

    let separate = decode_coap(SEPARATE_CON_CHANGED)?;
    assert_eq!(separate.options_value()[0].as_opaque()?, [0x10, 0x20]);
    assert_eq!(separate.options_value()[0].registry_meta().label, "ETag");

    let created = decode_coap(NON_CREATED)?;
    assert_eq!(created.options_value()[0].as_str()?, "jobs");
    assert_eq!(
        created.options_value()[0].registry_meta().label,
        "Location-Path"
    );

    let server_error = decode_coap(NON_INTERNAL_ERROR)?;
    assert_eq!(server_error.options_value()[0].as_uint()?, 0);
    assert_eq!(server_error.options_value()[1].as_uint()?, 30);
    assert_eq!(
        server_error.options_value()[1].registry_meta().label,
        "Max-Age"
    );

    Ok(())
}

#[test]
fn response_matching_fields_follow_ack_reset_and_token_rules() -> crafter::Result<()> {
    let piggybacked = decode_coap(PIGGYBACKED_ACK_CONTENT)?;
    assert_eq!(
        piggybacked.message_id_value(),
        PIGGYBACKED_REQUEST_MESSAGE_ID
    );
    assert_eq!(piggybacked.token_value().as_bytes(), PIGGYBACKED_TOKEN);

    let empty_ack = decode_coap(EMPTY_ACK)?;
    let separate = decode_coap(SEPARATE_CON_CHANGED)?;
    assert_eq!(empty_ack.message_id_value(), SEPARATE_REQUEST_MESSAGE_ID);
    assert!(empty_ack.token_value().is_empty());
    assert_ne!(separate.message_id_value(), SEPARATE_REQUEST_MESSAGE_ID);
    assert_eq!(separate.message_id_value(), SEPARATE_RESPONSE_MESSAGE_ID);
    assert_eq!(separate.token_value().as_bytes(), SEPARATE_TOKEN);

    let non_response = decode_coap(NON_CREATED)?;
    assert_ne!(non_response.message_id_value(), NON_REQUEST_MESSAGE_ID);
    assert_eq!(non_response.message_id_value(), NON_RESPONSE_MESSAGE_ID);
    assert_eq!(non_response.token_value().as_bytes(), NON_TOKEN);

    let reset = decode_coap(EMPTY_RESET)?;
    assert_eq!(reset.message_id_value(), RESET_MESSAGE_ID);
    assert!(reset.token_value().is_empty());

    Ok(())
}

#[test]
fn unknown_response_and_unusual_reset_code_pair_remain_lossless() -> crafter::Result<()> {
    let decoded = decode_coap(UNKNOWN_RESET_RESPONSE)?;
    let code = decoded.code_value();

    assert_eq!(decoded.message_type_value(), CoapMessageType::Reset);
    assert_eq!(code.wire_value(), 0x5d);
    assert_eq!(code.class(), 2);
    assert_eq!(code.detail(), 29);
    assert_eq!(code.label(), "2.29");
    assert!(code.is_response());
    assert_eq!(code.registry_meta().label, "code-2.29");
    assert_eq!(code.registry_meta().status, CoapRegistryStatus::Unassigned);
    assert_eq!(decoded.token_value().as_bytes(), [0x12, 0x34]);
    assert_recompile_equality(&decoded, UNKNOWN_RESET_RESPONSE)?;

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
