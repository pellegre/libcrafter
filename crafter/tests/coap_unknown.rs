//! Lossless unknown-value and explicit-override coverage for CoAP datagrams.
//!
//! RFC 7252 makes unknown Code and Option values structurally representable,
//! while the crate contract permits callers to emit intentionally malformed
//! dependent fields. These tests keep both paths byte-exact and offline.

use crafter::prelude::*;

const UNKNOWN_CODE: u8 = 0x1f;
const UNKNOWN_OPTION: u16 = 1_234;
const UNASSIGNED_CONTENT_FORMAT: u64 = 12_345;

fn compile(message: Coap) -> Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.as_bytes().to_vec())
}

#[test]
fn unknown_values_unusual_version_and_repeated_options_round_trip() -> Result<()> {
    // Independently derived option headers:
    // Content-Format 12 is delta 12/length 2 => c2.
    // Option 1234 follows 12, so delta 1222 uses 14 + (1222 - 269) => e2 03b9.
    // The repeated Option 1234 has delta 0/length 1 => 01.
    const EXPECTED: &[u8] = &[
        0x92,
        UNKNOWN_CODE,
        0xa1,
        0xb2,
        0xde,
        0xad,
        0xc2,
        0x30,
        0x39,
        0xe2,
        0x03,
        0xb9,
        0x00,
        0xff,
        0x01,
        0x80,
        0xff,
        0xfa,
        0x00,
    ];

    let message = Coap::request(CoapCode::from_wire(UNKNOWN_CODE))
        .version(CoapVersion::from_wire(2))
        .non_confirmable()
        .message_id(0xa1b2)
        .token(CoapToken::from_bytes([0xde, 0xad]))
        .option(CoapOption::from_uint(
            COAP_OPTION_CONTENT_FORMAT,
            UNASSIGNED_CONTENT_FORMAT,
        ))
        .option(CoapOption::new(UNKNOWN_OPTION, [0x00, 0xff]))
        .option(CoapOption::new(UNKNOWN_OPTION, [0x80]))
        .payload([0xfa, 0x00]);

    assert_eq!(compile(message)?, EXPECTED);

    let decoded = decode_coap(EXPECTED)?;
    assert_eq!(decoded.version_value(), CoapVersion::from_wire(2));
    assert_eq!(decoded.code_value(), CoapCode::from_wire(UNKNOWN_CODE));
    assert_eq!(decoded.token_value().as_bytes(), [0xde, 0xad]);
    assert_eq!(decoded.options_value().len(), 3);
    assert_eq!(
        decoded.options_value()[0].as_uint()?,
        UNASSIGNED_CONTENT_FORMAT
    );
    assert_eq!(decoded.options_value()[1].number().value(), UNKNOWN_OPTION);
    assert_eq!(decoded.options_value()[1].value(), [0x00, 0xff]);
    assert_eq!(decoded.options_value()[2].number().value(), UNKNOWN_OPTION);
    assert_eq!(decoded.options_value()[2].value(), [0x80]);
    assert_eq!(decoded.payload_value(), [0xfa, 0x00]);
    assert_eq!(compile(decoded.clone())?, EXPECTED);

    let content_format = coap_content_format_meta(UNASSIGNED_CONTENT_FORMAT);
    assert_eq!(content_format.value, UNASSIGNED_CONTENT_FORMAT);
    assert_eq!(content_format.label, "content-format-12345");
    assert_eq!(content_format.status, CoapRegistryStatus::Unassigned);

    let packet = Packet::from_layer(decoded);
    let summary = packet.summary();
    assert!(
        summary.contains("version=2 [explicit-noncurrent]"),
        "{summary}"
    );
    assert!(summary.contains("code=0.31(code-0.31)"), "{summary}");

    let show = packet.show();
    assert!(show.contains("version: 2 [explicit-noncurrent]"), "{show}");
    assert!(show.contains("code: 0.31(code-0.31)"), "{show}");
    assert!(show.contains("option-1234(1234"), "{show}");

    Ok(())
}

#[test]
fn explicit_token_length_and_payload_marker_mismatches_are_byte_exact() -> Result<()> {
    let token_mismatch = Coap::get()
        .message_id(0x1010)
        .token_length(CoapTokenLength::explicit(1, Vec::new(), 1))
        .token(CoapToken::from_bytes([0xaa, 0xbb]));
    let token_packet = Packet::from_layer(token_mismatch);
    assert_eq!(
        token_packet.compile()?.as_bytes(),
        &[0x41, 0x01, 0x10, 0x10, 0xaa, 0xbb]
    );
    assert!(token_packet
        .summary()
        .contains("token_len=1 [explicit-mismatch:nibble=1,actual=2]"));

    let marker_without_payload = Coap::get()
        .message_id(0x2020)
        .payload_marker(CoapPayloadMarker::Present);
    let marker_packet = Packet::from_layer(marker_without_payload);
    assert_eq!(
        marker_packet.compile()?.as_bytes(),
        &[0x40, 0x01, 0x20, 0x20, 0xff]
    );
    assert!(marker_packet
        .summary()
        .contains("marker=present [explicit-mismatch]"));

    let payload_without_marker = Coap::get()
        .message_id(0x2021)
        .payload_marker(CoapPayloadMarker::Absent)
        .payload(b"ok".to_vec());
    let payload_packet = Packet::from_layer(payload_without_marker);
    assert_eq!(
        payload_packet.compile()?.as_bytes(),
        &[0x40, 0x01, 0x20, 0x21, b'o', b'k']
    );
    assert!(payload_packet
        .show()
        .contains("payload_marker: absent [explicit-mismatch]"));

    Ok(())
}

#[test]
fn raw_option_extensions_and_out_of_order_overrides_are_byte_exact() -> Result<()> {
    let raw_extension = Coap::get().message_id(0x3030).option(
        CoapOption::new(1u16, [0xaa])
            .with_encoding(CoapOptionEncoding::from_raw_bytes([0xd1, 0x00])),
    );
    let raw_packet = Packet::from_layer(raw_extension);
    assert_eq!(
        raw_packet.compile()?.as_bytes(),
        &[0x40, 0x01, 0x30, 0x30, 0xd1, 0x00, 0xaa]
    );
    assert!(raw_packet
        .summary()
        .contains("options=1 [malformed-override]"));

    let out_of_order = Coap::get()
        .message_id(0x3031)
        .option_order(CoapOptionOrder::Wire)
        .option(CoapOption::new(20u16, [0xaa]))
        .option(CoapOption::new(4u16, [0xbb]).with_wire_delta(0));
    let out_of_order_packet = Packet::from_layer(out_of_order);
    assert_eq!(
        out_of_order_packet.compile()?.as_bytes(),
        &[0x40, 0x01, 0x30, 0x31, 0xd1, 0x07, 0xaa, 0x01, 0xbb]
    );
    assert!(out_of_order_packet
        .show()
        .contains("options: 2 [Location-Query(20"));
    assert!(out_of_order_packet.show().contains("[malformed-override]"));

    Ok(())
}

#[test]
fn unset_dependent_fields_compile_to_canonical_wire_values() -> Result<()> {
    const EXPECTED: &[u8] = &[
        0x40, 0x01, 0x40, 0x40, 0xb1, b'x', 0x95, b'l', b'a', b't', b'e', b'r', 0xff, b'o', b'k',
    ];

    let message = Coap::get()
        .message_id(0x4040)
        .option(CoapOption::new(20u16, b"later".to_vec()))
        .option(CoapOption::new(COAP_OPTION_URI_PATH, b"x".to_vec()))
        .payload(b"ok".to_vec());

    assert_eq!(compile(message)?, EXPECTED);

    let decoded = decode_coap(EXPECTED)?;
    assert_eq!(decoded.version_value(), CoapVersion::current());
    assert_eq!(decoded.message_type_value(), CoapMessageType::Confirmable);
    assert_eq!(decoded.token_length_value()?.declared_len(), 0);
    assert_eq!(decoded.options_value()[0].number().value(), 11);
    assert_eq!(decoded.options_value()[1].number().value(), 20);
    assert_eq!(decoded.payload_marker_value(), CoapPayloadMarker::Present);
    assert_eq!(compile(decoded)?, EXPECTED);

    Ok(())
}
