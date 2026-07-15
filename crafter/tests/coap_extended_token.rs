//! RFC 8974 extended-token integration coverage.
//!
//! The literal boundary vectors follow RFC 8974 Section 2.1 and Appendix A:
//! TKL 0 through 12 is direct, TKL 13 adds one byte to 13, TKL 14 adds a
//! network-order `u16` to 269, and TKL 15 is reserved. The packet envelopes
//! use documentation addresses and never send traffic.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crafter::prelude::*;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const CLIENT_PORT: u16 = 49_152;
const UNKNOWN_OPTION: u16 = 30_000;
const IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 75);
const IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 75);
const IPV6_CLIENT: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x75);
const IPV6_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x76);

fn patterned_token(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| 0x40u8.wrapping_add(index as u8))
        .collect()
}

fn compile(message: Coap) -> crafter::Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

fn prop_result<T>(result: crafter::Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

#[test]
fn direct_and_extended_boundaries_are_exact_and_round_trip() -> crafter::Result<()> {
    let cases: &[(usize, u8, &[u8])] = &[
        (0, 0, &[]),
        (COAP_MAX_TOKEN_LEN, 8, &[]),
        (COAP_MAX_TOKEN_LEN + 1, 9, &[]),
        (CoapTokenLength::DIRECT_MAX_LEN, 12, &[]),
        (CoapTokenLength::EXTENDED8_MIN_LEN, 13, &[0x00]),
        (CoapTokenLength::EXTENDED8_MAX_LEN, 13, &[0xff]),
        (CoapTokenLength::EXTENDED16_MIN_LEN, 14, &[0x00, 0x00]),
        (CoapTokenLength::MAX_LEN, 14, &[0xff, 0xff]),
    ];

    for &(token_len, nibble, extension) in cases {
        let token = patterned_token(token_len);
        let message = Coap::get()
            .confirmable()
            .message_id(0x7501)
            .token(CoapToken::from_bytes(&token));

        let mut expected = vec![0x40 | nibble, 0x01, 0x75, 0x01];
        expected.extend_from_slice(extension);
        expected.extend_from_slice(&token);

        let encoded = compile(message.clone())?;
        assert_eq!(encoded, expected, "token length {token_len}");
        assert_eq!(
            message.encoded_len(),
            expected.len(),
            "token length {token_len}"
        );

        let metadata = message.token_length_value()?;
        assert_eq!(metadata.nibble(), nibble, "token length {token_len}");
        assert_eq!(
            metadata.extension_bytes(),
            extension,
            "token length {token_len}"
        );
        assert_eq!(
            metadata.declared_len(),
            token_len,
            "token length {token_len}"
        );
        assert_eq!(metadata.wire_len()?, token_len, "token length {token_len}");

        let decoded = decode_coap(&encoded)?;
        assert_eq!(
            decoded.token_value().as_bytes(),
            token,
            "token length {token_len}"
        );
        assert_eq!(
            decoded.token_length_value()?,
            metadata,
            "token length {token_len}"
        );
        assert_eq!(compile(decoded)?, encoded, "token length {token_len}");
    }

    Ok(())
}

#[test]
fn long_token_requests_and_responses_keep_following_unknown_options() -> crafter::Result<()> {
    let cases = [
        (
            "request",
            Coap::get().confirmable().message_id(0x7502),
            CoapTokenLength::EXTENDED8_MIN_LEN,
            0x4d,
            vec![0x00],
            0x01,
        ),
        (
            "response",
            Coap::response(CoapCode::content())
                .acknowledgement()
                .message_id(0x7503),
            CoapTokenLength::EXTENDED16_MIN_LEN,
            0x6e,
            vec![0x00, 0x00],
            0x45,
        ),
    ];

    for (name, message, token_len, first, extension, code) in cases {
        let token = patterned_token(token_len);
        let message = message
            .token(CoapToken::from_bytes(&token))
            .option(CoapOption::new(UNKNOWN_OPTION, vec![0xde, 0xad]));

        let mut expected = vec![
            first,
            code,
            0x75,
            if name == "request" { 0x02 } else { 0x03 },
        ];
        expected.extend_from_slice(&extension);
        expected.extend_from_slice(&token);
        // Option 30000 uses delta nibble 14 and 30000 - 269 = 0x7423.
        expected.extend_from_slice(&[0xe2, 0x74, 0x23, 0xde, 0xad]);

        let encoded = compile(message)?;
        assert_eq!(encoded, expected, "{name}");

        let decoded = Coap::decode(&encoded)?;
        assert_eq!(decoded.token_value().as_bytes(), token, "{name}");
        assert_eq!(decoded.options_value().len(), 1, "{name}");
        assert_eq!(
            decoded.options_value()[0].number().value(),
            UNKNOWN_OPTION,
            "{name}"
        );
        assert_eq!(decoded.options_value()[0].value(), [0xde, 0xad], "{name}");
        assert_eq!(
            decoded.options_value()[0].registry_meta().status,
            CoapRegistryStatus::Unassigned,
            "{name}"
        );
        assert_eq!(compile(decoded)?, encoded, "{name}");
    }

    Ok(())
}

#[test]
fn extended_tokens_compose_in_ipv4_and_ipv6_udp_stacks_with_autofill() -> crafter::Result<()> {
    let request_token = patterned_token(CoapTokenLength::EXTENDED8_MIN_LEN);
    let request = Coap::get()
        .confirmable()
        .message_id(0x7504)
        .token(CoapToken::from_bytes(&request_token));
    let request_coap_len = COAP_HEADER_LEN + 1 + request_token.len();
    let request_udp_len = UDP_HEADER_LEN + request_coap_len;
    let request_total_len = IPV4_HEADER_LEN + request_udp_len;
    let request_packet = Ipv4::with_addresses(IPV4_CLIENT, IPV4_SERVER)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / request;

    let request_bytes = request_packet.compile()?.into_bytes();
    assert_eq!(request_bytes.len(), request_total_len);
    assert_eq!(
        &request_bytes[2..4],
        &(request_total_len as u16).to_be_bytes()
    );
    assert_eq!(
        &request_bytes[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 6],
        &(request_udp_len as u16).to_be_bytes()
    );
    assert_eq!(request_bytes[IPV4_HEADER_LEN + UDP_HEADER_LEN], 0x4d);
    assert_eq!(
        request_bytes[IPV4_HEADER_LEN + UDP_HEADER_LEN + COAP_HEADER_LEN],
        0x00
    );

    let decoded_request = Packet::decode_from_l3(NetworkLayer::Ipv4, &request_bytes)?;
    let decoded_request_udp = decoded_request.layer::<Udp>().expect("decoded request UDP");
    let decoded_request_coap = decoded_request
        .layer::<Coap>()
        .expect("decoded extended-token request");
    assert_eq!(
        decoded_request_udp.length_value(),
        Some(request_udp_len as u16)
    );
    assert_eq!(
        decoded_request_udp.checksum_status(),
        UdpChecksumStatus::Valid
    );
    assert_eq!(decoded_request_coap.token_value().as_bytes(), request_token);
    assert_eq!(
        decoded_request_coap.token_length_value()?.extension_bytes(),
        [0x00]
    );

    let response_token = patterned_token(CoapTokenLength::EXTENDED16_MIN_LEN);
    let response = Coap::response(CoapCode::content())
        .acknowledgement()
        .message_id(0x7504)
        .token(CoapToken::from_bytes(&response_token));
    let response_coap_len = COAP_HEADER_LEN + 2 + response_token.len();
    let response_udp_len = UDP_HEADER_LEN + response_coap_len;
    let response_packet = Ipv6::with_addresses(IPV6_SERVER, IPV6_CLIENT)
        / Udp::new().sport(COAP_PORT).dport(CLIENT_PORT)
        / response;

    let response_bytes = response_packet.compile()?.into_bytes();
    assert_eq!(response_bytes.len(), IPV6_HEADER_LEN + response_udp_len);
    assert_eq!(
        &response_bytes[4..6],
        &(response_udp_len as u16).to_be_bytes()
    );
    assert_eq!(
        &response_bytes[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 6],
        &(response_udp_len as u16).to_be_bytes()
    );
    assert_eq!(response_bytes[IPV6_HEADER_LEN + UDP_HEADER_LEN], 0x6e);
    assert_eq!(
        &response_bytes[IPV6_HEADER_LEN + UDP_HEADER_LEN + COAP_HEADER_LEN
            ..IPV6_HEADER_LEN + UDP_HEADER_LEN + COAP_HEADER_LEN + 2],
        &[0x00, 0x00]
    );

    let decoded_response = Packet::decode_from_l3(NetworkLayer::Ipv6, &response_bytes)?;
    let decoded_response_udp = decoded_response
        .layer::<Udp>()
        .expect("decoded response UDP");
    let decoded_response_coap = decoded_response
        .layer::<Coap>()
        .expect("decoded extended-token response");
    assert_eq!(
        decoded_response_udp.length_value(),
        Some(response_udp_len as u16)
    );
    assert_eq!(
        decoded_response_udp.checksum_status(),
        UdpChecksumStatus::Valid
    );
    assert_eq!(
        decoded_response_coap.token_value().as_bytes(),
        response_token
    );
    assert_eq!(
        decoded_response_coap
            .token_length_value()?
            .extension_bytes(),
        [0x00, 0x00]
    );

    Ok(())
}

#[test]
fn explicit_token_length_mismatches_compile_without_repair() -> crafter::Result<()> {
    let message = Coap::get()
        .message_id(0x7505)
        .token_length(CoapTokenLength::explicit(13, vec![0xfe, 0xed], usize::MAX))
        .token(CoapToken::from_bytes([0xaa, 0xbb]));

    let encoded = compile(message.clone())?;
    assert_eq!(encoded, [0x4d, 0x01, 0x75, 0x05, 0xfe, 0xed, 0xaa, 0xbb]);
    assert!(message
        .summary()
        .contains("explicit-mismatch:nibble=13,actual=2"));
    assert!(message
        .validate()
        .issues()
        .iter()
        .any(|issue| issue.field() == "coap.token-length"));

    assert_eq!(
        Coap::decode(&encoded),
        Err(CrafterError::buffer_too_short("coap.token", 267, 3))
    );
    Ok(())
}

#[test]
fn extended_token_truncations_are_structured_and_panic_free() {
    let mut truncated_extended8_token = vec![0x4d, 0x01, 0x75, 0x06, 0x00];
    truncated_extended8_token.extend_from_slice(&[0xa5; 12]);

    let mut truncated_extended16_token = vec![0x4e, 0x01, 0x75, 0x07, 0x00, 0x00];
    truncated_extended16_token.extend_from_slice(&[0xa5; 268]);

    let cases = [
        (
            "missing-extended8-byte",
            vec![0x4d, 0x01, 0x75, 0x06],
            CrafterError::buffer_too_short("coap.token-length.extended8", 1, 0),
        ),
        (
            "short-extended16-bytes",
            vec![0x4e, 0x01, 0x75, 0x07, 0x00],
            CrafterError::buffer_too_short("coap.token-length.extended16", 2, 1),
        ),
        (
            "short-extended8-token",
            truncated_extended8_token,
            CrafterError::buffer_too_short("coap.token", 13, 12),
        ),
        (
            "short-extended16-token",
            truncated_extended16_token,
            CrafterError::buffer_too_short("coap.token", 269, 268),
        ),
    ];

    for (name, bytes, expected) in cases {
        let outcome = catch_unwind(AssertUnwindSafe(|| decode_coap(&bytes)));
        assert!(outcome.is_ok(), "{name} panicked");
        assert_eq!(outcome.expect("checked above"), Err(expected), "{name}");
    }

    let reserved = catch_unwind(|| Coap::decode(&[0x4f, 0x01, 0x75, 0x08]));
    assert!(reserved.is_ok(), "reserved TKL decode panicked");
    assert_eq!(
        reserved.expect("checked above"),
        Err(CrafterError::invalid_field_value(
            "coap.token-length",
            "reserved TKL encoding 15",
        ))
    );
}

#[test]
fn extended_token_summary_and_show_are_bounded_and_deterministic() {
    let packet = Packet::from_layer(
        Coap::get()
            .confirmable()
            .message_id(0x7509)
            .token(CoapToken::from_bytes([0xa5; 13])),
    );

    assert_eq!(
        packet.summary(),
        "Coap(version=1, type=confirmable, code=0.01(GET), mid=0x7509, token_len=13, options=0, marker=absent, payload=0 bytes)"
    );
    assert_eq!(
        packet.show(),
        "Packet(len=18, layers=1)\n  [0] Coap\n      version: 1\n      type: confirmable\n      token_length: 13\n      code: 0.01(GET)\n      message_id: 0x7509\n      token: len=13 hex=a5a5a5a5a5a5a5a5a5a5a5a5a5\n      options: 0 []\n      payload_marker: absent\n      payload_length: 0"
    );

    let maximum = Packet::from_layer(
        Coap::get().token(CoapToken::from_bytes(vec![0x7e; CoapTokenLength::MAX_LEN])),
    );
    assert!(maximum
        .show()
        .contains("token: len=65804 hex=7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e...(+65788 bytes)"));
}

#[test]
fn public_token_metadata_matches_reliable_token_boundaries() -> crafter::Result<()> {
    // RFC 8974 Appendix A places the same extension bytes after the Code in
    // reliable messages. The complete public CoapReliable layer is added by
    // later plan steps; this locks the shared public boundary metadata now.
    let cases: &[(usize, u8, &[u8])] = &[
        (13, 13, &[0x00]),
        (268, 13, &[0xff]),
        (269, 14, &[0x00, 0x00]),
        (CoapTokenLength::MAX_LEN, 14, &[0xff, 0xff]),
    ];

    for &(token_len, nibble, extension) in cases {
        let metadata = CoapTokenLength::canonical_for_len(token_len)?;
        let token = vec![0xa5; token_len];
        let mut bytes_after_reliable_header = vec![0x01];
        bytes_after_reliable_header.extend_from_slice(metadata.extension_bytes());
        bytes_after_reliable_header.extend_from_slice(&token);
        bytes_after_reliable_header.extend_from_slice(&[0xb1, b'x']);

        let option_offset = 1 + metadata.encoding()?.extension_len() + metadata.wire_len()?;
        assert_eq!(metadata.nibble(), nibble);
        assert_eq!(metadata.extension_bytes(), extension);
        assert_eq!(
            &bytes_after_reliable_header[1..1 + extension.len()],
            extension
        );
        assert_eq!(
            &bytes_after_reliable_header[1 + extension.len()..option_offset],
            token
        );
        assert_eq!(&bytes_after_reliable_header[option_offset..], &[0xb1, b'x']);
    }

    Ok(())
}

#[test]
fn base_token_constructor_and_golden_bytes_remain_unchanged() -> crafter::Result<()> {
    assert_eq!(CoapToken::new([])?.len(), 0);
    assert_eq!(CoapToken::new([0u8; COAP_MAX_TOKEN_LEN])?.len(), 8);
    assert_eq!(
        CoapToken::new([0u8; COAP_MAX_TOKEN_LEN + 1]),
        Err(CrafterError::invalid_field_value(
            "coap.token-length",
            "base CoAP tokens must be at most 8 bytes",
        ))
    );

    let golden = Coap::get()
        .confirmable()
        .message_id(0x1234)
        .token(CoapToken::new([0xaa, 0xbb])?);
    assert_eq!(compile(golden)?, [0x42, 0x01, 0x12, 0x34, 0xaa, 0xbb]);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn bounded_extended_token_lengths_round_trip_without_panics(
        token_len in 9usize..=1_024,
        seed in any::<u8>(),
        response in any::<bool>(),
    ) {
        let token = (0..token_len)
            .map(|index| seed.wrapping_add(index as u8))
            .collect::<Vec<_>>();
        let message = if response {
            Coap::response(CoapCode::content()).acknowledgement()
        } else {
            Coap::get().confirmable()
        }
        .message_id(0x7510)
        .token(CoapToken::from_bytes(&token));

        let metadata = prop_result(message.token_length_value())?;
        let encoded = prop_result(Packet::from_layer(message).compile())?.into_bytes();
        prop_assert_eq!(encoded[0] & COAP_TKL_MASK, metadata.nibble());
        prop_assert_eq!(
            &encoded[COAP_HEADER_LEN..COAP_HEADER_LEN + metadata.extension_bytes().len()],
            metadata.extension_bytes()
        );

        let outcome = catch_unwind(AssertUnwindSafe(|| decode_coap(&encoded)));
        prop_assert!(outcome.is_ok());
        let decoded = prop_result(outcome.expect("checked above"))?;
        prop_assert_eq!(decoded.token_value().as_bytes(), token.as_slice());
        prop_assert_eq!(prop_result(decoded.token_length_value())?.wire_len(), Ok(token_len));
        let recompiled = prop_result(Packet::from_layer(decoded).compile())?;
        prop_assert_eq!(recompiled.as_bytes(), encoded.as_slice());
    }
}
