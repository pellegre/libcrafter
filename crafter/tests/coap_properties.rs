//! Bounded property coverage for CoAP datagram messages and options.
//!
//! Canonical round trips and explicit malformed overrides use separate
//! generators so preservation guarantees do not blur structural validity.

use crafter::prelude::*;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

#[derive(Clone, Debug)]
struct MessageCase {
    message_type: CoapMessageType,
    code: CoapCode,
    message_id: u16,
    token: Vec<u8>,
    options: Vec<(u16, Vec<u8>)>,
    payload: Vec<u8>,
}

fn prop_result<T>(result: crafter::Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn compile(message: Coap) -> std::result::Result<Vec<u8>, TestCaseError> {
    Ok(prop_result(Packet::from_layer(message).compile())?
        .as_bytes()
        .to_vec())
}

fn bounded_bytes(max_len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max_len)
}

fn option_delta() -> impl Strategy<Value = u16> {
    prop_oneof![
        3 => Just(0),
        1 => Just(1),
        1 => Just(12),
        1 => Just(13),
        1 => Just(268),
        1 => Just(269),
        4 => 0u16..=1_024,
    ]
}

fn boundary_delta() -> impl Strategy<Value = u16> {
    prop::sample::select(vec![0, 1, 12, 13, 268, 269, 1_024])
}

fn option_value() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        1 => Just(Vec::new()),
        1 => prop::collection::vec(any::<u8>(), 1..=1),
        1 => prop::collection::vec(any::<u8>(), 12..=12),
        1 => prop::collection::vec(any::<u8>(), 13..=13),
        1 => prop::collection::vec(any::<u8>(), 268..=268),
        1 => prop::collection::vec(any::<u8>(), 269..=269),
        6 => bounded_bytes(48),
    ]
}

fn boundary_value() -> impl Strategy<Value = Vec<u8>> {
    prop::sample::select(vec![0usize, 1, 12, 13, 268, 269])
        .prop_flat_map(|len| prop::collection::vec(any::<u8>(), len..=len))
}

fn monotonic_options() -> impl Strategy<Value = Vec<(u16, Vec<u8>)>> {
    prop::collection::vec((option_delta(), option_value()), 0..=6).prop_map(|entries| {
        let mut number = 0u16;
        entries
            .into_iter()
            .map(|(delta, value)| {
                number = number
                    .checked_add(delta)
                    .expect("bounded option deltas fit in u16");
                (number, value)
            })
            .collect()
    })
}

fn message_case() -> impl Strategy<Value = MessageCase> {
    (
        0u8..=3,
        any::<u8>().prop_filter("Empty messages have their own grammar", |code| *code != 0),
        any::<u16>(),
        bounded_bytes(COAP_MAX_TOKEN_LEN),
        monotonic_options(),
        bounded_bytes(64),
    )
        .prop_map(
            |(message_type, code, message_id, token, options, payload)| MessageCase {
                message_type: CoapMessageType::from_wire(message_type),
                code: CoapCode::from_wire(code),
                message_id,
                token,
                options,
                payload,
            },
        )
}

fn build_message(case: &MessageCase) -> Coap {
    Coap::request(case.code)
        .message_type(case.message_type)
        .message_id(case.message_id)
        .token(CoapToken::from_bytes(&case.token))
        .options(
            case.options
                .iter()
                .map(|(number, value)| CoapOption::new(*number, value.clone())),
        )
        .payload(case.payload.clone())
}

fn assert_decoded_options(
    actual: &[CoapOption],
    expected: &[(u16, Vec<u8>)],
) -> std::result::Result<(), TestCaseError> {
    prop_assert_eq!(actual.len(), expected.len());

    let mut previous = 0u16;
    for (decoded, (expected_number, expected_value)) in actual.iter().zip(expected) {
        prop_assert!(*expected_number >= previous);
        prop_assert_eq!(decoded.number().value(), *expected_number);
        prop_assert_eq!(decoded.value(), expected_value.as_slice());

        let encoding = decoded
            .encoding()
            .ok_or_else(|| TestCaseError::fail("decoded option lacks wire metadata"))?;
        prop_assert_eq!(
            encoding.wire_delta(),
            Some(u32::from(*expected_number - previous))
        );
        prop_assert_eq!(encoding.wire_length(), Some(expected_value.len()));
        prop_assert!(encoding.raw_bytes().is_some());
        previous = *expected_number;
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn coap_property_canonical_messages_roundtrip_byte_exact(case in message_case()) {
        let encoded = compile(build_message(&case))?;
        let decoded = prop_result(decode_coap(&encoded))?;

        prop_assert_eq!(decoded.version_value(), CoapVersion::current());
        prop_assert_eq!(decoded.message_type_value(), case.message_type);
        prop_assert_eq!(decoded.code_value(), case.code);
        prop_assert_eq!(decoded.message_id_value(), case.message_id);
        prop_assert_eq!(decoded.token_value().as_bytes(), case.token.as_slice());
        prop_assert_eq!(
            prop_result(decoded.token_length_value())?.declared_len(),
            case.token.len()
        );
        assert_decoded_options(decoded.options_value(), &case.options)?;
        prop_assert_eq!(decoded.payload_value(), case.payload.as_slice());
        prop_assert_eq!(
            decoded.payload_marker_value(),
            if case.payload.is_empty() {
                CoapPayloadMarker::Absent
            } else {
                CoapPayloadMarker::Present
            }
        );

        prop_assert_eq!(compile(decoded)?, encoded);
    }

    #[test]
    fn coap_property_boundary_delta_and_length_forms_roundtrip(
        delta in boundary_delta(),
        value in boundary_value(),
    ) {
        let expected = vec![(delta, value.clone())];
        let message = Coap::get()
            .message_id(0x3901)
            .option(CoapOption::new(delta, value));

        let encoded = compile(message)?;
        let decoded = prop_result(decode_coap(&encoded))?;
        assert_decoded_options(decoded.options_value(), &expected)?;
        prop_assert_eq!(compile(decoded)?, encoded);
    }

    #[test]
    fn coap_property_repeated_options_preserve_occurrence_order(
        number in 0u16..=4_096,
        first in option_value(),
        second in option_value(),
    ) {
        let expected = vec![(number, first.clone()), (number, second.clone())];
        let message = Coap::get()
            .message_id(0x3902)
            .option(CoapOption::new(number, first))
            .option(CoapOption::new(number, second));

        let encoded = compile(message)?;
        let decoded = prop_result(decode_coap(&encoded))?;
        assert_decoded_options(decoded.options_value(), &expected)?;
        prop_assert_eq!(compile(decoded)?, encoded);
    }

    #[test]
    fn coap_property_explicit_delta_overrides_are_authoritative(
        (logical_number, wire_delta, value) in
            (0u16..=4_096, boundary_delta(), bounded_bytes(48))
                .prop_filter("override differs from the typed option number", |(number, delta, _)| number != delta),
    ) {
        let message = Coap::get()
            .message_id(0x3903)
            .option(
                CoapOption::new(logical_number, value.clone())
                    .with_wire_delta(u32::from(wire_delta)),
            );

        let encoded = compile(message)?;
        let decoded = prop_result(decode_coap(&encoded))?;
        prop_assert_eq!(decoded.options_value().len(), 1);
        prop_assert_eq!(decoded.options_value()[0].number().value(), wire_delta);
        prop_assert_eq!(decoded.options_value()[0].value(), value.as_slice());
        prop_assert_eq!(compile(decoded)?, encoded);
    }

    #[test]
    fn coap_property_explicit_token_length_mismatches_compile_unchanged(
        (declared_len, token) in (0u8..=8, bounded_bytes(COAP_MAX_TOKEN_LEN))
            .prop_filter("token length override is intentionally malformed", |(declared, token)| usize::from(*declared) != token.len()),
    ) {
        let encoded = compile(
            Coap::get()
                .message_id(0x3904)
                .token_length(CoapTokenLength::explicit(
                    declared_len,
                    Vec::new(),
                    usize::from(declared_len),
                ))
                .token(CoapToken::from_bytes(&token)),
        )?;

        prop_assert_eq!(encoded[0] & COAP_TKL_MASK, declared_len);
        prop_assert_eq!(&encoded[4..], token.as_slice());
    }

    #[test]
    fn coap_property_arbitrary_bounded_datagrams_never_panic(
        bytes in bounded_bytes(256),
    ) {
        let outcome = std::panic::catch_unwind(|| decode_coap(&bytes));
        prop_assert!(outcome.is_ok());
    }
}
