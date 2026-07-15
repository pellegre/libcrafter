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

fn block_kind() -> impl Strategy<Value = CoapBlockKind> {
    prop_oneof![Just(CoapBlockKind::Block1), Just(CoapBlockKind::Block2),]
}

fn canonical_block_number() -> impl Strategy<Value = u64> {
    prop_oneof![
        2 => Just(0),
        1 => Just(1),
        1 => Just(CoapBlock::MAX_NUMBER - 1),
        2 => Just(CoapBlock::MAX_NUMBER),
        8 => 0..=CoapBlock::MAX_NUMBER,
    ]
}

fn checked_offset_number() -> impl Strategy<Value = u64> {
    let constructor_max = u64::MAX >> 4;
    prop_oneof![
        2 => Just(0),
        1 => Just(1),
        1 => Just(CoapBlock::MAX_NUMBER),
        1 => Just(constructor_max - 1),
        2 => Just(constructor_max),
        8 => 0..=constructor_max,
    ]
}

fn bert_payload_length() -> impl Strategy<Value = usize> {
    prop_oneof![
        1 => Just(0),
        1 => Just(1),
        1 => Just(1_023),
        1 => Just(1_024),
        1 => Just(1_025),
        1 => Just(2_048),
        4 => 0usize..=4_096,
    ]
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
    fn coap_property_canonical_blocks_roundtrip_through_options_and_messages(
        kind in block_kind(),
        number in canonical_block_number(),
        more in any::<bool>(),
        szx in 0u8..=CoapBlock::BERT_SZX,
    ) {
        let block = prop_result(CoapBlock::new_for(kind, number, more, szx))?;
        let option = block.clone().into_option(kind);
        let decoded_option = prop_result(CoapBlock::try_from(&option))?;

        prop_assert_eq!(decoded_option.option_kind(), Some(kind));
        prop_assert_eq!(decoded_option.number(), number);
        prop_assert_eq!(decoded_option.more(), more);
        prop_assert_eq!(decoded_option.szx(), szx);
        prop_assert_eq!(decoded_option.raw_bytes(), block.raw_bytes());

        let message = match kind {
            CoapBlockKind::Block1 => Coap::put().message_id(0x65a1).block1(block),
            CoapBlockKind::Block2 => Coap::content().message_id(0x65a2).block2(block),
            CoapBlockKind::QBlock1 | CoapBlockKind::QBlock2 => unreachable!("generator excludes Q-Block"),
        };
        let encoded = compile(message)?;
        let decoded_message = prop_result(decode_coap(&encoded))?;
        let decoded_block = match kind {
            CoapBlockKind::Block1 => decoded_message.block1_value(),
            CoapBlockKind::Block2 => decoded_message.block2_value(),
            CoapBlockKind::QBlock1 | CoapBlockKind::QBlock2 => unreachable!("generator excludes Q-Block"),
        }
        .ok_or_else(|| TestCaseError::fail("decoded message lacks block option"))
        .and_then(prop_result)?;

        prop_assert_eq!(decoded_block, decoded_option);
        prop_assert_eq!(compile(decoded_message)?, encoded);
    }

    #[test]
    fn coap_property_checked_block_offsets_match_u64_arithmetic(
        number in checked_offset_number(),
        szx in 0u8..=CoapBlock::BERT_SZX,
    ) {
        let block = prop_result(CoapBlock::new(number, false, szx))?;
        match number.checked_mul(block.block_size()) {
            Some(expected) => prop_assert_eq!(prop_result(block.offset())?, expected),
            None => prop_assert!(block.offset().is_err()),
        }
    }

    #[test]
    fn coap_property_bert_next_offsets_are_checked_at_num_boundaries(
        number in prop::sample::select(vec![0, 1, CoapBlock::MAX_NUMBER - 1, CoapBlock::MAX_NUMBER]),
        payload_len in bert_payload_length(),
    ) {
        let block = prop_result(CoapBlock::block2(
            number,
            true,
            CoapBlock::BERT_SZX,
        ))?;
        let payload_len_u64 = payload_len as u64;
        let represented = (payload_len_u64 / CoapBlock::BERT_UNIT)
            + u64::from(payload_len_u64 % CoapBlock::BERT_UNIT != 0);
        prop_assert_eq!(prop_result(block.bert_block_count(payload_len))?, represented);

        match number.checked_add(represented).filter(|next| *next <= CoapBlock::MAX_NUMBER) {
            Some(next) => {
                prop_assert_eq!(prop_result(block.bert_next_number(payload_len))?, next);
                prop_assert_eq!(
                    prop_result(block.bert_next_offset(payload_len))?,
                    next * CoapBlock::BERT_UNIT,
                );
            }
            None => {
                prop_assert!(block.bert_next_number(payload_len).is_err());
                prop_assert!(block.bert_next_offset(payload_len).is_err());
            }
        }
    }

    #[test]
    fn coap_property_arbitrary_bounded_datagrams_never_panic(
        bytes in bounded_bytes(256),
    ) {
        let outcome = std::panic::catch_unwind(|| decode_coap(&bytes));
        prop_assert!(outcome.is_ok());
    }
}
