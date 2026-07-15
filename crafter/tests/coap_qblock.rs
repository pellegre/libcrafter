//! RFC 9177 Q-Block integration coverage through public APIs.
//!
//! These tests cover packet-local metadata and arithmetic only. Burst pacing,
//! recovery scheduling, congestion control, and body reassembly remain caller
//! responsibilities.

use crafter::prelude::*;
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

fn compile_coap(message: Coap) -> Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

fn prop_result<T>(result: crafter::Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

#[test]
fn qblock1_first_middle_final_and_continue_are_byte_exact() -> Result<()> {
    // RFC 9177 Sections 3.2 and 4.2: every Q-Block1 payload carries the
    // transfer's Request-Tag and Size1 while NUM/M/SZX advances independently.
    let cases = [
        (0u16, 0u64, true, vec![0x11; 16], 0x08u8, 0u64),
        (1u16, 1u64, true, vec![0x22; 16], 0x18u8, 16u64),
        (2u16, 2u64, false, vec![0x33; 4], 0x20u8, 32u64),
    ];

    for (mid_delta, number, more, payload, raw_block, expected_offset) in cases {
        let message_id = 0x7200 + mid_delta;
        let message = Coap::put()
            .message_id(message_id)
            .token(CoapToken::from_bytes([0xa1]))
            .qblock1_request_fragment(
                CoapBlock::qblock1(number, more, 0)?,
                payload.clone(),
                CoapRequestTag::try_new([0x44])?,
                CoapSize1::new(36),
            );

        let mut expected = vec![
            0x41,
            0x03,
            (message_id >> 8) as u8,
            message_id as u8,
            0xa1, // CON, PUT, MID, token.
            0xd1,
            0x06,
            raw_block, // Q-Block1 (option 19).
            0xd1,
            0x1c,
            0x24, // Size1 36 (option 60).
            0xd1,
            0xdb,
            0x44, // Request-Tag (option 292).
            COAP_PAYLOAD_MARKER,
        ];
        expected.extend_from_slice(&payload);

        assert_eq!(compile_coap(message.clone())?, expected);
        assert!(message.validate().is_clean());
        assert!(message
            .qblock1_validation(CoapBlockTransport::Datagram)
            .expect("Q-Block1 option")?
            .is_valid());

        let decoded = decode_coap(&expected)?;
        let block = decoded.qblock1_value().expect("Q-Block1 option")?;
        assert_eq!(block.option_kind(), Some(CoapBlockKind::QBlock1));
        assert_eq!(block.raw_bytes(), &[raw_block]);
        assert_eq!(block.number(), number);
        assert_eq!(block.more(), more);
        assert_eq!(block.szx(), 0);
        assert_eq!(block.offset()?, expected_offset);
        assert_eq!(
            decoded
                .request_tag_value()
                .expect("Request-Tag option")?
                .as_bytes(),
            [0x44]
        );
        assert_eq!(decoded.size1_value().expect("Size1 option")?.value(), 36);
        assert_eq!(compile_coap(decoded)?, expected);
    }

    let continued = Coap::qblock1_continue(CoapBlock::qblock1(1, true, 0)?)
        .acknowledgement()
        .message_id(0x7201)
        .token(CoapToken::from_bytes([0xa1]));
    let continued_bytes = [
        0x61, 0x5f, 0x72, 0x01, 0xa1, // ACK, 2.31 Continue, MID, token.
        0xd1, 0x06, 0x18, // Q-Block1 1/1/16.
    ];
    assert_eq!(compile_coap(continued.clone())?, continued_bytes);
    assert!(continued.validate().is_clean());
    assert!(continued
        .qblock1_validation(CoapBlockTransport::Datagram)
        .expect("Q-Block1 option")?
        .is_valid());
    assert_eq!(
        compile_coap(decode_coap(&continued_bytes)?)?,
        continued_bytes
    );

    Ok(())
}

#[test]
fn qblock2_request_range_response_size_and_inspection_are_typed() -> Result<()> {
    // RFC 9177 Section 4.4: M=1 at a set boundary requests the remainder of
    // that MAX_PAYLOADS_SET. The response may negotiate a smaller SZX.
    let requested = CoapBlock::qblock2(10, true, 2)?;
    let request = Coap::get()
        .message_id(0x7300)
        .token(CoapToken::from_bytes([0xb2]))
        .qblock2_request_selection(requested.clone());
    let request_bytes = [
        0x41, 0x01, 0x73, 0x00, 0xb2, // CON, GET, MID, token.
        0xd1, 0x12, 0xaa, // Q-Block2 10/1/64.
    ];
    assert_eq!(compile_coap(request.clone())?, request_bytes);
    assert_eq!(requested.qblock2_request_range(10)?, (10, 19));
    assert!(requested.is_qblock2_continue(10)?);
    assert_eq!(request.qblock2_offset().expect("Q-Block2 option")?, 640);
    assert!(request
        .qblock2_validation(CoapBlockTransport::Datagram, None, 10)
        .expect("Q-Block2 option")?
        .is_valid());
    assert_eq!(compile_coap(decode_coap(&request_bytes)?)?, request_bytes);

    let response = Coap::content()
        .acknowledgement()
        .message_id(0x7300)
        .token(CoapToken::from_bytes([0xb2]))
        .qblock2_response_fragment(
            CoapBlock::qblock2(15, true, 1)?,
            vec![0x6b; 32],
            CoapEtag::try_new([0xde, 0xad])?,
            CoapSize2::new(700),
        );
    let mut response_bytes = vec![
        0x61,
        0x45,
        0x73,
        0x00,
        0xb2, // ACK, 2.05 Content, MID, token.
        0x42,
        0xde,
        0xad, // ETag.
        0xd2,
        0x0b,
        0x02,
        0xbc, // Size2 700.
        0x31,
        0xf9, // Q-Block2 15/1/32.
        COAP_PAYLOAD_MARKER,
    ];
    response_bytes.extend_from_slice(&[0x6b; 32]);
    assert_eq!(compile_coap(response.clone())?, response_bytes);
    assert!(response.validate().is_clean());
    assert!(response
        .qblock2_validation(CoapBlockTransport::Datagram, Some(&requested), 10)
        .expect("Q-Block2 option")?
        .is_valid());

    let decoded = decode_coap(&response_bytes)?;
    let returned = decoded.qblock2_value().expect("Q-Block2 option")?;
    assert_eq!(returned.option_kind(), Some(CoapBlockKind::QBlock2));
    assert_eq!(returned.number(), 15);
    assert!(returned.more());
    assert_eq!(returned.szx(), 1);
    assert_eq!(returned.block_size(), 32);
    assert_eq!(returned.offset()?, 480);
    assert_eq!(
        decoded.etag_value().expect("ETag option")?.as_bytes(),
        [0xde, 0xad]
    );
    assert_eq!(decoded.size2_value().expect("Size2 option")?.value(), 700);
    assert_eq!(compile_coap(decoded.clone())?, response_bytes);
    assert_eq!(
        decoded.summary(),
        "Coap(version=1, type=acknowledgement, code=2.05(Content), mid=0x7300, token_len=1, options=3, marker=present, payload=32 bytes)"
    );
    let show = Packet::from_layer(decoded).show();
    assert!(show.contains("ETag(4,len=2,hex=dead)"), "{show}");
    assert!(show.contains("Size2(28,len=2,hex=02bc)"), "{show}");
    assert!(show.contains("Q-Block2(31,len=1,hex=f9)"), "{show}");

    let outside = Coap::content().qblock2_response_fragment(
        CoapBlock::qblock2(20, true, 1)?,
        vec![0x6b; 32],
        CoapEtag::try_new([0xde, 0xad])?,
        CoapSize2::new(700),
    );
    let report = outside
        .qblock2_validation(CoapBlockTransport::Datagram, Some(&requested), 10)
        .expect("Q-Block2 option")?;
    assert!(report.issues().iter().any(|issue| matches!(
        issue,
        CrafterError::InvalidFieldValue {
            field: "coap.qblock2.response.number",
            reason: "returned Q-Block2 number is outside the requested range",
        }
    )));

    Ok(())
}

#[test]
fn missing_recovery_order_interactions_and_unknown_options_remain_inspectable() -> Result<()> {
    // Repeated Q-Block2 request options identify missing response blocks.
    let recovery = Coap::get()
        .message_id(0x7400)
        .qblock2(CoapBlock::qblock2(3, false, 0)?)
        .qblock2(CoapBlock::qblock2(7, false, 0)?);
    let recovery_bytes = [
        0x40, 0x01, 0x74, 0x00, // CON, GET, MID.
        0xd1, 0x12, 0x30, // Q-Block2 number 3.
        0x01, 0x70, // Repeated Q-Block2 number 7.
    ];
    assert_eq!(compile_coap(recovery.clone())?, recovery_bytes);
    assert!(recovery.validate().is_clean());
    let decoded_recovery = decode_coap(&recovery_bytes)?;
    assert_eq!(
        decoded_recovery
            .qblock2_values()
            .map(|value| value.map(|value| value.number()))
            .collect::<Result<Vec<_>>>()?,
        [3, 7]
    );
    assert_eq!(compile_coap(decoded_recovery)?, recovery_bytes);

    let out_of_order = Coap::get()
        .qblock2(CoapBlock::qblock2(7, false, 0)?)
        .qblock2(CoapBlock::qblock2(3, false, 0)?);
    assert!(out_of_order.validate().issues().iter().any(|issue| {
        issue.field() == "coap.options[1].value"
            && issue.category() == CoapValidationCategory::OptionOrdering
            && issue.reason() == "repeated Q-Block2 request numbers must be strictly increasing"
    }));

    let missing_metadata = Coap::put().qblock1(CoapBlock::qblock1(0, false, 0)?);
    let missing_issues = missing_metadata.validate();
    assert!(missing_issues.issues().iter().any(|issue| {
        issue.category() == CoapValidationCategory::OptionInteraction
            && issue.reason() == "Q-Block1 requests require a Request-Tag option"
    }));
    assert!(missing_issues.issues().iter().any(|issue| {
        issue.category() == CoapValidationCategory::OptionInteraction
            && issue.reason() == "Q-Block1 requests require a Size1 option"
    }));

    // Ordinary Block2, Q-Block2, and an unassigned option stay distinct and
    // byte exact even though opt-in validation reports the illegal mix.
    let mixed = Coap::get()
        .message_id(0x7401)
        .block2(CoapBlock::block2(0, false, 0)?)
        .qblock2(CoapBlock::qblock2(0, false, 0)?)
        .option(CoapOption::new(65_000, [0xde, 0xad]));
    let mixed_bytes = [
        0x40, 0x01, 0x74, 0x01, // CON, GET, MID.
        0xd0, 0x0a, // Empty Block2 (option 23).
        0x80, // Empty Q-Block2 (option 31).
        0xe2, 0xfc, 0xbc, 0xde, 0xad, // Unknown option 65000.
    ];
    assert_eq!(compile_coap(mixed.clone())?, mixed_bytes);
    assert!(mixed.validate().issues().iter().any(|issue| {
        issue.category() == CoapValidationCategory::OptionInteraction
            && issue.reason()
                == "Block and Q-Block options must not be mixed at the same protection level"
    }));

    let decoded_mixed = decode_coap(&mixed_bytes)?;
    assert_eq!(
        decoded_mixed
            .block2_value()
            .expect("Block2 option")?
            .option_kind(),
        Some(CoapBlockKind::Block2)
    );
    assert_eq!(
        decoded_mixed
            .qblock2_value()
            .expect("Q-Block2 option")?
            .option_kind(),
        Some(CoapBlockKind::QBlock2)
    );
    let unknown = decoded_mixed
        .options_value()
        .iter()
        .find(|option| option.number().value() == 65_000)
        .expect("unknown option");
    assert_eq!(unknown.value(), [0xde, 0xad]);
    assert_eq!(compile_coap(decoded_mixed.clone())?, mixed_bytes);
    let show = Packet::from_layer(decoded_mixed).show();
    assert!(show.contains("Block2(23,len=0,hex=)"), "{show}");
    assert!(show.contains("Q-Block2(31,len=0,hex=)"), "{show}");
    assert!(
        show.contains("option-65000(65000,len=2,hex=dead)"),
        "{show}"
    );

    Ok(())
}

fn qblock_kind() -> impl Strategy<Value = CoapBlockKind> {
    prop_oneof![Just(CoapBlockKind::QBlock1), Just(CoapBlockKind::QBlock2),]
}

fn canonical_qblock_number() -> impl Strategy<Value = u64> {
    prop_oneof![
        2 => Just(0),
        1 => Just(1),
        1 => Just(CoapBlock::MAX_NUMBER - 1),
        2 => Just(CoapBlock::MAX_NUMBER),
        8 => 0..=CoapBlock::MAX_NUMBER,
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn canonical_qblock_values_roundtrip_with_checked_offsets(
        kind in qblock_kind(),
        number in canonical_qblock_number(),
        more in any::<bool>(),
        szx in 0u8..=6,
    ) {
        let block = prop_result(CoapBlock::new_for(kind, number, more, szx))?;
        let expected_size = 1u64 << (szx + 4);
        prop_assert_eq!(block.block_size(), expected_size);
        prop_assert_eq!(prop_result(block.offset())?, number * expected_size);

        let option = block.clone().into_option(kind);
        let option_roundtrip = prop_result(CoapBlock::try_from(&option))?;
        prop_assert_eq!(option_roundtrip.option_kind(), Some(kind));
        prop_assert_eq!(option_roundtrip.raw_bytes(), block.raw_bytes());

        let message = match kind {
            CoapBlockKind::QBlock1 => Coap::put().message_id(0x72f1).qblock1(block),
            CoapBlockKind::QBlock2 => Coap::get().message_id(0x72f2).qblock2(block),
            CoapBlockKind::Block1 | CoapBlockKind::Block2 => unreachable!("Q-Block generator"),
        };
        let encoded = prop_result(compile_coap(message))?;
        let decoded = prop_result(decode_coap(&encoded))?;
        let decoded_block = match kind {
            CoapBlockKind::QBlock1 => decoded.qblock1_value(),
            CoapBlockKind::QBlock2 => decoded.qblock2_value(),
            CoapBlockKind::Block1 | CoapBlockKind::Block2 => unreachable!("Q-Block generator"),
        }
        .ok_or_else(|| TestCaseError::fail("decoded message lacks Q-Block option"))
        .and_then(prop_result)?;
        prop_assert_eq!(decoded_block, option_roundtrip);
        prop_assert_eq!(prop_result(compile_coap(decoded))?, encoded);
    }

    #[test]
    fn qblock_set_and_next_arithmetic_matches_bounded_integer_transitions(
        number in 0u64..CoapBlock::MAX_NUMBER,
        max_payloads in 1u64..=64,
        more in any::<bool>(),
    ) {
        let block = prop_result(CoapBlock::qblock2(number, more, 0))?;
        let expected_index = number / max_payloads;
        let expected_position = number % max_payloads;
        let expected_start = expected_index * max_payloads;
        let expected_end = (expected_start + max_payloads - 1).min(CoapBlock::MAX_NUMBER);

        prop_assert_eq!(prop_result(block.qblock_set_index(max_payloads))?, expected_index);
        prop_assert_eq!(prop_result(block.qblock_set_position(max_payloads))?, expected_position);
        prop_assert_eq!(prop_result(block.qblock_set_start_number(max_payloads))?, expected_start);
        prop_assert_eq!(prop_result(block.qblock_set_end_number(max_payloads))?, expected_end);
        prop_assert_eq!(prop_result(block.qblock_next_number())?, number + 1);

        let next = prop_result(CoapBlock::qblock2(number + 1, false, 0))?;
        prop_assert!(block.qblock_precedes(&next));
        let expected_range = if !more {
            (number, number)
        } else if number == 0 {
            (0, CoapBlock::MAX_NUMBER)
        } else {
            (number, expected_end)
        };
        prop_assert_eq!(prop_result(block.qblock2_request_range(max_payloads))?, expected_range);
        prop_assert_eq!(
            prop_result(block.is_qblock2_continue(max_payloads))?,
            more && number != 0 && expected_position == 0,
        );
    }
}
