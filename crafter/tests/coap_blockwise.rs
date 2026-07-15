//! RFC 7959 and RFC 8323 blockwise integration coverage through public APIs.
//!
//! These tests exercise packet-local block metadata only. Transfer assembly,
//! follow-up scheduling, and reliable stream framing deliberately remain out
//! of scope.

use crafter::prelude::*;

fn compile_coap(message: Coap) -> Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

#[test]
fn block1_request_and_continue_preserve_size_negotiation() -> Result<()> {
    let request = Coap::put()
        .message_id(0x6501)
        .token(CoapToken::from_bytes([0xa1]))
        .block1_request_fragment_with_size1(
            CoapBlock::block1(2, true, 1)?,
            vec![0x5a; 32],
            CoapSize1::new(70),
        );
    let mut expected = vec![
        0x41, 0x03, 0x65, 0x01, 0xa1, // CON, PUT, MID, token.
        0xd1, 0x0e, 0x29, // Block1 2/1/32.
        0xd1, 0x14, 0x46, // Size1 70.
        0xff,
    ];
    expected.extend_from_slice(&[0x5a; 32]);

    assert_eq!(compile_coap(request.clone())?, expected);
    assert!(request
        .block1_validation(CoapBlockTransport::Datagram)
        .expect("Block1 option")?
        .is_valid());

    let decoded = decode_coap(&expected)?;
    let block = decoded.block1_value().expect("Block1 option")?;
    assert_eq!(block.raw_bytes(), &[0x29]);
    assert_eq!(block.number(), 2);
    assert!(block.more());
    assert_eq!(block.szx(), 1);
    assert_eq!(block.block_size(), 32);
    assert_eq!(block.offset()?, 64);
    assert_eq!(decoded.size1_value().expect("Size1 option")?.value(), 70);
    assert_eq!(compile_coap(decoded)?, expected);

    let continued = Coap::block1_continue(CoapBlock::block1(2, true, 0)?)
        .acknowledgement()
        .message_id(0x6501)
        .token(CoapToken::from_bytes([0xa1]));
    let continued_bytes = [
        0x61, 0x5f, 0x65, 0x01, 0xa1, // ACK, 2.31 Continue, MID, token.
        0xd1, 0x0e, 0x28, // Block1 2/1/16 selected by the server.
    ];
    assert_eq!(compile_coap(continued.clone())?, continued_bytes);
    assert!(continued
        .block1_validation(CoapBlockTransport::Datagram)
        .expect("Block1 option")?
        .is_valid());
    assert_eq!(
        compile_coap(decode_coap(&continued_bytes)?)?,
        continued_bytes
    );

    Ok(())
}

#[test]
fn block2_request_response_correlate_offset_etag_and_total_size() -> Result<()> {
    let requested = CoapBlock::block2(2, false, 2)?; // offset 128, size 64.
    let request = Coap::get()
        .message_id(0x6502)
        .token(CoapToken::from_bytes([0xb2]))
        .block2_request_selection_with_size2(requested.clone());
    let request_bytes = [
        0x41, 0x01, 0x65, 0x02, 0xb2, // CON, GET, MID, token.
        0xd1, 0x0a, 0x22, // Block2 2/0/64.
        0x50, // Empty Size2 requests a size estimate.
    ];
    assert_eq!(compile_coap(request.clone())?, request_bytes);
    assert_eq!(request.block2_offset().expect("Block2 option")?, 128);
    assert_eq!(request.size2_value().expect("Size2 option")?.value(), 0);
    assert!(request
        .block2_validation(CoapBlockTransport::Datagram, None)
        .expect("Block2 option")?
        .is_valid());
    assert_eq!(compile_coap(decode_coap(&request_bytes)?)?, request_bytes);

    let response = Coap::content()
        .acknowledgement()
        .message_id(0x6502)
        .token(CoapToken::from_bytes([0xb2]))
        .block2_response_fragment_with_metadata(
            CoapBlock::block2(4, true, 1)?, // offset 128, size 32.
            vec![0x6b; 32],
            CoapEtag::try_new([0xde, 0xad])?,
            CoapSize2::new(291),
        );
    let mut response_bytes = vec![
        0x61, 0x45, 0x65, 0x02, 0xb2, // ACK, 2.05 Content, MID, token.
        0x42, 0xde, 0xad, // ETag.
        0xd1, 0x06, 0x49, // Block2 4/1/32.
        0x52, 0x01, 0x23, // Size2 291.
        0xff,
    ];
    response_bytes.extend_from_slice(&[0x6b; 32]);
    assert_eq!(compile_coap(response.clone())?, response_bytes);
    assert!(response
        .block2_validation(CoapBlockTransport::Datagram, Some(&requested))
        .expect("Block2 option")?
        .is_valid());

    let decoded = decode_coap(&response_bytes)?;
    let block = decoded.block2_value().expect("Block2 option")?;
    assert_eq!(block.raw_bytes(), &[0x49]);
    assert_eq!(block.offset()?, requested.offset()?);
    assert_eq!(
        decoded.etag_value().expect("ETag option")?.as_bytes(),
        [0xde, 0xad]
    );
    assert_eq!(decoded.size2_value().expect("Size2 option")?.value(), 291);
    assert_eq!(compile_coap(decoded.clone())?, response_bytes);

    assert_eq!(
        decoded.summary(),
        "Coap(version=1, type=acknowledgement, code=2.05(Content), mid=0x6502, token_len=1, options=3, marker=present, payload=32 bytes)"
    );
    let show = Packet::from_layer(decoded).show();
    assert!(show.contains("ETag(4,len=2,hex=dead)"), "{show}");
    assert!(show.contains("Block2(23,len=1,hex=49)"), "{show}");
    assert!(show.contains("Size2(28,len=2,hex=0123)"), "{show}");

    Ok(())
}

#[test]
fn bert_metadata_uses_reliable_transport_units_without_stream_state() -> Result<()> {
    let non_final_block = CoapBlock::block1(3, true, CoapBlock::BERT_SZX)?;
    let non_final = Coap::put()
        .message_id(0x6503)
        .block1_request_fragment(non_final_block.clone(), vec![0x7c; 2_048]);
    assert!(non_final
        .block1_validation(CoapBlockTransport::Reliable)
        .expect("Block1 option")?
        .is_valid());
    assert_eq!(non_final_block.raw_bytes(), &[0x3f]);
    assert_eq!(non_final_block.offset()?, 3_072);
    assert_eq!(non_final_block.bert_block_count(2_048)?, 2);
    assert_eq!(non_final_block.bert_payload_end_offset(2_048)?, 5_120);
    assert_eq!(non_final_block.bert_next_number(2_048)?, 5);
    assert_eq!(non_final_block.bert_next_offset(2_048)?, 5_120);

    let encoded = compile_coap(non_final)?;
    assert_eq!(&encoded[..7], &[0x40, 0x03, 0x65, 0x03, 0xd1, 0x0e, 0x3f]);
    assert_eq!(encoded[7], COAP_PAYLOAD_MARKER);
    assert_eq!(encoded.len(), 8 + 2_048);
    let decoded = decode_coap(&encoded)?;
    let decoded_block = decoded.block1_value().expect("Block1 option")?;
    assert!(decoded_block.is_bert());
    assert_eq!(decoded_block.block_size(), CoapBlock::BERT_UNIT);
    assert!(decoded
        .block1_validation(CoapBlockTransport::Reliable)
        .expect("Block1 option")?
        .is_valid());
    assert_eq!(compile_coap(decoded.clone())?, encoded);
    assert!(decoded.summary().contains("payload=2048 bytes"));
    assert!(Packet::from_layer(decoded)
        .show()
        .contains("Block1(27,len=1,hex=3f)"));

    let final_block = CoapBlock::block2(5, false, CoapBlock::BERT_SZX)?;
    let final_message = Coap::content()
        .message_id(0x6504)
        .block2_response_fragment(final_block.clone(), vec![0x4d; 1_537]);
    assert!(final_message
        .block2_validation(CoapBlockTransport::Reliable, None)
        .expect("Block2 option")?
        .is_valid());
    assert_eq!(final_block.bert_block_count(1_537)?, 2);
    assert_eq!(final_block.bert_payload_end_offset(1_537)?, 6_657);
    assert_eq!(final_block.bert_next_number(1_537)?, 7);
    assert_eq!(final_block.bert_next_offset(1_537)?, 7_168);
    let final_bytes = compile_coap(final_message)?;
    assert_eq!(compile_coap(decode_coap(&final_bytes)?)?, final_bytes);

    let malformed_non_final = Coap::put().block1_request_fragment(
        CoapBlock::block1(0, true, CoapBlock::BERT_SZX)?,
        vec![0; 1_537],
    );
    let report = malformed_non_final
        .block1_validation(CoapBlockTransport::Reliable)
        .expect("Block1 option")?;
    assert!(report.issues().iter().any(|issue| matches!(
        issue,
        CrafterError::InvalidFieldValue {
            field: "coap.block.payload-length",
            reason: "non-final BERT payload must be a positive multiple of 1024 bytes",
        }
    )));
    assert!(compile_coap(malformed_non_final).is_ok());

    Ok(())
}

#[test]
fn malformed_block_and_size_values_remain_byte_exact_and_inspectable() -> Result<()> {
    let raw_block = CoapBlock::from_raw_bytes_for(CoapBlockKind::Block1, [0x00, 0x00, 0x00, 0x10])?;
    let message = Coap::put()
        .message_id(0x6505)
        .block1(raw_block)
        .option(CoapOption::new(
            COAP_OPTION_SIZE1,
            [0x00, 0x00, 0x00, 0x00, 0x10],
        ))
        .payload(vec![0x33; 16]);
    let mut expected = vec![
        0x40, 0x03, 0x65, 0x05, // CON, PUT, MID.
        0xd4, 0x0e, 0x00, 0x00, 0x00, 0x10, // Overlong Block1 uint.
        0xd5, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10, // Overlong Size1 uint.
        0xff,
    ];
    expected.extend_from_slice(&[0x33; 16]);
    assert_eq!(compile_coap(message)?, expected);

    let decoded = decode_coap(&expected)?;
    let decoded_block = decoded.block1_value().expect("Block1 option")?;
    assert_eq!(decoded_block.raw_bytes(), &[0x00, 0x00, 0x00, 0x10]);
    assert_eq!(decoded_block.number(), 1);
    assert_eq!(decoded_block.offset()?, 16);
    assert!(decoded.size1_value().expect("Size1 option").is_err());
    let report = decoded
        .block1_validation(CoapBlockTransport::Datagram)
        .expect("Block1 option")?;
    assert!(report.issues().iter().any(|issue| matches!(
        issue,
        CrafterError::InvalidFieldValue {
            field: "coap.block.value",
            ..
        }
    )));
    assert!(decoded.validate().has_errors());
    assert_eq!(compile_coap(decoded.clone())?, expected);

    let packet = Packet::from_layer(decoded);
    assert!(packet.summary().contains("options=2"));
    let show = packet.show();
    assert!(show.contains("Block1(27,len=4,hex=00000010)"), "{show}");
    assert!(show.contains("Size1(60,len=5,hex=0000000010)"), "{show}");

    let short_non_final =
        Coap::put().block1_request_fragment(CoapBlock::block1(0, true, 0)?, vec![0; 15]);
    let short_report = short_non_final
        .block1_validation(CoapBlockTransport::Datagram)
        .expect("Block1 option")?;
    assert!(short_report.issues().iter().any(|issue| matches!(
        issue,
        CrafterError::InvalidFieldValue {
            field: "coap.block.payload-length",
            ..
        }
    )));
    assert!(compile_coap(short_non_final).is_ok());

    Ok(())
}
