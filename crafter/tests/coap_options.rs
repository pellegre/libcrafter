//! Regression coverage for source-backed CoAP option extensions.
//!
//! These tests stay packet-local: they validate wire construction, decoding,
//! inspection, and opt-in semantics without implementing proxy, cache, patch,
//! or response-suppression workflows.

use crafter::prelude::*;

const UNKNOWN_OPTION: u16 = 13;
const UNKNOWN_CONTENT_FORMAT: u16 = 64_997;

fn compile_coap(message: Coap) -> Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

#[test]
fn patch_request_canonically_orders_repeatable_validators_and_extensions() -> Result<()> {
    let request = Coap::patch_document(CoapContentFormat::json_patch_json(), b"[]".to_vec())
        .message_id(0x6801)
        .token(CoapToken::from_bytes([0xaa, 0xbb]))
        .no_response(CoapNoResponse::try_new(
            CoapNoResponse::SUPPRESS_SUCCESS | CoapNoResponse::SUPPRESS_SERVER_ERROR,
        )?)
        .size1(CoapSize1::new(2))
        .accept(CoapAccept::merge_patch_json())
        .uri_path("items")
        .if_match(CoapIfMatch::try_new([0x10])?)
        .if_match(CoapIfMatch::try_new([0x11])?);

    // The builders above are intentionally not in numeric option order. The
    // literal below independently locks canonical deltas and stable ordering.
    let expected = [
        0x42, 0x06, 0x68, 0x01, 0xaa, 0xbb, // CON, PATCH, MID, token.
        0x11, 0x10, // If-Match 1, first occurrence.
        0x01, 0x11, // If-Match 1, repeated with delta zero.
        0xa5, b'i', b't', b'e', b'm', b's', // Uri-Path 11.
        0x11, 0x33, // Content-Format 12 = 51.
        0x51, 0x34, // Accept 17 = 52.
        0xd1, 0x1e, 0x02, // Size1 60 = 2.
        0xd1, 0xb9, 0x12, // No-Response 258 = success + server error.
        0xff, b'[', b']', // Payload marker and patch document.
    ];

    assert_eq!(compile_coap(request.clone())?, expected);
    assert!(request.validate().is_clean());

    let decoded = decode_coap(&expected)?;
    let numbers = decoded
        .options_value()
        .iter()
        .map(|option| option.number().value())
        .collect::<Vec<_>>();
    assert_eq!(numbers, [1, 1, 11, 12, 17, 60, 258]);
    let if_matches = decoded
        .options_value()
        .iter()
        .filter(|option| option.number().value() == COAP_OPTION_IF_MATCH)
        .map(CoapIfMatch::try_from)
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(if_matches[0].as_bytes(), [0x10]);
    assert_eq!(if_matches[1].as_bytes(), [0x11]);
    assert_eq!(
        decoded
            .no_response_value()
            .expect("No-Response option")?
            .mask(),
        0x12
    );
    assert_eq!(compile_coap(decoded)?, expected);

    Ok(())
}

#[test]
fn proxy_uri_conflicts_remain_serializable_and_are_reported() -> Result<()> {
    let request = Coap::get()
        .message_id(0x6802)
        .proxy_uri(CoapProxyUri::try_new("coap://p/x")?)
        .uri_host("p")
        .uri_path("x")
        .proxy_scheme(CoapProxyScheme::try_new("coap")?)
        .accept(CoapAccept::new(0));
    let expected = [
        0x40, 0x01, 0x68, 0x02, // CON, GET, MID.
        0x31, b'p', // Uri-Host 3.
        0x81, b'x', // Uri-Path 11.
        0x60, // Accept 17 = 0, canonical empty uint.
        0xda, 0x05, b'c', b'o', b'a', b'p', b':', b'/', b'/', b'p', b'/',
        b'x', // Proxy-Uri 35.
        0x44, b'c', b'o', b'a', b'p', // Proxy-Scheme 39.
    ];

    assert_eq!(compile_coap(request)?, expected);
    let decoded = decode_coap(&expected)?;
    assert!(decoded.validate_proxy_options().is_err());
    let interaction_findings = decoded
        .validate()
        .issues()
        .iter()
        .filter(|issue| issue.category() == CoapValidationCategory::OptionInteraction)
        .count();
    assert_eq!(interaction_findings, 3);
    assert_eq!(
        decoded.proxy_uris().next().expect("Proxy-Uri")?.as_str()?,
        "coap://p/x"
    );
    assert_eq!(
        decoded
            .proxy_schemes()
            .next()
            .expect("Proxy-Scheme")?
            .as_str()?,
        "coap"
    );
    assert_eq!(compile_coap(decoded)?, expected);

    Ok(())
}

#[test]
fn unknown_representation_metadata_round_trips_next_to_known_options() -> Result<()> {
    let response = Coap::content()
        .acknowledgement()
        .message_id(0x6803)
        .token(CoapToken::from_bytes([0x01]))
        .etag(vec![0xaa])
        .etag(vec![0xbb])
        .content_format(CoapContentFormat::new(UNKNOWN_CONTENT_FORMAT))
        .option(CoapOption::new(UNKNOWN_OPTION, [0x7f]))
        .option(CoapOption::from(CoapMaxAge::new(30)))
        .size2(CoapSize2::new(2))
        .payload([0xde, 0xad]);
    let expected = [
        0x61, 0x45, 0x68, 0x03, 0x01, // ACK, Content, MID, token.
        0x41, 0xaa, // ETag 4, first occurrence.
        0x01, 0xbb, // ETag 4, repeated with delta zero.
        0x82, 0xfd, 0xe5, // Content-Format 12 = 64997.
        0x11, 0x7f, // Unassigned option 13 adjacent to known assignments.
        0x11, 0x1e, // Max-Age 14 = 30.
        0xd1, 0x01, 0x02, // Size2 28 = 2.
        0xff, 0xde, 0xad,
    ];

    assert_eq!(compile_coap(response)?, expected);
    let decoded = decode_coap(&expected)?;
    assert!(decoded.validate().is_clean());
    assert_eq!(
        coap_option_meta(UNKNOWN_OPTION).status,
        CoapRegistryStatus::Unassigned
    );
    let format = decoded
        .content_format_value()
        .transpose()?
        .expect("Content-Format option");
    assert_eq!(format.value(), UNKNOWN_CONTENT_FORMAT);
    assert_eq!(
        format.registry_meta().status,
        CoapRegistryStatus::Unassigned
    );
    assert_eq!(decoded.etag_values().collect::<Result<Vec<_>>>()?.len(), 2);
    assert_eq!(
        decoded.summary(),
        "Coap(version=1, type=acknowledgement, code=2.05(Content), mid=0x6803, token_len=1, options=6, marker=present, payload=2 bytes)"
    );
    let show = Packet::from_layer(decoded.clone()).show();
    assert!(
        show.contains("ETag(4,len=1,hex=aa), ETag(4,len=1,hex=bb)"),
        "{show}"
    );
    assert!(show.contains("Content-Format(12,len=2,hex=fde5)"), "{show}");
    assert!(show.contains("option-13(13,len=1,hex=7f)"), "{show}");
    assert!(show.contains("Max-Age(14,len=1,hex=1e)"), "{show}");
    assert_eq!(compile_coap(decoded)?, expected);

    Ok(())
}

#[test]
fn ipatch_duplicate_content_format_and_empty_document_report_semantics() -> Result<()> {
    let request = Coap::ipatch()
        .message_id(0x6804)
        .content_format(CoapContentFormat::merge_patch_json())
        .content_format(CoapContentFormat::json_patch_json())
        .no_response(CoapNoResponse::suppress_success());
    let expected = [
        0x40, 0x07, 0x68, 0x04, // CON, iPATCH, MID.
        0xc1, 0x34, // Content-Format 12 = 52.
        0x01, 0x33, // Repeated Content-Format 12 = 51.
        0xd1, 0xe9, 0x02, // No-Response 258 = suppress success.
    ];

    assert_eq!(compile_coap(request)?, expected);
    let decoded = decode_coap(&expected)?;
    let validation = decoded.validate();
    assert!(validation.has_errors());
    assert!(validation.issues().iter().any(|issue| {
        issue.field() == "coap.payload"
            && issue.category() == CoapValidationCategory::MethodSemantics
    }));
    assert!(validation.issues().iter().any(|issue| {
        issue.category() == CoapValidationCategory::OptionRepeatability
            && issue.reason().contains("Content-Format")
    }));
    assert_eq!(decoded.content_format_values().count(), 2);
    assert_eq!(compile_coap(decoded)?, expected);

    Ok(())
}

#[test]
fn echo_challenge_and_response_round_trip_exact_opaque_bytes() -> Result<()> {
    // RFC 9175 Section 2.2.1 leaves Echo content implementation-specific.
    let challenge = CoapEcho::try_new([0x00, 0xff, 0x80, 0x45])?;
    let echoed = CoapEcho::response_to(&challenge);
    assert!(echoed.matches_challenge(&challenge));
    assert!(echoed.matches_bytes([0x00, 0xff, 0x80, 0x45]));

    let response = Coap::response(CoapCode::unauthorized())
        .message_id(0x7001)
        .echo(challenge);
    let response_bytes = [
        0x40, 0x81, 0x70, 0x01, // CON, 4.01 Unauthorized, MID.
        0xd4, 0xef, 0x00, 0xff, 0x80, 0x45, // Echo 252, four opaque bytes.
    ];
    assert_eq!(compile_coap(response)?, response_bytes);

    let decoded_response = decode_coap(&response_bytes)?;
    let decoded_challenge = decoded_response.echo_value().expect("Echo option")?;
    assert!(echoed.matches_challenge(&decoded_challenge));
    assert_eq!(compile_coap(decoded_response)?, response_bytes);

    let request = Coap::get().message_id(0x7002).echo(echoed);
    let request_bytes = [
        0x40, 0x01, 0x70, 0x02, // CON, GET, MID.
        0xd4, 0xef, 0x00, 0xff, 0x80, 0x45, // Exact echoed value.
    ];
    assert_eq!(compile_coap(request)?, request_bytes);
    assert_eq!(compile_coap(decode_coap(&request_bytes)?)?, request_bytes);

    Ok(())
}

#[test]
fn echo_and_request_tag_checked_boundaries_leave_raw_values_lossless() -> Result<()> {
    assert!(CoapEcho::try_new([]).is_err());
    assert!(CoapEcho::try_new([0x01]).is_ok());
    assert!(CoapEcho::try_new([0x5a; 40]).is_ok());
    assert!(CoapEcho::try_new([0x5a; 41]).is_err());

    assert!(CoapRequestTag::try_new([]).is_ok());
    assert!(CoapRequestTag::try_new([0xa5; 8]).is_ok());
    assert!(CoapRequestTag::try_new([0xa5; 9]).is_err());

    let malformed = Coap::get()
        .message_id(0x7003)
        .echo(CoapEcho::new([]))
        .request_tag(CoapRequestTag::new([0x7e; 9]));
    let malformed_bytes = compile_coap(malformed)?;
    let decoded = decode_coap(&malformed_bytes)?;
    assert!(decoded.echo_value().expect("Echo option").is_err());
    assert!(decoded
        .request_tag_value()
        .expect("Request-Tag option")
        .is_err());
    assert!(decoded.validate().issues().iter().any(|issue| {
        issue.field() == "coap.options[0].value"
            && issue.category() == CoapValidationCategory::OptionLength
            && issue.reason().contains("Echo")
    }));
    assert!(decoded.validate().issues().iter().any(|issue| {
        issue.field() == "coap.options[1].value"
            && issue.category() == CoapValidationCategory::OptionLength
            && issue.reason().contains("Request-Tag")
    }));
    assert_eq!(compile_coap(decoded)?, malformed_bytes);

    Ok(())
}

#[test]
fn echo_repeatability_and_request_tag_repetition_are_validated_separately() -> Result<()> {
    let request = Coap::get()
        .echo(CoapEcho::try_new([0x10])?)
        .echo(CoapEcho::try_new([0x11])?)
        .request_tag(CoapRequestTag::try_new([])?)
        .request_tag(CoapRequestTag::try_new([0x22])?);

    let validation = request.validate();
    assert!(validation.issues().iter().any(|issue| {
        issue.category() == CoapValidationCategory::OptionRepeatability
            && issue.reason().contains("Echo")
    }));
    assert!(!validation.issues().iter().any(|issue| {
        issue.category() == CoapValidationCategory::OptionRepeatability
            && issue.reason().contains("Request-Tag")
    }));
    assert_eq!(request.echo_values().count(), 2);
    assert_eq!(request.request_tag_values().count(), 2);

    Ok(())
}

#[test]
fn request_tag_correlates_block1_fragments_without_transfer_state() -> Result<()> {
    // RFC 9175 Sections 3.2 through 3.4 associate payload-bearing messages
    // carrying equal Request-Tag bytes with one blockwise request body.
    let tag = CoapRequestTag::try_new([0x00, 0xff, 0x42])?;
    let first = Coap::put()
        .message_id(0x7004)
        .block1_request_fragment(CoapBlock::block1(0, true, 0)?, vec![0x61; 16])
        .request_tag(tag.clone());
    let final_fragment = Coap::put()
        .message_id(0x7005)
        .block1_request_fragment(CoapBlock::block1(1, false, 0)?, b"tail".to_vec())
        .request_tag(CoapRequestTag::try_new([0x00, 0xff, 0x42])?);
    let unrelated = Coap::put()
        .block1(CoapBlock::block1(1, false, 0)?)
        .request_tag(CoapRequestTag::try_new([0x00, 0xff, 0x43])?);

    assert!(tag.correlates_with(
        &final_fragment
            .request_tag_value()
            .expect("Request-Tag option")?
    ));
    assert!(first.request_tag_matches(&final_fragment));
    assert!(final_fragment.request_tag_matches(&first));
    assert!(!first.request_tag_matches(&unrelated));
    assert!(!first.request_tag_matches(&Coap::put()));
    assert!(first
        .block1_validation(CoapBlockTransport::Datagram)
        .expect("Block1 option")?
        .is_valid());
    assert!(final_fragment
        .block1_validation(CoapBlockTransport::Datagram)
        .expect("Block1 option")?
        .is_valid());
    assert!(first.validate().is_clean());
    assert!(final_fragment.validate().is_clean());

    let empty_a = Coap::post().request_tag(CoapRequestTag::try_new([])?);
    let empty_b = Coap::post().request_tag(CoapRequestTag::try_new([])?);
    assert!(empty_a.request_tag_matches(&empty_b));

    let first_bytes = compile_coap(first)?;
    let mut first_golden = vec![
        0x40, 0x03, 0x70, 0x04, // CON, PUT, MID.
        0xd1, 0x0e, 0x08, // Block1 0/1/16.
        0xd3, 0xfc, 0x00, 0xff, 0x42, // Request-Tag 292, three opaque bytes.
        0xff, // Payload marker.
    ];
    first_golden.extend_from_slice(&[0x61; 16]);
    assert_eq!(first_bytes, first_golden);

    let decoded = decode_coap(&first_bytes)?;
    assert_eq!(
        decoded
            .request_tag_value()
            .expect("Request-Tag option")?
            .as_bytes(),
        [0x00, 0xff, 0x42]
    );
    assert_eq!(compile_coap(decoded)?, first_bytes);

    Ok(())
}
