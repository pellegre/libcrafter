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
