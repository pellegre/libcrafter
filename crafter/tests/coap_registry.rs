use crafter::prelude::*;

// Source: `.agents/docs/coap-codepoints.md`, reviewed against the IANA CoRE
// Parameters registries on this date. Updating these rows requires a new
// source-manifest and IANA review, not merely changing the expected values.
const IANA_SNAPSHOT_REVIEW_DATE: &str = "2026-07-14";

#[derive(Clone, Copy)]
struct OptionRow {
    number: u16,
    label: &'static str,
    reference: &'static str,
    critical: bool,
    unsafe_to_forward: bool,
    no_cache_key: bool,
}

#[test]
fn admitted_option_rows_match_the_reviewed_iana_snapshot() {
    let rows = [
        OptionRow {
            number: COAP_OPTION_IF_MATCH,
            label: "If-Match",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_URI_HOST,
            label: "Uri-Host",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_ETAG,
            label: "ETag",
            reference: "RFC 7252; RFC 8613",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_IF_NONE_MATCH,
            label: "If-None-Match",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_OBSERVE,
            label: "Observe",
            reference: "RFC 7641; RFC 8613",
            critical: false,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_URI_PORT,
            label: "Uri-Port",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_LOCATION_PATH,
            label: "Location-Path",
            reference: "RFC 7252; RFC 8613",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_OSCORE,
            label: "OSCORE",
            reference: "RFC 8613",
            critical: true,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_URI_PATH,
            label: "Uri-Path",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_CONTENT_FORMAT,
            label: "Content-Format",
            reference: "RFC 7252; RFC 8613",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_MAX_AGE,
            label: "Max-Age",
            reference: "RFC 7252; RFC 8516; RFC 8613",
            critical: false,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_URI_QUERY,
            label: "Uri-Query",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_HOP_LIMIT,
            label: "Hop-Limit",
            reference: "RFC 8768",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_ACCEPT,
            label: "Accept",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_Q_BLOCK1,
            label: "Q-Block1",
            reference: "RFC 9177",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_LOCATION_QUERY,
            label: "Location-Query",
            reference: "RFC 7252; RFC 8613",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_BLOCK2,
            label: "Block2",
            reference: "RFC 7959; RFC 8323; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_BLOCK1,
            label: "Block1",
            reference: "RFC 7959; RFC 8323; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_SIZE2,
            label: "Size2",
            reference: "RFC 7959; RFC 8613",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: true,
        },
        OptionRow {
            number: COAP_OPTION_Q_BLOCK2,
            label: "Q-Block2",
            reference: "RFC 9177",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_PROXY_URI,
            label: "Proxy-Uri",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_PROXY_SCHEME,
            label: "Proxy-Scheme",
            reference: "RFC 7252; RFC 8613",
            critical: true,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_SIZE1,
            label: "Size1",
            reference: "RFC 7252; RFC 8613",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: true,
        },
        OptionRow {
            number: COAP_OPTION_ECHO,
            label: "Echo",
            reference: "RFC 9175",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: true,
        },
        OptionRow {
            number: COAP_OPTION_NO_RESPONSE,
            label: "No-Response",
            reference: "RFC 7967; RFC 8613",
            critical: false,
            unsafe_to_forward: true,
            no_cache_key: false,
        },
        OptionRow {
            number: COAP_OPTION_REQUEST_TAG,
            label: "Request-Tag",
            reference: "RFC 9175",
            critical: false,
            unsafe_to_forward: false,
            no_cache_key: false,
        },
    ];

    assert_eq!(rows.len(), 26, "snapshot {IANA_SNAPSHOT_REVIEW_DATE}");

    for row in rows {
        let number = CoapOptionNumber::from_wire(row.number);
        let converted = CoapOptionNumber::from(row.number);
        let numeric: u16 = number.into();
        let metadata = number.registry_meta();

        assert_eq!(number, converted, "snapshot {IANA_SNAPSHOT_REVIEW_DATE}");
        assert_eq!(number.value(), row.number);
        assert_eq!(numeric, row.number);
        assert_eq!(metadata.value, u64::from(row.number));
        assert_eq!(metadata.label, row.label);
        assert_eq!(metadata.status, CoapRegistryStatus::Assigned);
        assert_eq!(metadata.reference, Some(row.reference));
        assert!(metadata.status.is_assigned());
        assert_eq!(number.is_critical(), row.critical, "option {}", row.number);
        assert_eq!(
            number.is_unsafe(),
            row.unsafe_to_forward,
            "option {}",
            row.number
        );
        assert_eq!(
            number.is_safe_to_forward(),
            !row.unsafe_to_forward,
            "option {}",
            row.number
        );
        assert_eq!(
            number.is_no_cache_key(),
            row.no_cache_key,
            "option {}",
            row.number
        );
    }
}

#[test]
fn option_registry_boundaries_keep_status_labels_and_fallbacks() {
    let rows = [
        (
            0,
            "option-0",
            CoapRegistryStatus::Reserved,
            "IANA CoRE Parameters; RFC 7252 Section 12.2",
        ),
        (
            2,
            "option-2",
            CoapRegistryStatus::Unassigned,
            "IANA CoRE Parameters; RFC 7252 Section 12.2",
        ),
        (
            128,
            "option-128",
            CoapRegistryStatus::Reserved,
            "IANA CoRE Parameters; RFC 7252 Section 12.2",
        ),
        (
            235,
            "Proxy-Cri",
            CoapRegistryStatus::DraftBacked,
            "RFC-ietf-core-href-29",
        ),
        (
            64_999,
            "option-64999",
            CoapRegistryStatus::Unassigned,
            "IANA CoRE Parameters; RFC 7252 Section 12.2",
        ),
        (
            65_000,
            "option-65000",
            CoapRegistryStatus::Experimental,
            "IANA CoRE Parameters; RFC 7252 Section 12.2",
        ),
        (
            u16::MAX,
            "option-65535",
            CoapRegistryStatus::Experimental,
            "IANA CoRE Parameters; RFC 7252 Section 12.2",
        ),
    ];

    for (value, label, status, reference) in rows {
        let number = CoapOptionNumber::from(value);
        let metadata = coap_option_meta(value);

        assert_eq!(metadata, number.registry_meta());
        assert_eq!(metadata.value, u64::from(value));
        assert_eq!(metadata.label, label);
        assert_eq!(metadata.status, status);
        assert_eq!(metadata.status.label(), status.label());
        assert_eq!(metadata.reference, Some(reference));
        assert_eq!(number.is_critical(), value & 1 != 0);
        assert_eq!(number.is_unsafe(), value & 2 != 0);
        assert_eq!(number.is_safe_to_forward(), value & 2 == 0);
        assert_eq!(number.is_no_cache_key(), value & 0x1e == 0x1c);
    }
}

#[derive(Clone, Copy)]
struct ContentFormatRow {
    value: u16,
    wire: &'static [u8],
    label: &'static str,
    reference: &'static str,
}

#[test]
fn builder_content_formats_match_the_reviewed_iana_snapshot() {
    let rows = [
        ContentFormatRow {
            value: 0,
            wire: &[],
            label: "text/plain; charset=utf-8",
            reference: "RFC 2046; RFC 3676; RFC 5147",
        },
        ContentFormatRow {
            value: 40,
            wire: &[0x28],
            label: "application/link-format",
            reference: "RFC 6690",
        },
        ContentFormatRow {
            value: 42,
            wire: &[0x2a],
            label: "application/octet-stream",
            reference: "RFC 2045; RFC 2046",
        },
        ContentFormatRow {
            value: 50,
            wire: &[0x32],
            label: "application/json",
            reference: "RFC 8259",
        },
        ContentFormatRow {
            value: 51,
            wire: &[0x33],
            label: "application/json-patch+json",
            reference: "RFC 6902",
        },
        ContentFormatRow {
            value: 52,
            wire: &[0x34],
            label: "application/merge-patch+json",
            reference: "RFC 7396",
        },
        ContentFormatRow {
            value: 60,
            wire: &[0x3c],
            label: "application/cbor",
            reference: "RFC 8949",
        },
        ContentFormatRow {
            value: 10_001,
            wire: &[0x27, 0x11],
            label: "application/oscore",
            reference: "RFC 8613",
        },
    ];

    for row in rows {
        let content_format = CoapContentFormat::new(row.value);
        let accept = CoapAccept::new(row.value);

        for metadata in [content_format.registry_meta(), accept.registry_meta()] {
            assert_eq!(metadata.value, u64::from(row.value));
            assert_eq!(metadata.label, row.label);
            assert_eq!(metadata.status, CoapRegistryStatus::Assigned);
            assert_eq!(metadata.reference, Some(row.reference));
            assert!(metadata.status.is_assigned());
        }

        assert_eq!(content_format.value(), row.value);
        assert_eq!(content_format.as_bytes(), row.wire);
        assert_eq!(accept.value(), row.value);
        assert_eq!(accept.as_bytes(), row.wire);

        let content_option = CoapOption::from(content_format);
        let accept_option = CoapOption::from(accept);
        assert_eq!(content_option.number().value(), COAP_OPTION_CONTENT_FORMAT);
        assert_eq!(accept_option.number().value(), COAP_OPTION_ACCEPT);
        assert_eq!(content_option.value(), row.wire);
        assert_eq!(accept_option.value(), row.wire);
        assert_eq!(
            CoapContentFormat::try_from(&content_option)
                .expect("builder Content-Format remains typed")
                .value(),
            row.value
        );
        assert_eq!(
            CoapAccept::try_from(&accept_option)
                .expect("builder Accept remains typed")
                .value(),
            row.value
        );
    }
}

#[test]
fn patch_methods_formats_and_response_helpers_match_rfc_8132_and_iana() {
    let methods = [
        (CoapCode::patch(), 0x06, "PATCH"),
        (CoapCode::ipatch(), 0x07, "iPATCH"),
    ];
    for (code, wire, label) in methods {
        assert_eq!(code.wire_value(), wire);
        assert_eq!(code.registry_meta().label, label);
        assert_eq!(code.registry_meta().status, CoapRegistryStatus::Assigned);
        assert_eq!(code.registry_meta().reference, Some("RFC 8132"));
    }

    let formats = [
        (
            CoapContentFormat::json_patch_json(),
            CoapAccept::json_patch_json(),
            51,
            "application/json-patch+json",
            "RFC 6902",
        ),
        (
            CoapContentFormat::merge_patch_json(),
            CoapAccept::merge_patch_json(),
            52,
            "application/merge-patch+json",
            "RFC 7396",
        ),
    ];
    for (content_format, accept, value, label, reference) in formats {
        assert_eq!(content_format.value(), value);
        assert_eq!(accept.value(), value);
        for metadata in [content_format.registry_meta(), accept.registry_meta()] {
            assert_eq!(metadata.label, label);
            assert_eq!(metadata.status, CoapRegistryStatus::Assigned);
            assert_eq!(metadata.reference, Some(reference));
        }
    }

    let responses = [
        (Coap::patch_created_response(), CoapCode::created()),
        (Coap::patch_changed_response(), CoapCode::changed()),
        (Coap::patch_conflict_response(), CoapCode::conflict()),
        (
            Coap::patch_unsupported_content_format_response(),
            CoapCode::unsupported_content_format(),
        ),
        (
            Coap::patch_unprocessable_entity_response(),
            CoapCode::unprocessable_entity(),
        ),
    ];
    for (response, code) in responses {
        assert_eq!(response.code_value(), code);
        assert!(response.is_response());
    }
}

#[test]
fn content_format_boundaries_keep_status_references_and_fallbacks() {
    let rows = [
        (
            1,
            "content-format-1",
            CoapRegistryStatus::Unassigned,
            "IANA CoRE Parameters; RFC 9876",
        ),
        (
            270,
            "application/suit-report+cose",
            CoapRegistryStatus::DraftBacked,
            "RFC-ietf-suit-report-19",
        ),
        (
            293,
            "application/sd-cwt",
            CoapRegistryStatus::Temporary,
            "draft-ietf-spice-sd-cwt-06; expires 2026-12-08",
        ),
        (
            1_542,
            "content-format-1542",
            CoapRegistryStatus::Reserved,
            "IANA CoRE Parameters; RFC 9876",
        ),
        (
            64_998,
            "content-format-64998",
            CoapRegistryStatus::Documentation,
            "IANA CoRE Parameters; RFC 9876",
        ),
        (
            65_000,
            "content-format-65000",
            CoapRegistryStatus::Experimental,
            "IANA CoRE Parameters; RFC 9876",
        ),
        (
            u64::from(u16::MAX),
            "content-format-65535",
            CoapRegistryStatus::Experimental,
            "IANA CoRE Parameters; RFC 9876",
        ),
        (
            u64::from(u16::MAX) + 1,
            "content-format-65536",
            CoapRegistryStatus::Unknown,
            "CoAP Content-Format registry domain is 0..=65535",
        ),
        (
            u64::MAX,
            "content-format-18446744073709551615",
            CoapRegistryStatus::Unknown,
            "CoAP Content-Format registry domain is 0..=65535",
        ),
    ];

    for (value, label, status, reference) in rows {
        let metadata = coap_content_format_meta(value);
        assert_eq!(metadata.value, value);
        assert_eq!(metadata.label, label);
        assert_eq!(metadata.status, status);
        assert_eq!(metadata.reference, Some(reference));
        assert_eq!(
            metadata.status.is_assigned(),
            matches!(
                status,
                CoapRegistryStatus::Temporary | CoapRegistryStatus::DraftBacked
            )
        );
    }
}

#[test]
fn registry_status_labels_are_stable_through_the_public_surface() {
    let rows = [
        (CoapRegistryStatus::Assigned, "assigned", true),
        (CoapRegistryStatus::Temporary, "temporary", true),
        (CoapRegistryStatus::Unassigned, "unassigned", false),
        (CoapRegistryStatus::Reserved, "reserved", false),
        (CoapRegistryStatus::Documentation, "documentation", false),
        (CoapRegistryStatus::Experimental, "experimental", false),
        (CoapRegistryStatus::DraftBacked, "draft-backed", true),
        (CoapRegistryStatus::Unknown, "unknown", false),
    ];

    for (status, label, assigned) in rows {
        assert_eq!(status.label(), label);
        assert_eq!(status.is_assigned(), assigned);
    }
}

#[test]
fn registry_status_never_controls_structural_parse_acceptance() -> Result<()> {
    let message = Coap::get()
        .message_id(0x5454)
        .option(CoapOption::new(2u16, [0x02]))
        .content_format(CoapContentFormat::new(64_997))
        .accept(CoapAccept::new(u16::MAX))
        .option(CoapOption::new(128u16, [0x80]))
        .option(CoapOption::new(65_000u16, [0xfe]))
        .option(CoapOption::new(u16::MAX, [0xff]));

    let compiled = Packet::from_layer(message).compile()?;
    let decoded = decode_coap(compiled.as_bytes())?;
    let options = decoded.options_value();

    assert_eq!(
        options
            .iter()
            .map(|option| (option.number().value(), option.value().to_vec()))
            .collect::<Vec<_>>(),
        vec![
            (2, vec![0x02]),
            (COAP_OPTION_CONTENT_FORMAT, vec![0xfd, 0xe5]),
            (COAP_OPTION_ACCEPT, vec![0xff, 0xff]),
            (128, vec![0x80]),
            (65_000, vec![0xfe]),
            (u16::MAX, vec![0xff]),
        ]
    );
    assert_eq!(
        options[0].registry_meta().status,
        CoapRegistryStatus::Unassigned
    );
    assert_eq!(
        options[3].registry_meta().status,
        CoapRegistryStatus::Reserved
    );
    assert_eq!(
        options[4].registry_meta().status,
        CoapRegistryStatus::Experimental
    );
    assert_eq!(
        options[5].registry_meta().status,
        CoapRegistryStatus::Experimental
    );
    assert_eq!(
        CoapContentFormat::try_from(&options[1])?
            .registry_meta()
            .status,
        CoapRegistryStatus::Unassigned
    );
    assert_eq!(
        CoapAccept::try_from(&options[2])?.registry_meta().status,
        CoapRegistryStatus::Experimental
    );
    assert_eq!(
        Packet::from_layer(decoded).compile()?.as_bytes(),
        compiled.as_bytes()
    );

    Ok(())
}
