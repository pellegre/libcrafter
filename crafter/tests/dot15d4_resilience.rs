#[macro_use]
mod support;

use std::collections::HashSet;

use crafter::core::{CrafterError, LinkType, Packet, Raw};

/// Which decode entrypoint a corpus entry targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorpusLinkType {
    /// Bare 802.15.4 MAC frame (with FCS): `LinkType::Ieee802154`.
    Mac,
    /// TAP radio-descriptor pseudo-header + MAC frame: `LinkType::Ieee802154Tap`.
    Tap,
}

impl CorpusLinkType {
    fn link_type(self) -> LinkType {
        match self {
            CorpusLinkType::Mac => LinkType::Ieee802154,
            CorpusLinkType::Tap => LinkType::Ieee802154Tap,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    BufferTooShort(&'static str),
    InvalidFieldValue(&'static str),
    Decodes(&'static str),
}

#[derive(Debug)]
struct Dot15d4MalformedCase {
    name: &'static str,
    link_type: CorpusLinkType,
    expected: ExpectedOutcome,
    bytes: Vec<u8>,
}

#[test]
fn dot15d4_resilience_malformed_decode_corpus_reports_structured_outcomes() {
    let cases = dot15d4_malformed_cases();
    assert_required_dot15d4_resilience_cases(&cases);

    for case in cases {
        let link_type = case.link_type.link_type();
        let decoded = std::panic::catch_unwind(|| Packet::decode_from_link(link_type, &case.bytes))
            .unwrap_or_else(|_| panic!("802.15.4 malformed corpus case {} panicked", case.name));

        match case.expected {
            ExpectedOutcome::BufferTooShort(expected_context) => {
                assert_buffer_too_short(&case, expected_context, decoded);
            }
            ExpectedOutcome::InvalidFieldValue(expected_field) => {
                assert_invalid_field_value(&case, expected_field, decoded);
            }
            ExpectedOutcome::Decodes(expected_marker) => {
                assert_case_decodes(&case, expected_marker, decoded);
            }
        }
    }
}

fn dot15d4_malformed_cases() -> Vec<Dot15d4MalformedCase> {
    fixture_str!("malformed/dot15d4-decode-corpus.hex")
        .lines()
        .enumerate()
        .filter_map(|(line_index, line)| {
            let line_number = line_index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let mut parts = line.split('|').map(str::trim);
            let name = parts.next().unwrap_or_else(|| {
                panic!("802.15.4 malformed corpus line {line_number} is missing a case name")
            });
            let link_type = parts.next().unwrap_or_else(|| {
                panic!("802.15.4 malformed corpus case {name} is missing a link type")
            });
            let expected_kind = parts.next().unwrap_or_else(|| {
                panic!("802.15.4 malformed corpus case {name} is missing an expected kind")
            });
            let expected_context_or_marker = parts.next().unwrap_or_else(|| {
                panic!("802.15.4 malformed corpus case {name} is missing an expected context")
            });
            let hex = parts.next().unwrap_or_else(|| {
                panic!("802.15.4 malformed corpus case {name} is missing hex bytes")
            });
            assert!(
                parts.next().is_none(),
                "802.15.4 malformed corpus case {name} has too many fields"
            );

            Some(Dot15d4MalformedCase {
                name,
                link_type: parse_link_type(name, link_type),
                expected: parse_expected_outcome(name, expected_kind, expected_context_or_marker),
                bytes: parse_hex(name, hex),
            })
        })
        .collect()
}

fn parse_link_type(name: &str, link_type: &str) -> CorpusLinkType {
    match link_type {
        "mac" => CorpusLinkType::Mac,
        "tap" => CorpusLinkType::Tap,
        _ => panic!("802.15.4 malformed corpus case {name} has unknown link type {link_type}"),
    }
}

fn parse_expected_outcome(
    name: &str,
    expected_kind: &'static str,
    expected_context_or_marker: &'static str,
) -> ExpectedOutcome {
    match expected_kind {
        "buffer-too-short" => ExpectedOutcome::BufferTooShort(expected_context_or_marker),
        "invalid-field-value" => ExpectedOutcome::InvalidFieldValue(expected_context_or_marker),
        "decodes" => ExpectedOutcome::Decodes(expected_context_or_marker),
        _ => panic!(
            "802.15.4 malformed corpus case {name} has unknown expected kind {expected_kind}"
        ),
    }
}

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "802.15.4 malformed corpus case {name} has an odd hex length"
    );

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).unwrap_or_else(|_| {
                panic!("802.15.4 malformed corpus case {name} contains non-UTF8 hex")
            });
            u8::from_str_radix(byte, 16).unwrap_or_else(|_| {
                panic!("802.15.4 malformed corpus case {name} has invalid hex {byte}")
            })
        })
        .collect()
}

fn assert_required_dot15d4_resilience_cases(cases: &[Dot15d4MalformedCase]) {
    let names = cases.iter().map(|case| case.name).collect::<HashSet<_>>();
    for required in [
        "too-short-mac-fcf",
        "mac-addressing-runs-past-buffer",
        "truncated-tap-tlv-header",
        "tap-declared-length-exceeds-buffer",
        "reserved-mac-frame-type",
        "truncated-nwk-header",
        "truncated-aps-header",
    ] {
        assert!(
            names.contains(required),
            "802.15.4 malformed corpus missing required case {required}"
        );
    }
}

fn assert_buffer_too_short(
    case: &Dot15d4MalformedCase,
    expected_context: &'static str,
    decoded: crafter::core::Result<Packet>,
) {
    match decoded {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert!(
                !context.is_empty(),
                "802.15.4 malformed corpus case {} BufferTooShort must carry a context",
                case.name
            );
            assert_eq!(
                context, expected_context,
                "802.15.4 malformed corpus case {} returned an unexpected buffer context",
                case.name
            );
            assert!(
                required > available,
                "802.15.4 malformed corpus case {} BufferTooShort must require more ({required}) \
                 than is available ({available})",
                case.name
            );
        }
        other => panic!(
            "802.15.4 malformed corpus case {} expected BufferTooShort, got {other:?}",
            case.name
        ),
    }
}

fn assert_invalid_field_value(
    case: &Dot15d4MalformedCase,
    expected_field: &'static str,
    decoded: crafter::core::Result<Packet>,
) {
    match decoded {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert!(
                !field.is_empty(),
                "802.15.4 malformed corpus case {} InvalidFieldValue must carry a field context",
                case.name
            );
            assert_eq!(
                field, expected_field,
                "802.15.4 malformed corpus case {} returned an unexpected invalid field",
                case.name
            );
            assert!(
                !reason.is_empty(),
                "802.15.4 malformed corpus case {} InvalidFieldValue must carry a reason",
                case.name
            );
        }
        other => panic!(
            "802.15.4 malformed corpus case {} expected InvalidFieldValue, got {other:?}",
            case.name
        ),
    }
}

fn assert_case_decodes(
    case: &Dot15d4MalformedCase,
    expected_marker: &'static str,
    decoded: crafter::core::Result<Packet>,
) {
    let packet = decoded.unwrap_or_else(|err| {
        panic!(
            "802.15.4 malformed corpus case {} should decode without error: {err}",
            case.name
        )
    });

    assert!(
        !packet.summary().is_empty(),
        "802.15.4 malformed corpus case {} summary should be inspectable",
        case.name
    );
    assert!(
        !packet.show().is_empty(),
        "802.15.4 malformed corpus case {} show output should be inspectable",
        case.name
    );

    // A truncated Zigbee NWK/APS payload is preserved as a trailing Raw layer
    // rather than rejecting the enclosing MAC frame; confirm the layer survives
    // for inspection.
    match expected_marker {
        "nwk-raw" | "aps-raw" => {
            assert!(
                packet.layer::<Raw>().is_some(),
                "802.15.4 malformed corpus case {} should preserve the truncated payload as Raw",
                case.name
            );
        }
        _ => panic!(
            "802.15.4 malformed corpus case {} has unknown decode marker {expected_marker}",
            case.name
        ),
    }
}
