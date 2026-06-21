#[macro_use]
mod support;

use std::collections::HashSet;

use crafter::core::{CrafterError, LinkType, Packet};
use crafter::BleLlAdv;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    BufferTooShort(&'static str),
    InvalidFieldValue(&'static str),
    Decodes(&'static str),
}

#[derive(Debug)]
struct BleMalformedCase {
    name: &'static str,
    expected: ExpectedOutcome,
    bytes: Vec<u8>,
}

#[test]
fn ble_resilience_malformed_decode_corpus_reports_structured_outcomes() {
    let cases = ble_malformed_cases();
    assert_required_ble_resilience_cases(&cases);

    for case in cases {
        let decoded = std::panic::catch_unwind(|| {
            Packet::decode_from_link(LinkType::BluetoothLeLl, &case.bytes)
        })
        .unwrap_or_else(|_| panic!("BLE malformed corpus case {} panicked", case.name));

        match case.expected {
            ExpectedOutcome::BufferTooShort(expected_context) => {
                assert_buffer_too_short(&case, expected_context, decoded);
            }
            ExpectedOutcome::InvalidFieldValue(expected_field) => {
                assert_invalid_field_value(&case, expected_field, decoded);
            }
            ExpectedOutcome::Decodes(expected_marker) => {
                assert_ble_case_decodes(&case, expected_marker, decoded);
            }
        }
    }
}

fn ble_malformed_cases() -> Vec<BleMalformedCase> {
    fixture_str!("malformed/ble-decode-corpus.hex")
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
                panic!("BLE malformed corpus line {line_number} is missing a case name")
            });
            let expected_kind = parts.next().unwrap_or_else(|| {
                panic!("BLE malformed corpus case {name} is missing an expected kind")
            });
            let expected_context_or_field = parts.next().unwrap_or_else(|| {
                panic!("BLE malformed corpus case {name} is missing an expected context or field")
            });
            let hex = parts
                .next()
                .unwrap_or_else(|| panic!("BLE malformed corpus case {name} is missing hex bytes"));
            assert!(
                parts.next().is_none(),
                "BLE malformed corpus case {name} has too many fields"
            );

            Some(BleMalformedCase {
                name,
                expected: parse_expected_outcome(name, expected_kind, expected_context_or_field),
                bytes: parse_hex(name, hex),
            })
        })
        .collect()
}

fn parse_expected_outcome(
    name: &str,
    expected_kind: &'static str,
    expected_context_or_field: &'static str,
) -> ExpectedOutcome {
    match expected_kind {
        "buffer-too-short" => ExpectedOutcome::BufferTooShort(expected_context_or_field),
        "invalid-field-value" => ExpectedOutcome::InvalidFieldValue(expected_context_or_field),
        "decodes" => ExpectedOutcome::Decodes(expected_context_or_field),
        _ => panic!("BLE malformed corpus case {name} has unknown expected kind {expected_kind}"),
    }
}

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "BLE malformed corpus case {name} has an odd hex length"
    );

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).unwrap_or_else(|_| {
                panic!("BLE malformed corpus case {name} contains non-UTF8 hex")
            });
            u8::from_str_radix(byte, 16).unwrap_or_else(|_| {
                panic!("BLE malformed corpus case {name} has invalid hex {byte}")
            })
        })
        .collect()
}

fn assert_required_ble_resilience_cases(cases: &[BleMalformedCase]) {
    let names = cases.iter().map(|case| case.name).collect::<HashSet<_>>();
    for required in [
        "too-short-pseudo-header",
        "pdu-length-exceeds-buffer",
        "ad-length-runs-past-buffer",
        "unknown-pdu-type-nibble",
        "unknown-ad-type-raw",
        "over-31-octet-ad-payload",
    ] {
        assert!(
            names.contains(required),
            "BLE malformed corpus missing required case {required}"
        );
    }
}

fn assert_buffer_too_short(
    case: &BleMalformedCase,
    expected_context: &'static str,
    decoded: crafter::core::Result<Packet>,
) {
    match decoded {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(
                context, expected_context,
                "BLE malformed corpus case {} returned an unexpected buffer context",
                case.name
            );
            assert!(
                required > available,
                "BLE malformed corpus case {} BufferTooShort must require more ({required}) \
                 than is available ({available})",
                case.name
            );
        }
        other => panic!(
            "BLE malformed corpus case {} expected BufferTooShort, got {other:?}",
            case.name
        ),
    }
}

fn assert_invalid_field_value(
    case: &BleMalformedCase,
    expected_field: &'static str,
    decoded: crafter::core::Result<Packet>,
) {
    match decoded {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(
                field, expected_field,
                "BLE malformed corpus case {} returned an unexpected invalid field",
                case.name
            );
            assert!(
                !reason.is_empty(),
                "BLE malformed corpus case {} InvalidFieldValue must carry a reason",
                case.name
            );
        }
        other => panic!(
            "BLE malformed corpus case {} expected InvalidFieldValue, got {other:?}",
            case.name
        ),
    }
}

fn assert_ble_case_decodes(
    case: &BleMalformedCase,
    expected_marker: &'static str,
    decoded: crafter::core::Result<Packet>,
) {
    let packet = decoded.unwrap_or_else(|err| {
        panic!(
            "BLE malformed corpus case {} should decode: {err}",
            case.name
        )
    });

    assert!(
        !packet.summary().is_empty(),
        "BLE malformed corpus case {} summary should be inspectable",
        case.name
    );
    assert!(
        !packet.show().is_empty(),
        "BLE malformed corpus case {} show output should be inspectable",
        case.name
    );
    let _ = packet.compile().unwrap_or_else(|err| {
        panic!(
            "BLE malformed corpus case {} should compile: {err}",
            case.name
        )
    });

    let adv_debug = format!(
        "{:?}",
        packet.layer::<BleLlAdv>().unwrap_or_else(|| panic!(
            "BLE malformed corpus case {} should carry BleLlAdv",
            case.name
        ))
    );
    match expected_marker {
        "unknown-ad-type" => {
            assert!(
                adv_debug.contains("ad_type: 127"),
                "unknown AD type should be preserved for inspection: {adv_debug}"
            );
        }
        "over-31-ad-payload" => {
            assert!(
                adv_debug.contains("ad_type: 255"),
                "over-31 AD payload should remain inspectable: {adv_debug}"
            );
        }
        _ => panic!(
            "BLE malformed corpus case {} has unknown decode marker {expected_marker}",
            case.name
        ),
    }
}
