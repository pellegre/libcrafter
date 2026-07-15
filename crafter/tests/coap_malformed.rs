//! Deterministic malformed-input coverage for the CoAP datagram decoder.
//!
//! Every case is exercised through both public direct decode entrypoints. The
//! decoder receives a slice ending before an in-allocation guard suffix, so
//! truncation outcomes remain pinned to the supplied datagram boundary.

use std::collections::HashSet;

use crafter::prelude::*;

const COAP_MALFORMED_CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/malformed/coap-corpus.hex"
));

const REQUIRED_CASES: &[&str] = &[
    "header-empty",
    "header-one-byte",
    "header-two-bytes",
    "header-three-bytes",
    "token-base-missing",
    "token-base-short",
    "token-extended8-missing",
    "token-extended8-short",
    "token-extended16-missing",
    "token-extended16-partial",
    "token-reserved",
    "option-delta-extended8-missing",
    "option-length-extended8-missing",
    "option-delta-extended16-missing",
    "option-delta-extended16-partial",
    "option-length-extended16-missing",
    "option-length-extended16-partial",
    "option-value-missing",
    "option-value-one-byte-short",
    "option-value-two-bytes-short",
    "option-value-extended16-short",
    "option-reserved-delta-f0",
    "option-reserved-delta-fe",
    "option-reserved-length-0f",
    "option-reserved-length-ef",
    "option-number-overflow",
    "payload-marker-without-payload",
    "empty-message-with-token",
    "empty-message-with-option",
    "unknown-option-raw-round-trip",
    "extended-token-269-raw-decode",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    BufferTooShort {
        context: &'static str,
        required: usize,
        available: usize,
    },
    InvalidFieldValue {
        field: &'static str,
        reason: &'static str,
    },
    Decodes {
        marker: &'static str,
    },
}

#[derive(Debug)]
struct CoapMalformedCase {
    name: &'static str,
    expected: ExpectedOutcome,
    bytes: Vec<u8>,
}

type PublicDecoder = fn(&[u8]) -> crafter::Result<Coap>;

const PUBLIC_DECODERS: &[(&str, PublicDecoder)] =
    &[("decode_coap", decode_coap), ("Coap::decode", Coap::decode)];

#[test]
fn coap_malformed_corpus_reports_exact_panic_free_outcomes() {
    let cases = malformed_cases();
    assert_required_cases(&cases);

    for case in &cases {
        for &(decoder_name, decoder) in PUBLIC_DECODERS {
            assert_case_with_decoder(case, decoder_name, decoder);
        }
    }
}

fn malformed_cases() -> Vec<CoapMalformedCase> {
    COAP_MALFORMED_CORPUS
        .lines()
        .enumerate()
        .filter_map(|(line_index, line)| {
            let line_number = line_index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let parts = line.split('|').map(str::trim).collect::<Vec<_>>();
            assert_eq!(
                parts.len(),
                7,
                "CoAP malformed corpus line {line_number} must have 7 fields"
            );

            let name = parts[0];
            assert!(
                !name.is_empty(),
                "CoAP malformed corpus line {line_number} has no name"
            );
            Some(CoapMalformedCase {
                name,
                expected: parse_expected(name, &parts),
                bytes: parse_hex(name, parts[6]),
            })
        })
        .collect()
}

fn parse_expected(name: &str, parts: &[&'static str]) -> ExpectedOutcome {
    match parts[1] {
        "buffer-too-short" => ExpectedOutcome::BufferTooShort {
            context: parts[2],
            required: parse_size(name, "required", parts[3]),
            available: parse_size(name, "available", parts[4]),
        },
        "invalid-field-value" => {
            assert_eq!(parts[3], "-", "case {name} must use '-' for required");
            assert_eq!(parts[4], "-", "case {name} must use '-' for available");
            assert_ne!(parts[5], "-", "case {name} must pin an exact reason");
            ExpectedOutcome::InvalidFieldValue {
                field: parts[2],
                reason: parts[5],
            }
        }
        "decodes" => {
            assert_eq!(parts[3], "-", "case {name} must use '-' for required");
            assert_eq!(parts[4], "-", "case {name} must use '-' for available");
            assert_eq!(parts[5], "-", "case {name} must use '-' for reason");
            ExpectedOutcome::Decodes { marker: parts[2] }
        }
        other => panic!("CoAP malformed corpus case {name} has unknown kind {other}"),
    }
}

fn parse_size(name: &str, field: &str, value: &str) -> usize {
    value
        .parse()
        .unwrap_or_else(|_| panic!("CoAP malformed corpus case {name} has invalid {field} {value}"))
}

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "CoAP malformed corpus case {name} has an odd hex length"
    );

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).unwrap_or_else(|_| {
                panic!("CoAP malformed corpus case {name} contains non-UTF8 hex")
            });
            u8::from_str_radix(byte, 16).unwrap_or_else(|_| {
                panic!("CoAP malformed corpus case {name} has invalid hex {byte}")
            })
        })
        .collect()
}

fn assert_required_cases(cases: &[CoapMalformedCase]) {
    let names = cases.iter().map(|case| case.name).collect::<HashSet<_>>();
    assert_eq!(
        names.len(),
        cases.len(),
        "CoAP malformed corpus case names must be unique"
    );
    for required in REQUIRED_CASES {
        assert!(
            names.contains(required),
            "CoAP malformed corpus missing required case {required}"
        );
    }
}

fn assert_case_with_decoder(case: &CoapMalformedCase, decoder_name: &str, decoder: PublicDecoder) {
    const GUARD_SUFFIX: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0xff, 0x00];

    let visible_len = case.bytes.len();
    let mut guarded = case.bytes.clone();
    guarded.extend_from_slice(GUARD_SUFFIX);
    let datagram = &guarded[..visible_len];

    let decoded = std::panic::catch_unwind(|| decoder(datagram)).unwrap_or_else(|_| {
        panic!(
            "CoAP malformed corpus case {} panicked through {decoder_name}",
            case.name
        )
    });

    assert_eq!(
        &guarded[visible_len..],
        GUARD_SUFFIX,
        "case {} changed bytes beyond its supplied datagram through {decoder_name}",
        case.name
    );
    assert_expected(case, decoder_name, decoded);
}

fn assert_expected(case: &CoapMalformedCase, decoder_name: &str, decoded: crafter::Result<Coap>) {
    match case.expected {
        ExpectedOutcome::BufferTooShort {
            context,
            required,
            available,
        } => match decoded {
            Err(CrafterError::BufferTooShort {
                context: actual_context,
                required: actual_required,
                available: actual_available,
            }) => {
                assert_eq!(actual_context, context, "case {} via {decoder_name}", case.name);
                assert_eq!(actual_required, required, "case {} via {decoder_name}", case.name);
                assert_eq!(actual_available, available, "case {} via {decoder_name}", case.name);
            }
            other => panic!(
                "CoAP malformed corpus case {} expected BufferTooShort through {decoder_name}, got {other:?}",
                case.name
            ),
        },
        ExpectedOutcome::InvalidFieldValue { field, reason } => match decoded {
            Err(CrafterError::InvalidFieldValue {
                field: actual_field,
                reason: actual_reason,
            }) => {
                assert_eq!(actual_field, field, "case {} via {decoder_name}", case.name);
                assert_eq!(actual_reason, reason, "case {} via {decoder_name}", case.name);
            }
            other => panic!(
                "CoAP malformed corpus case {} expected InvalidFieldValue through {decoder_name}, got {other:?}",
                case.name
            ),
        },
        ExpectedOutcome::Decodes { marker } => {
            let message = decoded.unwrap_or_else(|error| {
                panic!(
                    "CoAP malformed corpus case {} should decode through {decoder_name}: {error}",
                    case.name
                )
            });
            assert_decode_marker(case, decoder_name, marker, message);
        }
    }
}

fn assert_decode_marker(case: &CoapMalformedCase, decoder_name: &str, marker: &str, message: Coap) {
    match marker {
        "unknown-option-round-trip" => {
            assert_eq!(message.options_value().len(), 1);
            let option = &message.options_value()[0];
            assert_eq!(option.number().value(), 269);
            assert_eq!(option.value(), [0xaa]);
            assert_eq!(
                option.encoding().and_then(|encoding| encoding.raw_bytes()),
                Some(&[0xe1, 0x00, 0x00][..])
            );

            let recompiled = Packet::from_layer(message)
                .compile()
                .unwrap_or_else(|error| panic!("case {} failed to recompile: {error}", case.name));
            assert_eq!(
                recompiled.as_bytes(),
                case.bytes,
                "case {} did not preserve exact bytes through {decoder_name}",
                case.name
            );
        }
        "extended-token-269" => {
            let token_length = message
                .token_length_value()
                .expect("decoded token-length metadata is present");
            assert_eq!(token_length.nibble(), 14);
            assert_eq!(token_length.extension_bytes(), [0x00, 0x00]);
            assert_eq!(token_length.declared_len(), 269);
            assert_eq!(message.token_value().len(), 269);
            assert_eq!(message.token_value().as_bytes(), &case.bytes[6..]);
        }
        other => panic!(
            "CoAP malformed corpus case {} has unknown decode marker {other}",
            case.name
        ),
    }
}
