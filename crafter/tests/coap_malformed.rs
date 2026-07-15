//! Deterministic malformed-input coverage for the CoAP datagram decoder.
//!
//! Every case is exercised through both public direct decode entrypoints. The
//! decoder receives a slice ending before an in-allocation guard suffix, so
//! truncation outcomes remain pinned to the supplied datagram boundary.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crafter::prelude::*;
use proptest::prelude::*;

const CLIENT_PORT: u16 = 49_152;
const DOC_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 44);
const DOC_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 44);
const MAX_EXTENDED_LENGTH: usize = 65_804;
const MAX_IPV4_UDP_PAYLOAD: usize = (u16::MAX as usize) - 20 - 8;
const DEEP_OPTION_COUNT: usize = 16_384;

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

#[test]
fn coap_extreme_lengths_and_option_repetition_are_panic_free() {
    let maximum_token = maximum_token_datagram();
    assert_eq!(maximum_token.len(), 6 + MAX_EXTENDED_LENGTH);
    assert_direct_decode("maximum-token", &maximum_token, true);

    let maximum_option = maximum_option_datagram();
    assert_eq!(maximum_option.len(), 7 + MAX_EXTENDED_LENGTH);
    assert_direct_decode("maximum-option", &maximum_option, true);

    let maximum_registry_input = maximum_registry_datagram();
    assert_eq!(maximum_registry_input.len(), MAX_IPV4_UDP_PAYLOAD);
    assert_direct_and_registry_decode("maximum-registry-input", &maximum_registry_input, false);

    let repeated_extensions = repeated_extension_overflow_datagram();
    assert_direct_and_registry_decode("repeated-extensions", &repeated_extensions, false);

    let overflow_adjacent = overflow_adjacent_option_datagram();
    assert_direct_and_registry_decode("overflow-adjacent-option", &overflow_adjacent, false);

    let deeply_repeated = deeply_repeated_option_datagram();
    assert_direct_and_registry_decode("deeply-repeated-options", &deeply_repeated, true);
}

#[test]
fn coap_empty_and_every_header_prefix_are_panic_free() {
    let complete_header = [0x40, 0x01, 0x12, 0x34];

    for available in 0..complete_header.len() {
        let input = &complete_header[..available];
        assert_direct_and_registry_decode("header-prefix", input, false);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn arbitrary_coap_slices_never_panic_or_escape_registry_shape_gating(
        input in prop::collection::vec(any::<u8>(), 0..=2_048),
    ) {
        let direct_ok = assert_direct_decode("arbitrary-slice", &input, None);
        let registry_typed = assert_registry_decode("arbitrary-slice", &input);
        let version_one = input
            .first()
            .is_some_and(|first| (first >> 6) == 1);

        prop_assert_eq!(registry_typed, direct_ok && version_one);
    }
}

fn maximum_token_datagram() -> Vec<u8> {
    let capacity = 6usize
        .checked_add(MAX_EXTENDED_LENGTH)
        .expect("maximum token test length is representable");
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&[0x4e, 0x01, 0x12, 0x34, 0xff, 0xff]);
    bytes.resize(capacity, 0xa5);
    bytes
}

fn maximum_option_datagram() -> Vec<u8> {
    let capacity = 7usize
        .checked_add(MAX_EXTENDED_LENGTH)
        .expect("maximum option test length is representable");
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&[0x40, 0x01, 0x12, 0x34, 0x0e, 0xff, 0xff]);
    bytes.resize(capacity, 0x5a);
    bytes
}

fn maximum_registry_datagram() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MAX_IPV4_UDP_PAYLOAD);
    bytes.extend_from_slice(&[0x40, 0x01, 0x12, 0x34, 0x0e, 0xff, 0xff]);
    bytes.resize(MAX_IPV4_UDP_PAYLOAD, 0x5a);
    bytes
}

fn repeated_extension_overflow_datagram() -> Vec<u8> {
    // A zero-length delta-269 option uses a repeated 16-bit extension. The
    // 244th occurrence crosses the u16 option-number domain without wrapping.
    const OCCURRENCES_THROUGH_OVERFLOW: usize = 244;
    let option_bytes = OCCURRENCES_THROUGH_OVERFLOW
        .checked_mul(3)
        .expect("repeated option test length is representable");
    let capacity = 4usize
        .checked_add(option_bytes)
        .expect("repeated option datagram length is representable");
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&[0x40, 0x01, 0x12, 0x34]);
    for _ in 0..OCCURRENCES_THROUGH_OVERFLOW {
        bytes.extend_from_slice(&[0xe0, 0x00, 0x00]);
    }
    bytes
}

fn overflow_adjacent_option_datagram() -> Vec<u8> {
    // 269 + 0xfef2 is exactly 65535; the following direct delta of one must be
    // rejected instead of wrapping the cumulative option number to zero.
    vec![0x40, 0x01, 0x12, 0x34, 0xe0, 0xfe, 0xf2, 0x10]
}

fn deeply_repeated_option_datagram() -> Vec<u8> {
    let capacity = 4usize
        .checked_add(DEEP_OPTION_COUNT)
        .expect("deep option test length is representable");
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&[0x40, 0x01, 0x12, 0x34]);
    bytes.resize(capacity, 0x00);
    bytes
}

fn assert_direct_and_registry_decode(name: &str, input: &[u8], expected_direct_ok: bool) {
    let direct_ok = assert_direct_decode(name, input, Some(expected_direct_ok));
    let registry_typed = assert_registry_decode(name, input);
    let version_one = input.first().is_some_and(|first| (first >> 6) == 1);

    assert_eq!(registry_typed, direct_ok && version_one, "case {name}");
}

fn assert_direct_decode(name: &str, input: &[u8], expected_ok: impl Into<Option<bool>>) -> bool {
    let expected_ok = expected_ok.into();
    let mut first_outcome = None;

    for &(decoder_name, decoder) in PUBLIC_DECODERS {
        let outcome = std::panic::catch_unwind(|| decoder(input)).unwrap_or_else(|_| {
            panic!("CoAP resilience case {name} panicked through {decoder_name}")
        });
        let decoded_ok = outcome.is_ok();

        if let Some(expected_ok) = expected_ok {
            assert_eq!(decoded_ok, expected_ok, "case {name} via {decoder_name}");
        }
        if let Some(first_outcome) = first_outcome {
            assert_eq!(decoded_ok, first_outcome, "case {name} via {decoder_name}");
        } else {
            first_outcome = Some(decoded_ok);
        }

        match outcome {
            Ok(message) => {
                assert!(
                    message.token_value().len() <= input.len(),
                    "case {name} allocated a token beyond its input via {decoder_name}"
                );
                assert!(
                    message.options_value().len() <= input.len(),
                    "case {name} decoded more options than input bytes via {decoder_name}"
                );
                assert!(
                    message
                        .options_value()
                        .iter()
                        .all(|option| option.value().len() <= input.len()),
                    "case {name} allocated an option value beyond its input via {decoder_name}"
                );
                assert!(
                    message.payload_value().len() <= input.len(),
                    "case {name} allocated a payload beyond its input via {decoder_name}"
                );
            }
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert!(context.starts_with("coap."), "case {name} via {decoder_name}");
                assert!(required > available, "case {name} via {decoder_name}");
            }
            Err(CrafterError::InvalidFieldValue { field, reason }) => {
                assert!(field.starts_with("coap."), "case {name} via {decoder_name}");
                assert!(!reason.is_empty(), "case {name} via {decoder_name}");
            }
            Err(other) => panic!(
                "CoAP resilience case {name} returned non-CoAP error through {decoder_name}: {other}"
            ),
        }
    }

    first_outcome.unwrap_or(false)
}

fn assert_registry_decode(name: &str, input: &[u8]) -> bool {
    assert!(
        input.len() <= MAX_IPV4_UDP_PAYLOAD,
        "case {name} exceeds the IPv4 UDP registry boundary"
    );
    let packet = Ipv4::with_addresses(DOC_CLIENT, DOC_SERVER)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / Raw::from_bytes(input);
    let compiled = packet
        .compile()
        .unwrap_or_else(|error| panic!("case {name} failed to compile registry input: {error}"));
    let decoded = std::panic::catch_unwind(|| {
        Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
    })
    .unwrap_or_else(|_| panic!("CoAP resilience case {name} panicked through registry decode"))
    .unwrap_or_else(|error| panic!("CoAP resilience case {name} failed registry decode: {error}"));

    let typed = decoded.layer::<Coap>().is_some();
    if typed {
        assert!(decoded.layer::<Raw>().is_none(), "case {name}");
    } else if input.is_empty() {
        assert!(decoded.layer::<Raw>().is_none(), "case {name}");
    } else {
        assert_eq!(
            decoded
                .layer::<Raw>()
                .unwrap_or_else(|| panic!("case {name} lost its Raw registry fallback"))
                .as_bytes(),
            input,
            "case {name} changed its Raw registry fallback"
        );
    }
    typed
}
