use crafter::prelude::*;

const NTP_EXTENSION_SHORT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/malformed/ntp-extension-short.hex"
));
const NTP_MALFORMED_CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/malformed/ntp-corpus.hex"
));
const REQUIRED_NTP_MALFORMED_CORPUS_CASES: &[&str] = &[
    "short-fixed-header",
    "short-extension-header",
    "invalid-extension-length",
    "truncated-mac-after-extension",
    "ambiguous-legacy-mac-tail",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum NtpMalformedExpected {
    BufferTooShort {
        context: String,
        required: usize,
        available: usize,
    },
    InvalidFieldValue {
        field: String,
    },
    Decodes {
        marker: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NtpMalformedCase {
    name: String,
    expected: NtpMalformedExpected,
    bytes: Vec<u8>,
}

fn valid_ntp_header_with_tail(tail: &[u8]) -> Vec<u8> {
    let mut payload = Packet::from_layer(Ntp::client())
        .compile()
        .unwrap()
        .into_bytes();
    assert_eq!(payload.len(), NTP_FIXED_HEADER_LEN);
    payload.extend_from_slice(tail);
    payload
}

fn decode_without_panic(name: &str, payload: &[u8]) -> crafter::Result<Ntp> {
    std::panic::catch_unwind(|| Ntp::decode(payload))
        .unwrap_or_else(|_| panic!("{name} panicked during NTP decode"))
}

fn decode_err_without_panic(name: &str, payload: &[u8]) -> CrafterError {
    decode_without_panic(name, payload).unwrap_err()
}

fn assert_buffer_too_short(
    name: &str,
    payload: &[u8],
    context: &'static str,
    required: usize,
    available: usize,
) {
    match decode_err_without_panic(name, payload) {
        CrafterError::BufferTooShort {
            context: actual_context,
            required: actual_required,
            available: actual_available,
        } => {
            assert_eq!(actual_context, context, "{name} returned wrong context");
            assert_eq!(
                actual_required, required,
                "{name} returned wrong required byte count"
            );
            assert_eq!(
                actual_available, available,
                "{name} returned wrong available byte count"
            );
        }
        other => panic!("{name} expected BufferTooShort, got {other:?}"),
    }
}

fn assert_invalid_extension_length(name: &str, payload: &[u8]) {
    match decode_err_without_panic(name, payload) {
        CrafterError::InvalidFieldValue { field, reason } => {
            assert_eq!(field, "ntp.extension.length", "{name} returned wrong field");
            assert!(
                !reason.is_empty(),
                "{name} returned an empty invalid-field reason"
            );
        }
        other => panic!("{name} expected InvalidFieldValue, got {other:?}"),
    }
}

fn parse_hex_fixture(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    assert!(hex.len() % 2 == 0, "{name} fixture has an odd hex length");

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("{name} fixture contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("{name} fixture has invalid hex byte {byte}"))
        })
        .collect()
}

fn ntp_malformed_corpus_cases() -> Vec<NtpMalformedCase> {
    NTP_MALFORMED_CORPUS
        .lines()
        .enumerate()
        .filter_map(|(line_number, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let parts = line.split('|').map(str::trim).collect::<Vec<_>>();
            assert_eq!(
                parts.len(),
                6,
                "NTP malformed corpus line {} must have 6 fields",
                line_number + 1
            );
            let name = parts[0].to_string();
            let expected = parse_ntp_malformed_expected(&name, &parts);
            let bytes = parse_hex_fixture(&name, parts[5]);
            Some(NtpMalformedCase {
                name,
                expected,
                bytes,
            })
        })
        .collect()
}

fn parse_ntp_malformed_expected(name: &str, parts: &[&str]) -> NtpMalformedExpected {
    match parts[1] {
        "buffer-too-short" => NtpMalformedExpected::BufferTooShort {
            context: parts[2].to_string(),
            required: parts[3]
                .parse()
                .unwrap_or_else(|_| panic!("case {name} has invalid required byte count")),
            available: parts[4]
                .parse()
                .unwrap_or_else(|_| panic!("case {name} has invalid available byte count")),
        },
        "invalid-field-value" => {
            assert_eq!(parts[3], "-", "case {name} must use '-' for required");
            assert_eq!(parts[4], "-", "case {name} must use '-' for available");
            NtpMalformedExpected::InvalidFieldValue {
                field: parts[2].to_string(),
            }
        }
        "decodes" => {
            assert_eq!(parts[3], "-", "case {name} must use '-' for required");
            assert_eq!(parts[4], "-", "case {name} must use '-' for available");
            NtpMalformedExpected::Decodes {
                marker: parts[2].to_string(),
            }
        }
        expected => panic!("NTP malformed corpus case {name} has unknown kind {expected}"),
    }
}

fn assert_required_ntp_malformed_corpus_cases(cases: &[NtpMalformedCase]) {
    for required in REQUIRED_NTP_MALFORMED_CORPUS_CASES {
        assert!(
            cases.iter().any(|case| case.name == *required),
            "NTP malformed corpus missing required case {required}"
        );
    }
}

fn assert_ntp_malformed_corpus_case(case: &NtpMalformedCase) {
    match &case.expected {
        NtpMalformedExpected::BufferTooShort {
            context,
            required,
            available,
        } => match decode_err_without_panic(&case.name, &case.bytes) {
            CrafterError::BufferTooShort {
                context: actual_context,
                required: actual_required,
                available: actual_available,
            } => {
                assert_eq!(actual_context, context.as_str(), "case {}", case.name);
                assert_eq!(actual_required, *required, "case {}", case.name);
                assert_eq!(actual_available, *available, "case {}", case.name);
            }
            other => panic!(
                "NTP malformed corpus case {} expected BufferTooShort, got {other:?}",
                case.name
            ),
        },
        NtpMalformedExpected::InvalidFieldValue { field } => {
            match decode_err_without_panic(&case.name, &case.bytes) {
                CrafterError::InvalidFieldValue {
                    field: actual_field,
                    reason,
                } => {
                    assert_eq!(actual_field, field.as_str(), "case {}", case.name);
                    assert!(
                        !reason.is_empty(),
                        "case {} InvalidFieldValue must carry a reason",
                        case.name
                    );
                }
                other => panic!(
                    "NTP malformed corpus case {} expected InvalidFieldValue, got {other:?}",
                    case.name
                ),
            }
        }
        NtpMalformedExpected::Decodes { marker } => {
            assert_ntp_malformed_corpus_decode_marker(case, marker);
        }
    }
}

fn assert_ntp_malformed_corpus_decode_marker(case: &NtpMalformedCase, marker: &str) {
    let packet = decode_without_panic(&case.name, &case.bytes)
        .unwrap_or_else(|err| panic!("case {} should decode: {err}", case.name));

    match marker {
        "legacy-mac-20" => {
            assert!(
                packet.extension_fields_value().is_empty(),
                "case {} should not decode extension fields",
                case.name
            );
            let mac = packet
                .legacy_mac_value()
                .unwrap_or_else(|| panic!("case {} should preserve a legacy MAC tail", case.name));
            assert_eq!(mac.len(), 20, "case {} legacy MAC length", case.name);
            assert_eq!(
                mac.key_id(),
                Some(0x0104_000c),
                "case {} legacy MAC key id",
                case.name
            );
            assert_eq!(
                mac.digest(),
                &[0xcc; 16],
                "case {} legacy MAC digest",
                case.name
            );
        }
        other => panic!(
            "NTP malformed corpus case {} has unknown decode marker {other}",
            case.name
        ),
    }
}

#[test]
fn ntp_malformed_corpus_reports_structured_outcomes() {
    let cases = ntp_malformed_corpus_cases();
    assert_required_ntp_malformed_corpus_cases(&cases);

    for case in cases {
        std::panic::catch_unwind(|| assert_ntp_malformed_corpus_case(&case))
            .unwrap_or_else(|_| panic!("NTP malformed corpus case {} panicked", case.name));
    }
}

#[test]
fn ntp_short_header_reports_buffer_too_short_for_every_truncated_length() {
    for len in 0..NTP_FIXED_HEADER_LEN {
        let payload = vec![0; len];

        match Ntp::decode(&payload).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ntp.header");
                assert_eq!(required, NTP_FIXED_HEADER_LEN);
                assert_eq!(available, len);
            }
            other => panic!("length {len} expected BufferTooShort, got {other:?}"),
        }
    }
}

#[test]
fn ntp_malformed_extension_short_headers_report_structured_errors() {
    for tail_len in 1..NTP_EXTENSION_FIELD_HEADER_LEN {
        let tail = vec![0xaa; tail_len];
        let payload = valid_ntp_header_with_tail(&tail);

        assert_buffer_too_short(
            &format!("short extension header with {tail_len} bytes"),
            &payload,
            "ntp.extension",
            NTP_EXTENSION_FIELD_HEADER_LEN,
            tail_len,
        );
    }
}

#[test]
fn ntp_malformed_extension_short_fixture_reports_structured_error() {
    let payload = parse_hex_fixture("ntp-extension-short", NTP_EXTENSION_SHORT_FIXTURE);
    assert_eq!(payload.len(), NTP_FIXED_HEADER_LEN + 3);

    assert_buffer_too_short(
        "ntp-extension-short",
        &payload,
        "ntp.extension",
        NTP_EXTENSION_FIELD_HEADER_LEN,
        3,
    );
}

#[test]
fn ntp_malformed_extension_invalid_lengths_report_structured_errors() {
    let below_minimum = valid_ntp_header_with_tail(&[
        0x01, 0x04, 0x00, 0x0c, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    ]);
    assert_invalid_extension_length("below-minimum extension length", &below_minimum);

    let mut non_aligned_tail = Vec::new();
    non_aligned_tail.extend_from_slice(&0x0104u16.to_be_bytes());
    non_aligned_tail.extend_from_slice(&18u16.to_be_bytes());
    non_aligned_tail.extend_from_slice(&[0xaa; 14]);
    let non_aligned = valid_ntp_header_with_tail(&non_aligned_tail);
    assert_invalid_extension_length("non-aligned extension length", &non_aligned);

    let final_without_mac = valid_ntp_header_with_tail(&[
        0x01, 0x04, 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa,
    ]);
    assert_invalid_extension_length("final 16-byte extension without MAC", &final_without_mac);
}

#[test]
fn ntp_malformed_extension_declared_length_exceeds_available_bytes() {
    let mut tail = Vec::new();
    tail.extend_from_slice(&0x0104u16.to_be_bytes());
    tail.extend_from_slice(&32u16.to_be_bytes());
    tail.extend_from_slice(&[0xaa; 24]);
    let payload = valid_ntp_header_with_tail(&tail);

    assert_buffer_too_short(
        "extension length exceeds available bytes",
        &payload,
        "ntp.extension",
        32,
        tail.len(),
    );
}
