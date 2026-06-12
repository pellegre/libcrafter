use crafter::protocols::bgp::decode::decode_bgp_message;
use crafter::CrafterError;

enum ExpectedError {
    BufferTooShort {
        context: &'static str,
        required: usize,
        available: usize,
    },
    InvalidField {
        field: &'static str,
    },
}

struct MalformedCase {
    name: &'static str,
    hex: &'static str,
    expected: ExpectedError,
}

const CASES: &[MalformedCase] = &[
    MalformedCase {
        name: "bgp-header-length-0005",
        hex: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/malformed/bgp-header-length-0005.hex"
        )),
        expected: ExpectedError::InvalidField {
            field: "bgp.header.length",
        },
    },
    MalformedCase {
        name: "bgp-update-attribute-length-overrun",
        hex: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/malformed/bgp-update-attribute-length-overrun.hex"
        )),
        expected: ExpectedError::BufferTooShort {
            context: "bgp update path attributes",
            required: 4,
            available: 0,
        },
    },
    MalformedCase {
        name: "bgp-update-nlri-prefix-overlong",
        hex: include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/malformed/bgp-update-nlri-prefix-overlong.hex"
        )),
        expected: ExpectedError::InvalidField {
            field: "bgp.prefix.length",
        },
    },
];

fn parse_hex(case_name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "{case_name} fixture has an odd hex length"
    );
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("{case_name} fixture contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("{case_name} fixture has invalid hex byte {byte}"))
        })
        .collect()
}

fn assert_expected_error(case: &MalformedCase, error: CrafterError) {
    match (&case.expected, error) {
        (
            ExpectedError::BufferTooShort {
                context,
                required,
                available,
            },
            CrafterError::BufferTooShort {
                context: actual_context,
                required: actual_required,
                available: actual_available,
            },
        ) => {
            assert_eq!(
                actual_context, *context,
                "{} returned the wrong buffer context",
                case.name
            );
            assert_eq!(
                actual_required, *required,
                "{} returned the wrong required byte count",
                case.name
            );
            assert_eq!(
                actual_available, *available,
                "{} returned the wrong available byte count",
                case.name
            );
        }
        (
            ExpectedError::InvalidField { field },
            CrafterError::InvalidFieldValue {
                field: actual_field,
                reason,
            },
        ) => {
            assert_eq!(
                actual_field, *field,
                "{} returned the wrong invalid field",
                case.name
            );
            assert!(
                !reason.is_empty(),
                "{} returned an empty invalid-field reason",
                case.name
            );
        }
        (ExpectedError::BufferTooShort { .. }, other) => {
            panic!("{} expected BufferTooShort, got {other:?}", case.name);
        }
        (ExpectedError::InvalidField { .. }, other) => {
            panic!("{} expected InvalidFieldValue, got {other:?}", case.name);
        }
    }
}

#[test]
fn bgp_malformed_fixtures_return_structured_errors() {
    for case in CASES {
        let bytes = parse_hex(case.name, case.hex);
        let decode_result = std::panic::catch_unwind(|| decode_bgp_message(&bytes))
            .unwrap_or_else(|_| panic!("{} panicked during decode", case.name));
        let error = match decode_result {
            Ok((_bgp, consumed)) => {
                panic!(
                    "{} decoded unexpectedly after consuming {consumed} bytes",
                    case.name
                )
            }
            Err(error) => error,
        };
        assert_expected_error(case, error);
    }
}
