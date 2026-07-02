use crafter::prelude::*;

const NTP_EXTENSION_SHORT_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/malformed/ntp-extension-short.hex"
));

fn valid_ntp_header_with_tail(tail: &[u8]) -> Vec<u8> {
    let mut payload = Packet::from_layer(Ntp::client())
        .compile()
        .unwrap()
        .into_bytes();
    assert_eq!(payload.len(), NTP_FIXED_HEADER_LEN);
    payload.extend_from_slice(tail);
    payload
}

fn decode_err_without_panic(name: &str, payload: &[u8]) -> CrafterError {
    std::panic::catch_unwind(|| Ntp::decode(payload))
        .unwrap_or_else(|_| panic!("{name} panicked during NTP decode"))
        .unwrap_err()
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
