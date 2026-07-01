//! TLS malformed input coverage.
//!
//! These tests stay offline and exercise the public TLS packet-layer primitives.

use crafter::protocols::tls::{
    TlsAlert, TlsAlpnProtocols, TlsCertificate, TlsKeyShare, TlsRawExtension, TlsRecord,
    TlsRecordHeader, TlsServerNameList, TlsSignatureAlgorithms, TLS_ALERT_LEN,
    TLS_CERTIFICATE_LIST_LENGTH_LEN, TLS_EXTENSION_HEADER_LEN, TLS_HANDSHAKE_HEADER_LEN,
    TLS_RECORD_HEADER_LEN,
};
use crafter::{CrafterError, Result};

const TLS_RECORD_MALFORMED_CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/malformed/tls-record-corpus.hex"
));

#[derive(Debug)]
struct TlsRecordMalformedCase {
    name: &'static str,
    target: TlsRecordMalformedTarget,
    context: &'static str,
    required: usize,
    available: usize,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsRecordMalformedTarget {
    Record,
    RecordHeader,
    RecordTailAfterValid,
}

fn assert_buffer_too_short(
    err: CrafterError,
    context: &'static str,
    required: usize,
    available: usize,
) {
    assert_eq!(
        err,
        CrafterError::buffer_too_short(context, required, available)
    );
}

fn tls_record_malformed_cases() -> Vec<TlsRecordMalformedCase> {
    TLS_RECORD_MALFORMED_CORPUS
        .lines()
        .enumerate()
        .filter_map(|(line_index, line)| {
            let line_number = line_index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let parts = line.split('|').collect::<Vec<_>>();
            assert_eq!(
                parts.len(),
                7,
                "TLS record malformed corpus line {line_number} must have 7 fields"
            );

            let name = parts[0];
            let target = parse_tls_record_malformed_target(name, parts[1]);
            assert_eq!(
                parts[2], "buffer-too-short",
                "TLS record malformed corpus case {name} must expect buffer-too-short"
            );
            let context = parse_tls_record_malformed_context(name, parts[3]);
            let required = parse_usize_field(name, "required", parts[4]);
            let available = parse_usize_field(name, "available", parts[5]);
            let bytes = parse_hex(name, parts[6]);

            Some(TlsRecordMalformedCase {
                name,
                target,
                context,
                required,
                available,
                bytes,
            })
        })
        .collect()
}

fn parse_tls_record_malformed_target(name: &str, target: &str) -> TlsRecordMalformedTarget {
    match target {
        "record" => TlsRecordMalformedTarget::Record,
        "record-header" => TlsRecordMalformedTarget::RecordHeader,
        "record-tail-after-valid" => TlsRecordMalformedTarget::RecordTailAfterValid,
        other => panic!("TLS record malformed corpus case {name} has unknown target {other}"),
    }
}

fn parse_tls_record_malformed_context(name: &str, context: &str) -> &'static str {
    match context {
        "tls.record.header" => "tls.record.header",
        "tls.record.fragment" => "tls.record.fragment",
        other => panic!("TLS record malformed corpus case {name} has unknown context {other}"),
    }
}

fn parse_usize_field(name: &str, field: &str, value: &str) -> usize {
    value.parse::<usize>().unwrap_or_else(|_| {
        panic!("TLS record malformed corpus case {name} has invalid {field} value {value}")
    })
}

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "TLS record malformed corpus case {name} has an odd hex length"
    );

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).unwrap_or_else(|_| {
                panic!("TLS record malformed corpus case {name} contains non-UTF8 hex")
            });
            u8::from_str_radix(byte, 16).unwrap_or_else(|_| {
                panic!("TLS record malformed corpus case {name} has invalid hex byte {byte}")
            })
        })
        .collect()
}

fn assert_required_tls_record_malformed_cases(cases: &[TlsRecordMalformedCase]) {
    const REQUIRED: &[&str] = &[
        "empty-record",
        "short-record-header",
        "declared-length-overrun",
        "invalid-first-malformed-record",
        "valid-record-trailing-partial",
    ];

    for required in REQUIRED {
        assert!(
            cases.iter().any(|case| case.name == *required),
            "TLS record malformed corpus missing required case {required}"
        );
    }
}

fn assert_tls_record_malformed_case(case: &TlsRecordMalformedCase) {
    let err = match case.target {
        TlsRecordMalformedTarget::Record => TlsRecord::decode(&case.bytes).unwrap_err(),
        TlsRecordMalformedTarget::RecordHeader => TlsRecordHeader::decode(&case.bytes).unwrap_err(),
        TlsRecordMalformedTarget::RecordTailAfterValid => {
            let (record, tail) = TlsRecord::decode_prefix(&case.bytes)
                .unwrap_or_else(|err| panic!("case {} valid anchor failed: {err}", case.name));
            assert_eq!(
                record.encode_to_vec().expect("valid anchor recompile"),
                case.bytes[..case.bytes.len() - tail.len()]
            );
            assert_eq!(
                tail.len(),
                case.available,
                "case {} tail availability",
                case.name
            );
            TlsRecord::decode(tail).unwrap_err()
        }
    };

    assert_buffer_too_short(err, case.context, case.required, case.available);
}

#[test]
fn tls_malformed_structured_truncation_contexts_are_public() {
    assert_buffer_too_short(
        TlsRecordHeader::decode([0x16, 0x03, 0x03, 0x00]).unwrap_err(),
        "tls.record.header",
        TLS_RECORD_HEADER_LEN,
        4,
    );
    assert_buffer_too_short(
        TlsRecord::decode([0x16, 0x03, 0x03, 0x00, 0x04, 0xaa]).unwrap_err(),
        "tls.record.fragment",
        TLS_RECORD_HEADER_LEN + 4,
        6,
    );
    assert_buffer_too_short(
        crafter::protocols::tls::TlsHandshakeHeader::decode([0x01, 0x00, 0x00]).unwrap_err(),
        "tls.handshake.header",
        TLS_HANDSHAKE_HEADER_LEN,
        3,
    );
    assert_buffer_too_short(
        TlsRawExtension::decode([0x00, 0x00, 0x00]).unwrap_err(),
        "tls.extension",
        TLS_EXTENSION_HEADER_LEN,
        3,
    );
    assert_buffer_too_short(
        TlsSignatureAlgorithms::decode([0x00, 0x04, 0x04, 0x01]).unwrap_err(),
        "tls.signature_algorithms",
        6,
        4,
    );
    assert_buffer_too_short(
        TlsCertificate::decode_tls12([0x00, 0x00]).unwrap_err(),
        "tls.certificate.certificate_list.length",
        TLS_CERTIFICATE_LIST_LENGTH_LEN,
        2,
    );
    assert_buffer_too_short(
        TlsKeyShare::decode_client([0x00, 0x04, 0x00, 0x1d]).unwrap_err(),
        "tls.key_share.client",
        6,
        4,
    );
    assert_buffer_too_short(
        TlsServerNameList::decode([0x00, 0x04, 0x00, 0x00]).unwrap_err(),
        "tls.server_name_list",
        6,
        4,
    );
    assert_buffer_too_short(
        TlsAlpnProtocols::decode([0x00, 0x03, 0x02, b'h']).unwrap_err(),
        "tls.alpn.protocol_name_list",
        5,
        4,
    );
    assert_buffer_too_short(
        TlsAlert::decode([0x01]).unwrap_err(),
        "tls.alert",
        TLS_ALERT_LEN,
        1,
    );
}

#[test]
fn tls_malformed_record_corpus_reports_structured_errors() {
    let cases = tls_record_malformed_cases();
    assert_required_tls_record_malformed_cases(&cases);

    for case in cases {
        std::panic::catch_unwind(|| assert_tls_record_malformed_case(&case))
            .unwrap_or_else(|_| panic!("TLS record malformed corpus case {} panicked", case.name));
    }
}

#[test]
fn tls_malformed_record_sequence_preserves_partial_tail_only_after_valid_anchor() -> Result<()> {
    let first_partial = [0x16, 0x03, 0x03, 0x00, 0x04, 0xaa];
    assert_buffer_too_short(
        TlsRecord::decode(first_partial).unwrap_err(),
        "tls.record.fragment",
        TLS_RECORD_HEADER_LEN + 4,
        first_partial.len(),
    );

    let payload = [
        0x17, 0x03, 0x03, 0x00, 0x03, b'a', b'b', b'c', 0x16, 0x03, 0x03, 0x00, 0x04, 0xde,
    ];
    let (record, tail) = TlsRecord::decode_prefix(&payload)?;

    assert_eq!(record.fragment(), b"abc");
    assert_eq!(tail, &[0x16, 0x03, 0x03, 0x00, 0x04, 0xde]);
    assert_buffer_too_short(
        TlsRecord::decode(tail).unwrap_err(),
        "tls.record.fragment",
        TLS_RECORD_HEADER_LEN + 4,
        tail.len(),
    );

    Ok(())
}
