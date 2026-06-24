#[macro_use]
mod support;

use std::collections::HashSet;
use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::mqtt::{MQTT_311_PROTOCOL_LEVEL, MQTT_5_PROTOCOL_LEVEL};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    BufferTooShort(&'static str),
    InvalidFieldValue(&'static str),
    Decodes(&'static str),
}

#[derive(Debug)]
struct MqttMalformedCase {
    name: &'static str,
    expected: ExpectedOutcome,
    default_version: u8,
    bytes: Vec<u8>,
}

#[test]
fn mqtt_resilience_malformed_decode_corpus_reports_structured_outcomes() -> crafter::Result<()> {
    let cases = mqtt_malformed_cases();
    assert_required_mqtt_resilience_cases(&cases);

    for case in cases {
        let decoded = std::panic::catch_unwind(|| decode_malformed_case(&case))
            .unwrap_or_else(|_| panic!("MQTT malformed corpus case {} panicked", case.name));

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

    Ok(())
}

fn decode_malformed_case(case: &MqttMalformedCase) -> crafter::Result<Packet> {
    if case.default_version == MQTT_5_PROTOCOL_LEVEL {
        Mqtt::decode_payload_with_default_version(&case.bytes, MQTT_5_PROTOCOL_LEVEL)
    } else {
        let frame = mqtt_over_ipv4_tcp(&case.bytes)?;
        Packet::decode_from_l3(NetworkLayer::Ipv4, &frame)
    }
}

fn mqtt_over_ipv4_tcp(payload: &[u8]) -> crafter::Result<Vec<u8>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 90))
        .dst(Ipv4Addr::new(198, 51, 100, 90))
        / Tcp::new()
            .sport(49_190)
            .dport(MQTT_PORT)
            .seq(0x3132_3334)
            .ack(0x4142_4344)
            .ack_segment()
        / Raw::from_bytes(payload);

    Ok(packet.compile()?.into_bytes())
}

fn mqtt_malformed_cases() -> Vec<MqttMalformedCase> {
    fixture_str!("malformed/mqtt-decode-corpus.hex")
        .lines()
        .enumerate()
        .filter_map(|(line_index, line)| {
            let line_number = line_index + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }

            let (hex, metadata) = line.split_once('#').unwrap_or_else(|| {
                panic!("MQTT malformed corpus line {line_number} is missing metadata comment")
            });
            let mut parts = metadata.split('|').map(str::trim);
            let name = parts.next().unwrap_or_else(|| {
                panic!("MQTT malformed corpus line {line_number} is missing a case name")
            });
            let expected_kind = parts.next().unwrap_or_else(|| {
                panic!("MQTT malformed corpus case {name} is missing an expected kind")
            });
            let expected_context_or_marker = parts.next().unwrap_or_else(|| {
                panic!("MQTT malformed corpus case {name} is missing an expected context")
            });
            let default_version = match parts.next() {
                Some("v5") => MQTT_5_PROTOCOL_LEVEL,
                Some("v311") | None => MQTT_311_PROTOCOL_LEVEL,
                Some(version) => {
                    panic!("MQTT malformed corpus case {name} has unknown version {version}")
                }
            };
            assert!(
                parts.next().is_none(),
                "MQTT malformed corpus case {name} has too many metadata fields"
            );

            Some(MqttMalformedCase {
                name,
                expected: parse_expected_outcome(name, expected_kind, expected_context_or_marker),
                default_version,
                bytes: parse_hex(name, hex),
            })
        })
        .collect()
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
        _ => panic!("MQTT malformed corpus case {name} has unknown expected kind {expected_kind}"),
    }
}

fn parse_hex(name: &str, hex: &str) -> Vec<u8> {
    let hex = hex
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>();
    assert!(
        hex.len() % 2 == 0,
        "MQTT malformed corpus case {name} has an odd hex length"
    );

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).unwrap_or_else(|_| {
                panic!("MQTT malformed corpus case {name} contains non-UTF8 hex")
            });
            u8::from_str_radix(byte, 16).unwrap_or_else(|_| {
                panic!("MQTT malformed corpus case {name} has invalid hex {byte}")
            })
        })
        .collect()
}

fn assert_required_mqtt_resilience_cases(cases: &[MqttMalformedCase]) {
    let names = cases.iter().map(|case| case.name).collect::<HashSet<_>>();
    for required in [
        "overlong-remaining-length",
        "remaining-length-overruns-buffer",
        "connect-truncated-client-id",
        "publish-topic-overruns-buffer",
        "subscribe-dangling-qos",
        "out-of-range-control-packet-type",
        "v5-connack-property-length-overruns",
        "v5-connack-truncated-property-value",
        "v5-connack-truncated-property-string",
        "v5-publish-property-length-overruns",
    ] {
        assert!(
            names.contains(required),
            "MQTT malformed corpus missing required case {required}"
        );
    }
}

fn assert_buffer_too_short(
    case: &MqttMalformedCase,
    expected_context: &'static str,
    decoded: crafter::Result<Packet>,
) {
    match decoded {
        Err(CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(
                context, expected_context,
                "MQTT malformed corpus case {} returned an unexpected buffer context",
                case.name
            );
            assert!(
                required > available,
                "MQTT malformed corpus case {} BufferTooShort must require more ({required}) \
                 than is available ({available})",
                case.name
            );
        }
        other => panic!(
            "MQTT malformed corpus case {} expected BufferTooShort, got {other:?}",
            case.name
        ),
    }
}

fn assert_invalid_field_value(
    case: &MqttMalformedCase,
    expected_field: &'static str,
    decoded: crafter::Result<Packet>,
) {
    match decoded {
        Err(CrafterError::InvalidFieldValue { field, reason }) => {
            assert_eq!(
                field, expected_field,
                "MQTT malformed corpus case {} returned an unexpected invalid field",
                case.name
            );
            assert!(
                !reason.is_empty(),
                "MQTT malformed corpus case {} InvalidFieldValue must carry a reason",
                case.name
            );
        }
        other => panic!(
            "MQTT malformed corpus case {} expected InvalidFieldValue, got {other:?}",
            case.name
        ),
    }
}

fn assert_case_decodes(
    case: &MqttMalformedCase,
    expected_marker: &'static str,
    decoded: crafter::Result<Packet>,
) {
    let packet = decoded.unwrap_or_else(|err| {
        panic!(
            "MQTT malformed corpus case {} should decode without error: {err}",
            case.name
        )
    });

    assert!(
        !packet.summary().is_empty(),
        "MQTT malformed corpus case {} summary should be inspectable",
        case.name
    );
    assert!(
        !packet.show().is_empty(),
        "MQTT malformed corpus case {} show output should be inspectable",
        case.name
    );

    match expected_marker {
        "raw-tail" => {
            let raw = packet.layers::<Raw>().last().unwrap_or_else(|| {
                panic!(
                    "MQTT malformed corpus case {} should preserve Raw",
                    case.name
                )
            });
            assert_eq!(
                raw.as_bytes(),
                case.bytes.as_slice(),
                "MQTT malformed corpus case {} should preserve the original MQTT bytes as Raw",
                case.name
            );
        }
        _ => panic!(
            "MQTT malformed corpus case {} has unknown decode marker {expected_marker}",
            case.name
        ),
    }
}
