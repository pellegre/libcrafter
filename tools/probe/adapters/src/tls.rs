//! TLS behavioral probe cases.
//!
//! The probe engine currently plans TLS cases as controlled-service
//! observations. This adapter materializes the stimulus with libcrafter so the
//! dry-run endpoint reports the exact IPv4/TCP/TLS bytes it would send.

use crafter::prelude::*;
use crafter::protocols::tls::TLS_PORT_EXAMPLE_TESTING;
use serde_json::{json, Map, Value};
use std::net::Ipv4Addr;

use crate::common::{
    capture_filter as common_capture_filter, decode_hex, decoded_packet_json, hex_bytes,
    observed_response, plan_json, required_str, required_u16, send_report_json,
    target_service_json, ExampleResult, ProbeOutcome, ProbePlan, StimulusEndpointRequest,
};

pub fn run_tls_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let packet = tls_packet(plan)?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw = report.plan().bytes();
    let sent_raw_hex = hex_bytes(sent_raw);
    let sent_packet = Packet::decode_from_l3(NetworkLayer::Ipv4, sent_raw)?;
    let sent_decoded = decoded_packet_json(&sent_packet, sent_raw);
    let expected_records = expected_records_json(plan);
    let tls_metadata = tls_plan_metadata(plan);
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "sent_decoded": sent_decoded,
            "tls": tls_metadata,
            "expected_records": expected_records,
            "capture_filter": common_capture_filter(plan),
            "target_service": target_service_json(plan),
        }),
    );
    let result = json!({
        "case": plan.case,
        "sequence": plan.sequence,
        "status": "planned",
        "endpoint_role": "stimulus",
        "passed": null,
        "observed_response": observed,
        "metadata": {
            "dry_run": true,
            "probe_plan": plan_json(plan),
            "planned_only": true,
            "sent_raw_hex": sent_raw_hex,
            "sent_decoded": sent_decoded,
            "tls": tls_metadata,
            "expected_records": expected_records,
            "capture_filter": common_capture_filter(plan),
            "target_service": target_service_json(plan),
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn tls_packet(plan: &ProbePlan) -> ExampleResult<Packet> {
    let source: Ipv4Addr = required_str(plan.source_ipv4.as_deref(), "source_ipv4")?.parse()?;
    let destination: Ipv4Addr =
        required_str(plan.destination_ipv4.as_deref(), "destination_ipv4")?.parse()?;
    let source_port = required_u16(plan.source_port, "source_port")?;
    let destination_port = required_u16(plan.destination_port, "destination_port")?;
    let sequence_number = packet_layer_u32(plan, "tcp", &["sequence", "seq"])?.unwrap_or(0);
    let acknowledgment_number =
        packet_layer_u32(plan, "tcp", &["acknowledgement", "acknowledgment", "ack"])?.unwrap_or(0);
    let window = packet_layer_u16(plan, "tcp", &["window"])?.unwrap_or(8192);
    let ttl = packet_layer_u8(plan, "ipv4", &["ttl"])?.unwrap_or(64);
    let flags = tcp_flags(plan)?;
    let records = tls_records(plan)?;

    Ok(Ipv4::new().src(source).dst(destination).ttl(ttl)
        / Tcp::new()
            .sport(source_port)
            .dport(destination_port)
            .seq(sequence_number)
            .ack(acknowledgment_number)
            .flags(flags)
            .window(window)
        / Tls::from_records(records))
}

pub fn tls_json(layer: &Tls) -> Value {
    json!({
        "record_count": layer.record_count(),
        "summary": layer.summary(),
        "records": layer.records().iter().map(tls_record_json).collect::<Vec<_>>(),
    })
}

pub fn capture_filter(plan: &ProbePlan) -> String {
    if let Some(filter) = plan
        .capture_filter
        .as_deref()
        .filter(|filter| !filter.is_empty())
    {
        return filter.to_string();
    }
    if let Some(filter) = object_field(plan.capture.as_ref(), &["filter"]).and_then(Value::as_str) {
        return filter.to_string();
    }
    if let Some(filter) = object_path(
        plan.tls.as_ref(),
        &["expected_observation", "capture_filter"],
    )
    .and_then(Value::as_str)
    {
        return filter.to_string();
    }
    if let Some(filter) =
        object_field(plan.target_service.as_ref(), &["capture_filter"]).and_then(Value::as_str)
    {
        return filter.to_string();
    }
    format!(
        "tcp and port {}",
        plan.destination_port.unwrap_or(TLS_PORT_EXAMPLE_TESTING)
    )
}

pub fn target_service_metadata(plan: &ProbePlan) -> Value {
    plan.target_service.clone().unwrap_or_else(|| {
        json!({
            "required": true,
            "kind": "tls-controlled-service",
            "protocol": "tcp",
            "port": plan.destination_port.unwrap_or(TLS_PORT_EXAMPLE_TESTING),
            "runtime": "probe-tls-reference",
            "deterministic": true,
            "capture_filter": capture_filter(plan),
            "planned_only": plan.planned_only.unwrap_or(true),
        })
    })
}

pub fn validation_json(plan: &ProbePlan) -> Value {
    json!({
        "planned_only": true,
        "driver": "tls_probe",
        "source_ipv4": plan.expected_reply_source_ipv4,
        "destination_ipv4": plan.expected_reply_destination_ipv4,
        "source_port": plan.destination_port,
        "destination_port": plan.source_port,
        "expected_records": expected_records_json(plan),
        "capture_filter": capture_filter(plan),
        "target_behavior": "tls_record_observation",
    })
}

fn tls_plan_metadata(plan: &ProbePlan) -> Value {
    json!({
        "plan": plan.tls,
        "packet_tls": packet_layer_value(plan, "tls").cloned(),
        "expected_records": expected_records_json(plan),
        "target_service": target_service_metadata(plan),
    })
}

fn expected_records_json(plan: &ProbePlan) -> Value {
    if let Some(records) = plan.expected_records.clone() {
        return records;
    }
    if let Some(records) = packet_layer_value(plan, "tls").and_then(|tls| tls.get("records")) {
        return records.clone();
    }
    if let Some(record) = object_field(plan.tls.as_ref(), &["record"]) {
        return json!([record]);
    }
    json!(null)
}

fn tls_records(plan: &ProbePlan) -> ExampleResult<Vec<TlsRecord>> {
    let mut records = Vec::new();
    if let Some(expected_records) = plan.expected_records.as_ref() {
        append_tls_records(expected_records, None, &mut records)?;
        return Ok(records);
    }

    if let Some(tls_fields) = packet_layer_value(plan, "tls").and_then(Value::as_object) {
        if let Some(value) = tls_fields.get("records") {
            append_tls_records(value, Some(tls_fields), &mut records)?;
        } else {
            records.push(tls_record_from_object(tls_fields, Some(tls_fields))?);
        }
        return Ok(records);
    }

    if let Some(tls_plan) = plan.tls.as_ref().and_then(Value::as_object) {
        if let Some(value) = tls_plan.get("record") {
            append_tls_records(value, Some(tls_plan), &mut records)?;
            return Ok(records);
        }
        if let Some(value) = tls_plan.get("records") {
            append_tls_records(value, Some(tls_plan), &mut records)?;
            return Ok(records);
        }
    }

    Err(
        "probe plan missing TLS records under expected_records, packet.tls.records, or tls.record"
            .into(),
    )
}

fn append_tls_records(
    value: &Value,
    fallback: Option<&Map<String, Value>>,
    records: &mut Vec<TlsRecord>,
) -> ExampleResult<()> {
    if let Some(items) = value.as_array() {
        for item in items {
            let record = item
                .as_object()
                .ok_or_else(|| format!("TLS record entry must be an object, got {item:?}"))?;
            records.push(tls_record_from_object(record, fallback)?);
        }
        return Ok(());
    }
    let record = value
        .as_object()
        .ok_or_else(|| format!("TLS record entry must be an object, got {value:?}"))?;
    records.push(tls_record_from_object(record, fallback)?);
    Ok(())
}

fn tls_record_from_object(
    record: &Map<String, Value>,
    fallback: Option<&Map<String, Value>>,
) -> ExampleResult<TlsRecord> {
    let content_type = first_present(record, fallback, &["content_type", "record_content_type"])
        .map(tls_content_type_value)
        .transpose()?
        .unwrap_or(22);
    let fragment = tls_fragment_bytes(content_type, record, fallback)?;
    let legacy_version = first_present(
        record,
        fallback,
        &["legacy_record_version", "record_legacy_version"],
    )
    .map(u16_value)
    .transpose()?
    .unwrap_or(0x0303);
    let declared_length = first_present(
        record,
        fallback,
        &["declared_length", "record_length", "length"],
    )
    .map(declared_length_value)
    .transpose()?
    .flatten();

    let mut tls_record = TlsRecord::from_fragment(TlsContentType::from_u8(content_type), fragment)
        .with_raw_legacy_record_version(legacy_version);
    if let Some(length) = declared_length {
        tls_record = tls_record.with_declared_length(length);
    }
    Ok(tls_record)
}

fn tls_fragment_bytes(
    content_type: u8,
    record: &Map<String, Value>,
    fallback: Option<&Map<String, Value>>,
) -> ExampleResult<Vec<u8>> {
    if let Some(value) = first_present(
        record,
        fallback,
        &[
            "fragment_hex",
            "record_fragment_hex",
            "application_data_hex",
            "raw_fragment_hex",
        ],
    ) {
        return bytes_value(value);
    }

    match content_type {
        20 => Ok(vec![first_present(
            record,
            fallback,
            &["value", "change_cipher_spec"],
        )
        .map(u8_value)
        .transpose()?
        .unwrap_or(1)]),
        21 => {
            let level = first_present(record, fallback, &["level", "alert_level"])
                .map(alert_level_value)
                .transpose()?
                .unwrap_or(2);
            let description =
                first_present(record, fallback, &["description", "alert_description"])
                    .map(alert_description_value)
                    .transpose()?
                    .unwrap_or(50);
            Ok(vec![level, description])
        }
        _ => Err("TLS record missing required fragment_hex or record_fragment_hex".into()),
    }
}

fn tcp_flags(plan: &ProbePlan) -> ExampleResult<u16> {
    let Some(value) = packet_layer_value(plan, "tcp").and_then(|tcp| tcp.get("flags")) else {
        return Ok(TCP_FLAG_PSH | TCP_FLAG_ACK);
    };
    if let Some(flags) = value.as_u64() {
        return Ok(u16::try_from(flags)?);
    }
    let Some(text) = value.as_str() else {
        return Err(format!("unsupported TCP flags value: {value:?}").into());
    };
    let mut flags = 0u16;
    for part in text
        .split(|char: char| char == '|' || char == ',' || char.is_ascii_whitespace())
        .filter(|part| !part.is_empty())
    {
        flags |= match part.to_ascii_lowercase().replace('-', "_").as_str() {
            "fin" => TCP_FLAG_FIN,
            "syn" => TCP_FLAG_SYN,
            "rst" => TCP_FLAG_RST,
            "psh" => TCP_FLAG_PSH,
            "ack" => TCP_FLAG_ACK,
            "urg" => TCP_FLAG_URG,
            "ece" => TCP_FLAG_ECE,
            "cwr" => TCP_FLAG_CWR,
            "ns" => TCP_FLAG_NS,
            other => u16::try_from(integer_text(other)?)?,
        };
    }
    Ok(flags)
}

fn tls_record_json(record: &TlsRecord) -> Value {
    json!({
        "content_type": record.content_type().label(),
        "content_type_raw": record.raw_content_type(),
        "legacy_record_version": record.legacy_record_version().label(),
        "legacy_record_version_raw": record.raw_legacy_record_version(),
        "declared_length": record.declared_length(),
        "fragment_length": record.fragment_len(),
        "fragment_hex": hex_bytes(record.fragment()),
        "summary": record.summary(),
    })
}

fn packet_layer_value<'a>(plan: &'a ProbePlan, layer: &str) -> Option<&'a Value> {
    plan.packet.as_ref().and_then(|packet| packet.get(layer))
}

fn packet_layer_u32(plan: &ProbePlan, layer: &str, names: &[&str]) -> ExampleResult<Option<u32>> {
    packet_layer_value(plan, layer)
        .and_then(|fields| object_field(Some(fields), names))
        .map(u32_value)
        .transpose()
}

fn packet_layer_u16(plan: &ProbePlan, layer: &str, names: &[&str]) -> ExampleResult<Option<u16>> {
    packet_layer_value(plan, layer)
        .and_then(|fields| object_field(Some(fields), names))
        .map(u16_value)
        .transpose()
}

fn packet_layer_u8(plan: &ProbePlan, layer: &str, names: &[&str]) -> ExampleResult<Option<u8>> {
    packet_layer_value(plan, layer)
        .and_then(|fields| object_field(Some(fields), names))
        .map(u8_value)
        .transpose()
}

fn first_present<'a>(
    record: &'a Map<String, Value>,
    fallback: Option<&'a Map<String, Value>>,
    names: &[&str],
) -> Option<&'a Value> {
    for name in names {
        if let Some(value) = record.get(*name) {
            return Some(value);
        }
        if let Some(value) = fallback.and_then(|fields| fields.get(*name)) {
            return Some(value);
        }
    }
    None
}

fn object_field<'a>(value: Option<&'a Value>, names: &[&str]) -> Option<&'a Value> {
    let fields = value.and_then(Value::as_object)?;
    names.iter().find_map(|name| fields.get(*name))
}

fn object_path<'a>(value: Option<&'a Value>, names: &[&str]) -> Option<&'a Value> {
    let mut current = value?;
    for name in names {
        current = current.as_object()?.get(*name)?;
    }
    Some(current)
}

fn tls_content_type_value(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "change_cipher_spec" | "change_cipher" | "ccs" => Ok(20),
            "alert" => Ok(21),
            "handshake" => Ok(22),
            "application_data" | "application" => Ok(23),
            "heartbeat" => Ok(24),
            other => Ok(u8::try_from(integer_text(other)?)?),
        };
    }
    u8_value(value)
}

fn alert_level_value(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "warning" => Ok(1),
            "fatal" => Ok(2),
            other => Ok(u8::try_from(integer_text(other)?)?),
        };
    }
    u8_value(value)
}

fn alert_description_value(value: &Value) -> ExampleResult<u8> {
    if let Some(text) = value.as_str() {
        return match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "close_notify" => Ok(0),
            "unexpected_message" => Ok(10),
            "bad_record_mac" => Ok(20),
            "handshake_failure" => Ok(40),
            "bad_certificate" => Ok(42),
            "unsupported_certificate" => Ok(43),
            "certificate_revoked" => Ok(44),
            "certificate_expired" => Ok(45),
            "certificate_unknown" => Ok(46),
            "illegal_parameter" => Ok(47),
            "unknown_ca" => Ok(48),
            "access_denied" => Ok(49),
            "decode_error" => Ok(50),
            "decrypt_error" => Ok(51),
            "protocol_version" => Ok(70),
            "insufficient_security" => Ok(71),
            "internal_error" => Ok(80),
            "inappropriate_fallback" => Ok(86),
            "user_canceled" => Ok(90),
            "missing_extension" => Ok(109),
            "unsupported_extension" => Ok(110),
            "unrecognized_name" => Ok(112),
            "bad_certificate_status_response" => Ok(113),
            "unknown_psk_identity" => Ok(115),
            "certificate_required" => Ok(116),
            "no_application_protocol" => Ok(120),
            other => Ok(u8::try_from(integer_text(other)?)?),
        };
    }
    u8_value(value)
}

fn declared_length_value(value: &Value) -> ExampleResult<Option<u16>> {
    if let Some(text) = value.as_str() {
        match text.to_ascii_lowercase().replace('-', "_").as_str() {
            "auto" | "derived" => return Ok(None),
            _ => {}
        }
    }
    Ok(Some(u16_value(value)?))
}

fn bytes_value(value: &Value) -> ExampleResult<Vec<u8>> {
    if let Some(text) = value.as_str() {
        return decode_hex(text);
    }
    if let Some(hex) = value
        .as_object()
        .and_then(|fields| fields.get("hex"))
        .and_then(Value::as_str)
    {
        return decode_hex(hex);
    }
    Err(format!("unsupported TLS fragment bytes value: {value:?}").into())
}

fn u8_value(value: &Value) -> ExampleResult<u8> {
    Ok(u8::try_from(u64_value(value)?)?)
}

fn u16_value(value: &Value) -> ExampleResult<u16> {
    Ok(u16::try_from(u64_value(value)?)?)
}

fn u32_value(value: &Value) -> ExampleResult<u32> {
    Ok(u32::try_from(u64_value(value)?)?)
}

fn u64_value(value: &Value) -> ExampleResult<u64> {
    if let Some(value) = value.as_u64() {
        return Ok(value);
    }
    if let Some(value) = value.as_i64() {
        return Ok(u64::try_from(value)?);
    }
    if let Some(text) = value.as_str() {
        return integer_text(text);
    }
    Err(format!("expected integer-compatible value, got {value:?}").into())
}

fn integer_text(value: &str) -> ExampleResult<u64> {
    let text = value.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    Ok(text.parse::<u64>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    fn clienthello_plan() -> ProbePlan {
        let mut plan = base_plan("tls-clienthello-observation");
        plan.source_ipv4 = Some("192.0.2.10".to_string());
        plan.destination_ipv4 = Some("198.51.100.20".to_string());
        plan.expected_reply_source_ipv4 = plan.destination_ipv4.clone();
        plan.expected_reply_destination_ipv4 = plan.source_ipv4.clone();
        plan.source_port = Some(49_152);
        plan.destination_port = Some(TLS_PORT_EXAMPLE_TESTING);
        plan.expected_response = Some("tls_clienthello_observed".to_string());
        plan.packet = Some(json!({
            "stack": ["ipv4", "tcp", "tls"],
            "root": "l3:ipv4",
            "ipv4": {
                "src": "192.0.2.10",
                "dst": "198.51.100.20",
                "ttl": 64,
                "protocol": "tcp",
            },
            "tcp": {
                "src_port": 49152,
                "dst_port": TLS_PORT_EXAMPLE_TESTING,
                "flags": "psh|ack",
                "sequence": 0x11112222u32,
                "acknowledgement": 0x33334444u32,
                "window": 8192,
            },
            "tls": {
                "record_content_type": "handshake",
                "record_legacy_version": 0x0303,
                "record_fragment_hex": "01000000",
                "records": [{
                    "content_type": "handshake",
                    "body_kind": "handshake",
                    "fragment_hex": "01000000",
                    "legacy_record_version": 0x0303
                }]
            },
        }));
        plan.expected_records = Some(json!([{
            "content_type": "handshake",
            "legacy_record_version": 0x0303,
            "fragment_hex": "01000000"
        }]));
        plan.tls = Some(json!({
            "service_name": "tls-controlled-service",
            "record": {
                "content_type": "handshake",
                "fragment_hex": "01000000",
                "legacy_record_version": 0x0303,
            },
            "expected_observation": {
                "record_content_type": "handshake",
                "fragment_hex": "01000000",
                "capture_filter": "tcp and port 4433",
            },
        }));
        plan.target_service = Some(json!({
            "required": true,
            "kind": "tls-controlled-service",
            "protocol": "tcp",
            "port": TLS_PORT_EXAMPLE_TESTING,
            "capture_filter": "tcp and port 4433",
            "planned_only": true,
        }));
        plan
    }

    #[test]
    fn tls_packet_builds_ipv4_tcp_tls_stack() {
        let packet = tls_packet(&clienthello_plan()).unwrap();
        let compiled = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let ipv4 = decoded.layer::<Ipv4>().expect("IPv4 layer");
        let tcp = decoded.layer::<Tcp>().expect("TCP layer");
        let tls = decoded.layer::<Tls>().expect("TLS layer");

        assert_eq!(ipv4.source().to_string(), "192.0.2.10");
        assert_eq!(ipv4.destination().to_string(), "198.51.100.20");
        assert_eq!(tcp.source_port_value(), 49_152);
        assert_eq!(tcp.destination_port_value(), TLS_PORT_EXAMPLE_TESTING);
        assert_eq!(tcp.flags_value(), TCP_FLAG_PSH | TCP_FLAG_ACK);
        assert_eq!(tls.record_count(), 1);
        assert_eq!(tls.records()[0].content_type(), TlsContentType::handshake());
        assert_eq!(tls.records()[0].fragment(), &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tls_packet_can_use_packet_tls_records_when_expected_records_absent() {
        let mut plan = clienthello_plan();
        plan.expected_records = None;

        let packet = tls_packet(&plan).unwrap();
        let tls = packet.layer::<Tls>().expect("TLS layer");

        assert_eq!(tls.records()[0].fragment(), &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn tls_packet_requires_record_bytes() {
        let mut plan = clienthello_plan();
        plan.expected_records = Some(json!([{"content_type": "handshake"}]));
        let err = tls_packet(&plan).unwrap_err().to_string();

        assert!(err.contains("TLS record missing required fragment_hex"));
    }

    #[test]
    fn tls_capture_filter_prefers_nested_plan_filter() {
        let plan = clienthello_plan();

        assert_eq!(capture_filter(&plan), "tcp and port 4433");
    }
}
