//! MQTT probe cases: planned CONNECT/CONNACK, SUBSCRIBE/SUBACK, and QoS 1
//! PUBLISH/PUBACK exchanges against a probe-owned Mosquitto broker.
//!
//! Dry-run compiles inspectable IPv4/TCP/MQTT packet plans without sending
//! traffic. Live mode is an explicit TCP application session: it connects to
//! the broker, sends CONNECT, validates CONNACK, then sends the case-specific
//! MQTT packet and validates the broker reply.

use crafter::prelude::*;
use crafter::protocols::mqtt::{MQTT_CONNACK_ACCEPTED, MQTT_PUBLISH_QOS_1, MQTT_SUBACK_FAILURE};
use serde_json::{json, Value};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::common::{
    capture_filter, expected_response, failed_outcome, hex_bytes, observed_response, plan_json,
    required_str, send_report_json, target_service_json, ExampleResult, ProbeOutcome, ProbePlan,
    StimulusEndpointRequest, FAILURE_DECODE_FAILED, FAILURE_TIMEOUT, FAILURE_WRONG_PAYLOAD,
};

const DEFAULT_CLIENT_ID_PREFIX: &str = "crafter-probe";
const DEFAULT_SUBSCRIBE_TOPIC: &str = "crafter/probe/inbound";
const DEFAULT_PUBLISH_TOPIC: &str = "crafter/probe/outbound";
const DEFAULT_PUBLISH_PAYLOAD: &[u8] = b"hello from crafter probe";
const SUBSCRIBE_PACKET_ID: u16 = 1;
const PUBLISH_PACKET_ID: u16 = 2;
const DEFAULT_SOURCE_PORT_BASE: u16 = 49_194;

#[derive(Debug, Clone, Copy)]
enum ExpectedMqttReply {
    ConnackAccepted,
    Suback { packet_id: u16 },
    Puback { packet_id: u16 },
}

impl ExpectedMqttReply {
    fn label(self) -> &'static str {
        match self {
            Self::ConnackAccepted => "CONNACK",
            Self::Suback { .. } => "SUBACK",
            Self::Puback { .. } => "PUBACK",
        }
    }

    fn response_type(self) -> &'static str {
        match self {
            Self::ConnackAccepted => "mqtt_connack",
            Self::Suback { .. } => "mqtt_suback",
            Self::Puback { .. } => "mqtt_puback",
        }
    }
}

#[derive(Debug, Clone)]
struct PlannedMqttMessage {
    label: &'static str,
    mqtt: Mqtt,
    expected_reply: ExpectedMqttReply,
}

pub fn run_mqtt_dry_run(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let message = case_message(plan)?;
    let packet = mqtt_packet(request, plan, message.mqtt.clone())?;
    let report = SocketSender::new(
        SendOptions::new()
            .iface(request.interface.clone())
            .network_layer()
            .dry_run(),
    )
    .send(&packet)?;
    let sent_raw_hex = hex_bytes(report.plan().bytes());
    let mqtt_raw_hex = hex_bytes(&mqtt_wire_bytes(&message.mqtt)?);
    let exchange = mqtt_exchange_json(plan, &message, &mqtt_raw_hex);
    let observed = observed_response(
        plan,
        false,
        None,
        json!({}),
        json!({
            "planned_only": true,
            "send_report": send_report_json(&report),
            "sent_raw_hex": sent_raw_hex,
            "mqtt_raw_hex": mqtt_raw_hex,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "exchange": exchange,
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
            "mqtt_raw_hex": mqtt_raw_hex,
            "capture_filter": capture_filter(plan),
            "target_service": target_service_json(plan),
            "exchange": exchange,
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent: false,
        received: false,
    })
}

pub fn run_mqtt_live(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
) -> ExampleResult<ProbeOutcome> {
    let scenario = live_scenario(plan)?;
    let peer = broker_addr(request, plan)?;
    let timeout = Duration::from_secs(request.timeout_seconds.max(1));
    let mut stream = match TcpStream::connect_timeout(&peer, timeout) {
        Ok(stream) => stream,
        Err(err) => {
            return Ok(failed_outcome(
                plan,
                FAILURE_TIMEOUT,
                vec![format!("connect to MQTT broker {peer} failed: {err}")],
                Some(json!({ "broker": peer.to_string() })),
                false,
                false,
            ));
        }
    };
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut transcript = Vec::new();
    let mut sent = false;
    let mut received_any = false;
    let mut last_observed = None;

    for message in scenario {
        match send_message(&mut stream, &message) {
            Ok(sent_hex) => {
                sent = true;
                transcript.push(json!({
                    "direction": "sent",
                    "label": message.label,
                    "mqtt_raw_hex": sent_hex,
                    "summary": message.mqtt.summary(),
                }));
            }
            Err(err) => {
                return Ok(failed_outcome(
                    plan,
                    FAILURE_DECODE_FAILED,
                    vec![format!("MQTT send failed: {err}")],
                    Some(json!({ "broker": peer.to_string(), "exchange": transcript })),
                    sent,
                    received_any,
                ));
            }
        }

        let received = match read_mqtt_message(&mut stream) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                return Ok(failed_outcome(
                    plan,
                    FAILURE_TIMEOUT,
                    vec![format!(
                        "timed out waiting for {}",
                        message.expected_reply.label()
                    )],
                    Some(json!({ "broker": peer.to_string(), "exchange": transcript })),
                    sent,
                    received_any,
                ));
            }
            Err(err) => {
                return Ok(failed_outcome(
                    plan,
                    FAILURE_DECODE_FAILED,
                    vec![format!("MQTT receive failed: {err}")],
                    Some(json!({ "broker": peer.to_string(), "exchange": transcript })),
                    sent,
                    received_any,
                ));
            }
        };
        received_any = true;

        let packet = match decode_mqtt_payload(request, plan, &received) {
            Ok(packet) => packet,
            Err(err) => {
                return Ok(failed_outcome(
                    plan,
                    FAILURE_DECODE_FAILED,
                    vec![format!("MQTT reply decode failed: {err}")],
                    Some(json!({
                        "broker": peer.to_string(),
                        "exchange": transcript,
                        "raw_hex": hex_bytes(&received),
                    })),
                    sent,
                    true,
                ));
            }
        };
        let decoded = mqtt_decoded_json(&packet, &received);
        transcript.push(json!({
            "direction": "received",
            "label": message.expected_reply.label(),
            "raw_hex": hex_bytes(&received),
            "decoded": decoded,
        }));
        last_observed = Some((received, decoded.clone(), message.expected_reply));

        if let Err(mismatches) = validate_expected_reply(&packet, message.expected_reply) {
            return Ok(failed_outcome(
                plan,
                FAILURE_WRONG_PAYLOAD,
                vec![format!(
                    "MQTT reply did not match expected {}",
                    message.expected_reply.label()
                )],
                Some(json!({
                    "broker": peer.to_string(),
                    "exchange": transcript,
                    "decoded": decoded,
                    "mismatches": mismatches,
                })),
                sent,
                true,
            ));
        }
    }

    stream.shutdown(std::net::Shutdown::Both).ok();

    let (raw, decoded, expected) =
        last_observed.ok_or("MQTT live scenario did not contain an expected reply")?;
    let raw_hex = hex_bytes(&raw);
    let observed = observed_response(
        plan,
        true,
        Some(raw_hex.clone()),
        decoded.clone(),
        json!({
            "broker": peer.to_string(),
            "response_type": expected.response_type(),
            "exchange": transcript,
        }),
    );
    let result = json!({
        "case": plan.case,
        "sequence": plan.sequence,
        "status": "passed",
        "endpoint_role": "stimulus",
        "passed": true,
        "observed_response": observed,
        "metadata": {
            "dry_run": false,
            "probe_plan": plan_json(plan),
            "raw_hex": raw_hex,
            "decoded": decoded,
            "broker": peer.to_string(),
            "exchange": transcript,
        }
    });
    Ok(ProbeOutcome {
        result,
        observed_response: observed,
        sent,
        received: received_any,
    })
}

fn case_message(plan: &ProbePlan) -> ExampleResult<PlannedMqttMessage> {
    Ok(match plan.case.as_str() {
        "mqtt-connect-connack" => connect_message(plan),
        "mqtt-subscribe-suback" => subscribe_message(),
        "mqtt-publish-puback" => publish_message(),
        _ => return Err(format!("unsupported MQTT probe case: {}", plan.case).into()),
    })
}

fn live_scenario(plan: &ProbePlan) -> ExampleResult<Vec<PlannedMqttMessage>> {
    let connect = connect_message(plan);
    Ok(match plan.case.as_str() {
        "mqtt-connect-connack" => vec![connect],
        "mqtt-subscribe-suback" => vec![connect, subscribe_message()],
        "mqtt-publish-puback" => vec![connect, publish_message()],
        _ => return Err(format!("unsupported MQTT probe case: {}", plan.case).into()),
    })
}

fn connect_message(plan: &ProbePlan) -> PlannedMqttMessage {
    PlannedMqttMessage {
        label: "CONNECT",
        mqtt: Mqtt::connect()
            .client_id(format!("{DEFAULT_CLIENT_ID_PREFIX}-{}", plan.sequence))
            .keep_alive(30)
            .clean_session(true),
        expected_reply: ExpectedMqttReply::ConnackAccepted,
    }
}

fn subscribe_message() -> PlannedMqttMessage {
    PlannedMqttMessage {
        label: "SUBSCRIBE",
        mqtt: Mqtt::subscribe()
            .packet_id(SUBSCRIBE_PACKET_ID)
            .subscribe_topic(DEFAULT_SUBSCRIBE_TOPIC, MQTT_PUBLISH_QOS_1),
        expected_reply: ExpectedMqttReply::Suback {
            packet_id: SUBSCRIBE_PACKET_ID,
        },
    }
}

fn publish_message() -> PlannedMqttMessage {
    PlannedMqttMessage {
        label: "PUBLISH QoS1",
        mqtt: Mqtt::publish()
            .topic(DEFAULT_PUBLISH_TOPIC)
            .qos(MQTT_PUBLISH_QOS_1)
            .packet_id(PUBLISH_PACKET_ID)
            .payload(DEFAULT_PUBLISH_PAYLOAD.to_vec()),
        expected_reply: ExpectedMqttReply::Puback {
            packet_id: PUBLISH_PACKET_ID,
        },
    }
}

fn mqtt_packet(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    mqtt: Mqtt,
) -> ExampleResult<Packet> {
    let source: Ipv4Addr = plan
        .source_ipv4
        .as_deref()
        .unwrap_or(&request.local_ipv4)
        .parse()?;
    let destination: Ipv4Addr = plan
        .destination_ipv4
        .as_deref()
        .unwrap_or(&request.peer_ipv4)
        .parse()?;
    Ok(Ipv4::new()
        .src(source)
        .dst(destination)
        .protocol(IPPROTO_TCP)
        / Tcp::new()
            .sport(source_port(plan))
            .dport(destination_port(plan))
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / mqtt)
}

fn broker_addr(request: &StimulusEndpointRequest, plan: &ProbePlan) -> ExampleResult<SocketAddr> {
    let host = plan
        .destination_ipv4
        .as_deref()
        .unwrap_or(&request.peer_ipv4);
    let ip: Ipv4Addr = required_str(Some(host), "destination_ipv4")?.parse()?;
    Ok(SocketAddr::from((ip, destination_port(plan))))
}

fn source_port(plan: &ProbePlan) -> u16 {
    plan.source_port
        .unwrap_or_else(|| DEFAULT_SOURCE_PORT_BASE.saturating_add((plan.sequence % 1000) as u16))
}

fn destination_port(plan: &ProbePlan) -> u16 {
    plan.destination_port.unwrap_or(MQTT_PORT)
}

fn mqtt_wire_bytes(mqtt: &Mqtt) -> ExampleResult<Vec<u8>> {
    let compiled = Packet::from_layer(mqtt.clone()).compile()?;
    Ok(compiled.as_bytes().to_vec())
}

fn send_message(stream: &mut TcpStream, message: &PlannedMqttMessage) -> ExampleResult<String> {
    let bytes = mqtt_wire_bytes(&message.mqtt)?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(hex_bytes(&bytes))
}

fn read_mqtt_message(stream: &mut TcpStream) -> ExampleResult<Option<Vec<u8>>> {
    let mut first = [0u8; 1];
    match stream.read_exact(&mut first) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::UnexpectedEof
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    }

    let mut bytes = vec![first[0]];
    let mut remaining_length = 0usize;
    let mut multiplier = 1usize;
    for offset in 0..4 {
        let mut encoded = [0u8; 1];
        stream.read_exact(&mut encoded)?;
        bytes.push(encoded[0]);
        remaining_length = remaining_length
            .checked_add(usize::from(encoded[0] & 0x7f) * multiplier)
            .ok_or("MQTT Remaining Length overflowed usize")?;
        if encoded[0] & 0x80 == 0 {
            let header_len = 1 + offset + 1;
            bytes.resize(header_len + remaining_length, 0);
            if remaining_length > 0 {
                stream.read_exact(&mut bytes[header_len..])?;
            }
            return Ok(Some(bytes));
        }
        if offset == 3 {
            return Err("MQTT Remaining Length used more than four bytes".into());
        }
        multiplier *= 128;
    }

    unreachable!("MQTT Remaining Length loop is bounded to four bytes")
}

fn decode_mqtt_payload(
    request: &StimulusEndpointRequest,
    plan: &ProbePlan,
    bytes: &[u8],
) -> ExampleResult<Packet> {
    let source: Ipv4Addr = plan
        .destination_ipv4
        .as_deref()
        .unwrap_or(&request.peer_ipv4)
        .parse()?;
    let destination: Ipv4Addr = plan
        .source_ipv4
        .as_deref()
        .unwrap_or(&request.local_ipv4)
        .parse()?;
    let wrapped = (Ipv4::new()
        .src(source)
        .dst(destination)
        .protocol(IPPROTO_TCP)
        / Tcp::new()
            .sport(destination_port(plan))
            .dport(source_port(plan))
        / Raw::from_bytes(bytes))
    .compile()?;
    Ok(Packet::decode_from_l3(
        NetworkLayer::Ipv4,
        wrapped.as_bytes(),
    )?)
}

fn validate_expected_reply(
    packet: &Packet,
    expected: ExpectedMqttReply,
) -> std::result::Result<(), Vec<Value>> {
    let Some(mqtt) = packet.layer::<Mqtt>() else {
        return Err(vec![json!({
            "field": "mqtt",
            "expected": "present",
            "actual": "missing",
        })]);
    };

    let mut mismatches = Vec::new();
    match expected {
        ExpectedMqttReply::ConnackAccepted => {
            if mqtt.packet_type() != MqttControlPacketType::Connack {
                mismatches.push(packet_type_mismatch(mqtt, "CONNACK"));
            }
            if mqtt.return_code_value() != Some(MQTT_CONNACK_ACCEPTED) {
                mismatches.push(json!({
                    "field": "mqtt.return_code",
                    "expected": MQTT_CONNACK_ACCEPTED,
                    "actual": mqtt.return_code_value(),
                }));
            }
        }
        ExpectedMqttReply::Suback { packet_id } => {
            if mqtt.packet_type() != MqttControlPacketType::Suback {
                mismatches.push(packet_type_mismatch(mqtt, "SUBACK"));
            }
            if mqtt.packet_id_value() != Some(packet_id) {
                mismatches.push(json!({
                    "field": "mqtt.packet_id",
                    "expected": packet_id,
                    "actual": mqtt.packet_id_value(),
                }));
            }
            if mqtt
                .suback_return_codes_value()
                .unwrap_or(&[])
                .contains(&MQTT_SUBACK_FAILURE)
            {
                mismatches.push(json!({
                    "field": "mqtt.suback_return_codes",
                    "expected": "no failure return code",
                    "actual": mqtt.suback_return_codes_value(),
                }));
            }
        }
        ExpectedMqttReply::Puback { packet_id } => {
            if mqtt.packet_type() != MqttControlPacketType::Puback {
                mismatches.push(packet_type_mismatch(mqtt, "PUBACK"));
            }
            if mqtt.packet_id_value() != Some(packet_id) {
                mismatches.push(json!({
                    "field": "mqtt.packet_id",
                    "expected": packet_id,
                    "actual": mqtt.packet_id_value(),
                }));
            }
        }
    }

    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches)
    }
}

fn packet_type_mismatch(mqtt: &Mqtt, expected: &str) -> Value {
    json!({
        "field": "mqtt.packet_type",
        "expected": expected,
        "actual": format!("{:?}", mqtt.packet_type()),
    })
}

pub fn mqtt_json(mqtt: &Mqtt) -> Value {
    json!({
        "packet_type": format!("{:?}", mqtt.packet_type()),
        "flags": mqtt.flags_value(),
        "remaining_length": mqtt.remaining_length_value(),
        "client_id": mqtt.client_id_value(),
        "return_code": mqtt.return_code_value(),
        "topic": mqtt.topic_value(),
        "qos": mqtt.qos_value(),
        "packet_id": mqtt.packet_id_value(),
        "subscribe_topics": mqtt.subscribe_topics_value(),
        "suback_return_codes": mqtt.suback_return_codes_value(),
        "payload_hex": mqtt.payload_value().map(hex_bytes),
        "summary": mqtt.summary(),
    })
}

fn mqtt_decoded_json(packet: &Packet, raw: &[u8]) -> Value {
    json!({
        "summary": packet.summary(),
        "raw_hex": hex_bytes(raw),
        "mqtt": packet.layer::<Mqtt>().map(mqtt_json),
    })
}

fn mqtt_exchange_json(plan: &ProbePlan, message: &PlannedMqttMessage, raw_hex: &str) -> Value {
    json!({
        "label": message.label,
        "case": plan.case,
        "mqtt_raw_hex": raw_hex,
        "expected_reply": message.expected_reply.label(),
        "expected_response": expected_response(plan),
        "source_port": source_port(plan),
        "destination_port": destination_port(plan),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::base_plan;

    #[test]
    fn case_messages_select_expected_packet_types() {
        let connect = case_message(&base_plan("mqtt-connect-connack")).unwrap();
        let subscribe = case_message(&base_plan("mqtt-subscribe-suback")).unwrap();
        let publish = case_message(&base_plan("mqtt-publish-puback")).unwrap();

        assert_eq!(connect.mqtt.packet_type(), MqttControlPacketType::Connect);
        assert_eq!(
            subscribe.mqtt.packet_type(),
            MqttControlPacketType::Subscribe
        );
        assert_eq!(publish.mqtt.packet_type(), MqttControlPacketType::Publish);
    }

    #[test]
    fn expected_reply_validation_accepts_connack() {
        let bytes = mqtt_wire_bytes(&Mqtt::connack()).unwrap();
        let request = StimulusEndpointRequest {
            provider: "qemu".to_string(),
            profile: "mqtt-smoke".to_string(),
            seed: 1,
            endpoint_role: "stimulus".to_string(),
            interface: "eth0".to_string(),
            local_ipv4: "192.0.2.10".to_string(),
            peer_ipv4: "192.0.2.20".to_string(),
            timeout_seconds: 1,
            probe_plans: vec![],
            artifact_paths: json!({}),
            metadata: json!({}),
        };
        let plan = base_plan("mqtt-connect-connack");
        let decoded = decode_mqtt_payload(&request, &plan, &bytes).unwrap();

        assert!(validate_expected_reply(&decoded, ExpectedMqttReply::ConnackAccepted).is_ok());
    }
}
