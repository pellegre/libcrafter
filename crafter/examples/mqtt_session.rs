mod common;

use common::{
    arg_value, flag_present, print_help_if_requested, print_packet_plan, ExampleResult, LOCAL_IPV4,
    REMOTE_IPV4,
};
use crafter::prelude::*;
use crafter::protocols::mqtt::{MQTT_CONNACK_ACCEPTED, MQTT_PUBLISH_QOS_1, MQTT_SUBACK_FAILURE};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_OUT_DIR: &str = "target/lab/mqtt";
const DEFAULT_CLIENT_ID: &str = "crafter-client";
const DEFAULT_SUBSCRIBE_TOPIC: &str = "crafter/demo/inbound";
const DEFAULT_PUBLISH_TOPIC: &str = "crafter/demo/outbound";
const DEFAULT_PAYLOAD: &[u8] = b"hello from crafter";
const SUBSCRIBE_PACKET_ID: u16 = 1;
const PUBLISH_PACKET_ID: u16 = 2;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const OFFLINE_SOURCE_PORT: u16 = 49_194;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example mqtt_session -- [--peer IP:PORT] [--out DIR]\n\nBuild an offline MQTT CONNECT/SUBSCRIBE/PUBLISH/PINGREQ/DISCONNECT plan by default. --peer opens an opt-in live TCP session to an explicitly provided MQTT broker and writes a transcript under --out.",
    ) {
        return Ok(());
    }

    let config = Config::from_args()?;
    if config.peer.is_some() {
        return run_live(&config);
    }

    println!("example: mqtt_session");
    println!("mode: offline");
    println!("client id: {DEFAULT_CLIENT_ID}");
    println!("subscribe topic: {DEFAULT_SUBSCRIBE_TOPIC}");
    println!("publish topic: {DEFAULT_PUBLISH_TOPIC}");
    println!("source: {LOCAL_IPV4}:{OFFLINE_SOURCE_PORT}");
    println!("destination: {REMOTE_IPV4}:{MQTT_PORT}");

    for message in mqtt_message_plan() {
        let packet = offline_packet(message.mqtt.clone());
        print_packet_plan(message.label, &packet)?;
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct Config {
    peer: Option<SocketAddr>,
    out_dir: PathBuf,
}

impl Config {
    fn from_args() -> ExampleResult<Self> {
        Ok(Self {
            peer: parse_peer()?,
            out_dir: arg_value("--out")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_OUT_DIR)),
        })
    }

    #[cfg(test)]
    fn offline_default() -> Self {
        Self {
            peer: None,
            out_dir: PathBuf::from(DEFAULT_OUT_DIR),
        }
    }
}

fn parse_peer() -> ExampleResult<Option<SocketAddr>> {
    let peer = arg_value("--peer");
    if peer.is_none() && flag_present("--peer") {
        return Err("--peer expects IP:PORT".into());
    }

    match peer {
        Some(value) => Ok(Some(value.parse()?)),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedReply {
    ConnackAccepted,
    Suback { packet_id: u16 },
    Puback { packet_id: u16 },
    Pingresp,
}

#[derive(Debug, Clone)]
struct PlannedMessage {
    label: &'static str,
    mqtt: Mqtt,
    expected_reply: Option<ExpectedReply>,
}

fn mqtt_message_plan() -> Vec<PlannedMessage> {
    vec![
        PlannedMessage {
            label: "CONNECT",
            mqtt: Mqtt::connect()
                .client_id(DEFAULT_CLIENT_ID)
                .keep_alive(30)
                .clean_session(true),
            expected_reply: Some(ExpectedReply::ConnackAccepted),
        },
        PlannedMessage {
            label: "SUBSCRIBE",
            mqtt: Mqtt::subscribe()
                .packet_id(SUBSCRIBE_PACKET_ID)
                .subscribe_topic(DEFAULT_SUBSCRIBE_TOPIC, MQTT_PUBLISH_QOS_1),
            expected_reply: Some(ExpectedReply::Suback {
                packet_id: SUBSCRIBE_PACKET_ID,
            }),
        },
        PlannedMessage {
            label: "PUBLISH QoS1",
            mqtt: Mqtt::publish()
                .topic(DEFAULT_PUBLISH_TOPIC)
                .qos(MQTT_PUBLISH_QOS_1)
                .packet_id(PUBLISH_PACKET_ID)
                .payload(DEFAULT_PAYLOAD.to_vec()),
            expected_reply: Some(ExpectedReply::Puback {
                packet_id: PUBLISH_PACKET_ID,
            }),
        },
        PlannedMessage {
            label: "PINGREQ",
            mqtt: Mqtt::pingreq(),
            expected_reply: Some(ExpectedReply::Pingresp),
        },
        PlannedMessage {
            label: "DISCONNECT",
            mqtt: Mqtt::disconnect(),
            expected_reply: None,
        },
    ]
}

fn offline_packet(mqtt: Mqtt) -> Packet {
    Ipv4::new()
        .src(LOCAL_IPV4)
        .dst(REMOTE_IPV4)
        .protocol(IPPROTO_TCP)
        / Tcp::new()
            .sport(OFFLINE_SOURCE_PORT)
            .dport(MQTT_PORT)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / mqtt
}

fn run_live(config: &Config) -> ExampleResult<()> {
    let mut transcript = Transcript::new();
    let result = run_live_inner(config, &mut transcript);
    let write_result = transcript.write(&config.out_dir, config);

    match write_result {
        Ok(path) => println!("transcript: {}", path.display()),
        Err(error) if result.is_ok() => return Err(error.into()),
        Err(error) => eprintln!("failed to write transcript: {error}"),
    }

    result
}

fn run_live_inner(config: &Config, transcript: &mut Transcript) -> ExampleResult<()> {
    let peer = config.peer.expect("live mode requires peer");
    println!("example: mqtt_session");
    println!("mode: live");
    println!("peer: {peer}");
    println!("transcript directory: {}", config.out_dir.display());

    let mut stream = TcpStream::connect_timeout(&peer, CONNECT_TIMEOUT)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;

    for message in mqtt_message_plan() {
        send_planned(&mut stream, transcript, &message)?;
        if let Some(expected) = message.expected_reply {
            receive_required(&mut stream, transcript, expected)?;
        }
    }

    stream.shutdown(std::net::Shutdown::Both).ok();
    Ok(())
}

fn send_planned(
    stream: &mut TcpStream,
    transcript: &mut Transcript,
    message: &PlannedMessage,
) -> ExampleResult<()> {
    let packet = Packet::from_layer(message.mqtt.clone());
    let compiled = packet.compile()?;
    stream.write_all(compiled.as_bytes())?;
    stream.flush()?;
    let summary = packet.summary();
    println!("sent {}: {}", message.label, summary);
    transcript.record("sent", message.label, &summary, compiled.as_bytes());
    Ok(())
}

fn receive_required(
    stream: &mut TcpStream,
    transcript: &mut Transcript,
    expected: ExpectedReply,
) -> ExampleResult<()> {
    let Some(bytes) = read_mqtt_message(stream)? else {
        return Err(format!("timed out waiting for {}", expected.label()).into());
    };

    let decoded = decode_mqtt_payload(&bytes)?;
    let mqtt = decoded
        .layer::<Mqtt>()
        .ok_or_else(|| format!("reply did not decode as MQTT: {}", decoded.summary()))?;

    validate_expected_reply(mqtt, expected)?;
    let summary = mqtt.summary();
    println!("received {}: {summary}", expected.label());
    transcript.record("received", expected.label(), &summary, &bytes);
    Ok(())
}

impl ExpectedReply {
    fn label(self) -> &'static str {
        match self {
            Self::ConnackAccepted => "CONNACK",
            Self::Suback { .. } => "SUBACK",
            Self::Puback { .. } => "PUBACK",
            Self::Pingresp => "PINGRESP",
        }
    }
}

fn validate_expected_reply(mqtt: &Mqtt, expected: ExpectedReply) -> ExampleResult<()> {
    match expected {
        ExpectedReply::ConnackAccepted => {
            if mqtt.packet_type() != MqttControlPacketType::Connack {
                return Err(format!("expected CONNACK, got {:?}", mqtt.packet_type()).into());
            }
            if mqtt.return_code_value() != Some(MQTT_CONNACK_ACCEPTED) {
                return Err(format!(
                    "expected CONNACK return code {MQTT_CONNACK_ACCEPTED}, got {:?}",
                    mqtt.return_code_value()
                )
                .into());
            }
        }
        ExpectedReply::Suback { packet_id } => {
            if mqtt.packet_type() != MqttControlPacketType::Suback {
                return Err(format!("expected SUBACK, got {:?}", mqtt.packet_type()).into());
            }
            if mqtt.packet_id_value() != Some(packet_id) {
                return Err(format!(
                    "expected SUBACK packet id {packet_id}, got {:?}",
                    mqtt.packet_id_value()
                )
                .into());
            }
            if mqtt
                .suback_return_codes_value()
                .unwrap_or(&[])
                .contains(&MQTT_SUBACK_FAILURE)
            {
                return Err("broker rejected the subscription".into());
            }
        }
        ExpectedReply::Puback { packet_id } => {
            if mqtt.packet_type() != MqttControlPacketType::Puback {
                return Err(format!("expected PUBACK, got {:?}", mqtt.packet_type()).into());
            }
            if mqtt.packet_id_value() != Some(packet_id) {
                return Err(format!(
                    "expected PUBACK packet id {packet_id}, got {:?}",
                    mqtt.packet_id_value()
                )
                .into());
            }
        }
        ExpectedReply::Pingresp => {
            if mqtt.packet_type() != MqttControlPacketType::Pingresp {
                return Err(format!("expected PINGRESP, got {:?}", mqtt.packet_type()).into());
            }
        }
    }

    Ok(())
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

fn decode_mqtt_payload(bytes: &[u8]) -> ExampleResult<Packet> {
    let wrapped = (Ipv4::new()
        .src(REMOTE_IPV4)
        .dst(LOCAL_IPV4)
        .protocol(IPPROTO_TCP)
        / Tcp::new().sport(MQTT_PORT).dport(OFFLINE_SOURCE_PORT)
        / Raw::from_bytes(bytes))
    .compile()?;
    Ok(Packet::decode_from_l3(
        NetworkLayer::Ipv4,
        wrapped.as_bytes(),
    )?)
}

struct Transcript {
    entries: Vec<TranscriptEntry>,
}

impl Transcript {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn record(&mut self, direction: &'static str, label: &str, summary: &str, bytes: &[u8]) {
        self.entries.push(TranscriptEntry {
            direction,
            label: label.to_string(),
            summary: summary.to_string(),
            hex: compact_hex(bytes),
        });
    }

    fn write(&self, out_dir: &Path, config: &Config) -> std::io::Result<PathBuf> {
        fs::create_dir_all(out_dir)?;
        let path = out_dir.join("mqtt-session-transcript.txt");
        let mut body = String::new();
        body.push_str("mqtt_session transcript\n");
        body.push_str(&format!("created_unix: {}\n", unix_timestamp()));
        body.push_str(&format!("peer: {:?}\n", config.peer));
        body.push_str(&format!("client_id: {DEFAULT_CLIENT_ID}\n"));
        body.push_str(&format!("subscribe_topic: {DEFAULT_SUBSCRIBE_TOPIC}\n"));
        body.push_str(&format!("publish_topic: {DEFAULT_PUBLISH_TOPIC}\n"));
        body.push_str(&format!("publish_packet_id: {PUBLISH_PACKET_ID}\n"));
        body.push('\n');

        for (index, entry) in self.entries.iter().enumerate() {
            body.push_str(&format!(
                "{}. {} {}\nsummary: {}\nhex: {}\n\n",
                index + 1,
                entry.direction,
                entry.label,
                entry.summary,
                entry.hex
            ));
        }

        fs::write(&path, body)?;
        Ok(path)
    }
}

struct TranscriptEntry {
    direction: &'static str,
    label: String,
    summary: String,
    hex: String,
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn compact_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mqtt_session_message_plan_default_orders_core_messages() {
        let _config = Config::offline_default();
        let types = mqtt_message_plan()
            .iter()
            .map(|message| message.mqtt.packet_type())
            .collect::<Vec<_>>();

        assert_eq!(
            types,
            vec![
                MqttControlPacketType::Connect,
                MqttControlPacketType::Subscribe,
                MqttControlPacketType::Publish,
                MqttControlPacketType::Pingreq,
                MqttControlPacketType::Disconnect,
            ]
        );
    }
}
