use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::mqtt::{
    MQTT_CONNACK_ACCEPTED, MQTT_CONNACK_IDENTIFIER_REJECTED, MQTT_CONNACK_SERVER_UNAVAILABLE,
    MQTT_PUBLISH_QOS_0, MQTT_PUBLISH_QOS_1,
};

const CONNECT_CLIENT_ONLY: &[u8] = &[
    // `.agents/docs/mqtt-manifest.md`: MQTT fixed header byte 1 is control
    // packet type in bits 7-4 plus flags in bits 3-0; CONNECT is type 1 and
    // fixed-header flags 0x0. Remaining Length is the body bytes after this
    // field: the 10-byte CONNECT variable header plus the payload fields.
    0x10, 0x12,
    // Manifest CONNECT variable header: Protocol Name is the UTF-8 string
    // "MQTT" with a two-byte length prefix; Protocol Level for MQTT 3.1.1 is 4.
    0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04,
    // Manifest CONNECT flags: Clean Session is bit 1. Keep Alive is a two-byte
    // integer in seconds.
    0x02, 0x00, 0x3c,
    // Manifest CONNECT payload: Client Identifier is required first and is an
    // MQTT UTF-8 string.
    0x00, 0x06, b'c', b'l', b'i', b'e', b'n', b't',
];

const CONNACK_ACCEPTED: &[u8] = &[
    // `.agents/docs/mqtt-manifest.md`: CONNACK is fixed-header type 2 with
    // flags 0x0 and Remaining Length 2. The two-byte variable header is
    // acknowledge flags followed by the return code.
    0x20,
    0x02,
    // Manifest CONNACK acknowledge flags: bit 0 is Session Present, all other
    // bits reserved. Return code 0x00 is Connection Accepted.
    0x00,
    MQTT_CONNACK_ACCEPTED,
];

const CONNACK_SERVER_UNAVAILABLE: &[u8] = &[
    // Same CONNACK fixed header and acknowledge-flags shape; return code 0x03
    // is Server unavailable in OASIS MQTT 3.1.1 sec. 3.2.2.3 Table 3.1.
    0x20,
    0x02,
    0x00,
    MQTT_CONNACK_SERVER_UNAVAILABLE,
];

const PUBLISH_QOS0: &[u8] = &[
    // `.agents/docs/mqtt-manifest.md`: PUBLISH fixed-header type 3 carries
    // DUP/QoS/RETAIN in the low nibble. QoS 0 has flags 0x0 and therefore no
    // packet identifier. Remaining Length covers topic plus payload.
    0x30, 0x07, // Manifest PUBLISH variable header: Topic Name is an MQTT UTF-8 string.
    0x00, 0x03, b'a', b'/', b'b',
    // The rest of the Remaining Length is application payload.
    b'h', b'i',
];

const PUBLISH_QOS1: &[u8] = &[
    // PUBLISH QoS 1 sets fixed-header QoS bits to 0b01, making the first byte
    // 0x32 and requiring a two-byte Packet Identifier after the topic.
    0x32, 0x0b, 0x00, 0x05, b't', b'o', b'p', b'i', b'c', 0x12, 0x34, 0xde, 0xad,
];

const PUBACK_PACKET_ID: &[u8] = &[
    // `.agents/docs/mqtt-manifest.md`: PUBACK fixed-header type 4 uses flags
    // 0x0 and Remaining Length 2. Its variable header is one Packet Identifier.
    0x40, 0x02, 0x12, 0x34,
];

const PUBREC_PACKET_ID: &[u8] = &[
    // `.agents/docs/mqtt-manifest.md`: PUBREC fixed-header type 5 uses flags
    // 0x0 and Remaining Length 2. Its variable header is one Packet Identifier.
    0x50, 0x02, 0x12, 0x34,
];

const PUBREL_PACKET_ID: &[u8] = &[
    // `.agents/docs/mqtt-manifest.md`: PUBREL fixed-header type 6 uses the
    // specification-fixed low-nibble flags value 0b0010, so the first byte is
    // 0x62. Remaining Length is 2 for the Packet Identifier.
    0x62, 0x02, 0x12, 0x34,
];

const PUBCOMP_PACKET_ID: &[u8] = &[
    // `.agents/docs/mqtt-manifest.md`: PUBCOMP fixed-header type 7 uses flags
    // 0x0 and Remaining Length 2. Its variable header is one Packet Identifier.
    0x70, 0x02, 0x12, 0x34,
];

fn mqtt_over_ipv4_tcp(payload: &[u8]) -> crafter::Result<Vec<u8>> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Tcp::new()
            .sport(49_152)
            .dport(MQTT_PORT)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / Raw::from_bytes(payload);

    Ok(packet.compile()?.into_bytes())
}

fn decode_ipv4_tcp_mqtt(payload: &[u8]) -> crafter::Result<(Vec<u8>, Packet)> {
    let bytes = mqtt_over_ipv4_tcp(payload)?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)?;
    Ok((bytes, decoded))
}

#[test]
fn connect_golden_decodes_typed_fields_and_recompiles_byte_exact() -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(CONNECT_CLIENT_ONLY)?;

    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, ["Ipv4", "Tcp", "MQTT"]);

    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNECT layer");
    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connect);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.remaining_length_value(), 0x12);
    assert_eq!(mqtt.protocol_name_value(), Some("MQTT"));
    assert_eq!(mqtt.protocol_level_value(), Some(4));
    assert_eq!(mqtt.connect_flags_value(), Some(0x02));
    assert_eq!(mqtt.keep_alive_value(), Some(60));
    assert_eq!(mqtt.client_id_value(), Some("client"));
    assert_eq!(mqtt.will_topic_value(), None);
    assert_eq!(mqtt.will_message_value(), None);
    assert_eq!(mqtt.username_value(), None);
    assert_eq!(mqtt.password_value(), None);

    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn connect_decode_preserves_fixed_header_and_connect_flags() -> crafter::Result<()> {
    let mut payload = CONNECT_CLIENT_ONLY.to_vec();
    payload[0] = 0x11;
    payload[9] = 0x03;

    let (bytes, decoded) = decode_ipv4_tcp_mqtt(&payload)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNECT layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connect);
    assert_eq!(mqtt.flags_value(), 0x1);
    assert_eq!(mqtt.connect_flags_value(), Some(0x03));
    assert_eq!(mqtt.client_id_value(), Some("client"));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn connect_build_decode_round_trip_with_will_username_and_password() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 30))
        .dst(Ipv4Addr::new(198, 51, 100, 40))
        / Tcp::new()
            .sport(49_153)
            .dport(MQTT_PORT)
            .seq(0x1112_1314)
            .ack(0x2122_2324)
            .ack_segment()
        / Mqtt::connect()
            .client_id("cid")
            .keep_alive(30)
            .will("status", vec![0xde, 0xad])
            .will_qos(1)
            .will_retain(true)
            .username("user")
            .password(vec![0xbe, 0xef]);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNECT layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connect);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.protocol_name_value(), Some("MQTT"));
    assert_eq!(mqtt.protocol_level_value(), Some(4));
    assert_eq!(mqtt.connect_flags_value(), Some(0xee));
    assert_eq!(mqtt.keep_alive_value(), Some(30));
    assert_eq!(mqtt.client_id_value(), Some("cid"));
    assert_eq!(mqtt.will_topic_value(), Some("status"));
    assert_eq!(mqtt.will_message_value(), Some(&[0xde, 0xad][..]));
    assert_eq!(mqtt.username_value(), Some("user"));
    assert_eq!(mqtt.password_value(), Some(&[0xbe, 0xef][..]));

    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

fn assert_connack_golden(payload: &[u8], expected_return_code: u8) -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(payload)?;
    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, ["Ipv4", "Tcp", "MQTT"]);

    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNACK layer");
    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connack);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.remaining_length_value(), 2);
    assert_eq!(mqtt.session_present_value(), Some(false));
    assert_eq!(mqtt.return_code_value(), Some(expected_return_code));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn connack_golden_decodes_accepted_and_nonzero_return_codes() -> crafter::Result<()> {
    assert_connack_golden(CONNACK_ACCEPTED, MQTT_CONNACK_ACCEPTED)?;
    assert_connack_golden(CONNACK_SERVER_UNAVAILABLE, MQTT_CONNACK_SERVER_UNAVAILABLE)?;
    Ok(())
}

#[test]
fn connack_build_decode_round_trip_with_session_present() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(198, 51, 100, 40))
        .dst(Ipv4Addr::new(192, 0, 2, 30))
        / Tcp::new()
            .sport(MQTT_PORT)
            .dport(49_153)
            .seq(0x3132_3334)
            .ack(0x4142_4344)
            .ack_segment()
        / Mqtt::connack()
            .session_present(true)
            .return_code(MQTT_CONNACK_IDENTIFIER_REJECTED);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNACK layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connack);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.remaining_length_value(), 2);
    assert_eq!(mqtt.session_present_value(), Some(true));
    assert_eq!(
        mqtt.return_code_value(),
        Some(MQTT_CONNACK_IDENTIFIER_REJECTED)
    );
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn publish_qos0_golden_decodes_payload_without_packet_id() -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(PUBLISH_QOS0)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBLISH layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.remaining_length_value(), 7);
    assert_eq!(mqtt.topic_value(), Some("a/b"));
    assert_eq!(mqtt.qos_value(), Some(MQTT_PUBLISH_QOS_0));
    assert_eq!(mqtt.dup_value(), Some(false));
    assert_eq!(mqtt.retain_value(), Some(false));
    assert_eq!(mqtt.packet_id_value(), None);
    assert_eq!(mqtt.payload_value(), Some(&b"hi"[..]));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn publish_qos1_golden_decodes_packet_id_and_payload() -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(PUBLISH_QOS1)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBLISH layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt.flags_value(), 0x2);
    assert_eq!(mqtt.remaining_length_value(), 11);
    assert_eq!(mqtt.topic_value(), Some("topic"));
    assert_eq!(mqtt.qos_value(), Some(MQTT_PUBLISH_QOS_1));
    assert_eq!(mqtt.dup_value(), Some(false));
    assert_eq!(mqtt.retain_value(), Some(false));
    assert_eq!(mqtt.packet_id_value(), Some(0x1234));
    assert_eq!(mqtt.payload_value(), Some(&[0xde, 0xad][..]));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn publish_build_decode_round_trip_with_retain_qos1() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 50))
        .dst(Ipv4Addr::new(198, 51, 100, 60))
        / Tcp::new()
            .sport(49_154)
            .dport(MQTT_PORT)
            .seq(0x5152_5354)
            .ack(0x6162_6364)
            .ack_segment()
        / Mqtt::publish()
            .topic("alerts")
            .qos(1)
            .retain(true)
            .packet_id(9)
            .payload(vec![0xca, 0xfe]);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBLISH layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt.qos_value(), Some(MQTT_PUBLISH_QOS_1));
    assert_eq!(mqtt.dup_value(), Some(false));
    assert_eq!(mqtt.retain_value(), Some(true));
    assert_eq!(mqtt.topic_value(), Some("alerts"));
    assert_eq!(mqtt.packet_id_value(), Some(9));
    assert_eq!(mqtt.payload_value(), Some(&[0xca, 0xfe][..]));
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn puback_golden_decodes_packet_id_and_recompiles() -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(PUBACK_PACKET_ID)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBACK layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Puback);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.remaining_length_value(), 2);
    assert_eq!(mqtt.packet_id_value(), Some(0x1234));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn puback_build_decode_round_trip() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(198, 51, 100, 60))
        .dst(Ipv4Addr::new(192, 0, 2, 50))
        / Tcp::new()
            .sport(MQTT_PORT)
            .dport(49_154)
            .seq(0x7172_7374)
            .ack(0x8182_8384)
            .ack_segment()
        / Mqtt::puback().packet_id(9);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBACK layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Puback);
    assert_eq!(mqtt.packet_id_value(), Some(9));
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn pubrec_golden_decodes_packet_id_and_recompiles() -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(PUBREC_PACKET_ID)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBREC layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pubrec);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.remaining_length_value(), 2);
    assert_eq!(mqtt.packet_id_value(), Some(0x1234));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn pubrec_build_decode_round_trip() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(198, 51, 100, 61))
        .dst(Ipv4Addr::new(192, 0, 2, 51))
        / Tcp::new()
            .sport(MQTT_PORT)
            .dport(49_155)
            .seq(0x9192_9394)
            .ack(0xa1a2_a3a4)
            .ack_segment()
        / Mqtt::pubrec().packet_id(9);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBREC layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pubrec);
    assert_eq!(mqtt.packet_id_value(), Some(9));
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn pubrel_golden_decodes_packet_id_and_fixed_flags() -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(PUBREL_PACKET_ID)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBREL layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pubrel);
    assert_eq!(mqtt.flags_value(), 0x2);
    assert_eq!(mqtt.remaining_length_value(), 2);
    assert_eq!(mqtt.packet_id_value(), Some(0x1234));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn pubrel_build_decode_round_trip() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(198, 51, 100, 62))
        .dst(Ipv4Addr::new(192, 0, 2, 52))
        / Tcp::new()
            .sport(MQTT_PORT)
            .dport(49_156)
            .seq(0xb1b2_b3b4)
            .ack(0xc1c2_c3c4)
            .ack_segment()
        / Mqtt::pubrel().packet_id(9);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBREL layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pubrel);
    assert_eq!(mqtt.flags_value(), 0x2);
    assert_eq!(mqtt.packet_id_value(), Some(9));
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn pubrel_decode_preserves_nonstandard_flags() -> crafter::Result<()> {
    let mut payload = PUBREL_PACKET_ID.to_vec();
    payload[0] = 0x60;

    let (bytes, decoded) = decode_ipv4_tcp_mqtt(&payload)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBREL layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pubrel);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.packet_id_value(), Some(0x1234));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn pubcomp_golden_decodes_packet_id_and_recompiles() -> crafter::Result<()> {
    let (bytes, decoded) = decode_ipv4_tcp_mqtt(PUBCOMP_PACKET_ID)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBCOMP layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pubcomp);
    assert_eq!(mqtt.flags_value(), 0x0);
    assert_eq!(mqtt.remaining_length_value(), 2);
    assert_eq!(mqtt.packet_id_value(), Some(0x1234));
    assert_eq!(decoded.compile()?.as_bytes(), bytes.as_slice());
    Ok(())
}

#[test]
fn pubcomp_build_decode_round_trip() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(198, 51, 100, 63))
        .dst(Ipv4Addr::new(192, 0, 2, 53))
        / Tcp::new()
            .sport(MQTT_PORT)
            .dport(49_157)
            .seq(0xd1d2_d3d4)
            .ack(0xe1e2_e3e4)
            .ack_segment()
        / Mqtt::pubcomp().packet_id(9);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBCOMP layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pubcomp);
    assert_eq!(mqtt.packet_id_value(), Some(9));
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}
