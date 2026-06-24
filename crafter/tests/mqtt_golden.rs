use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::mqtt::{
    MQTT_CONNACK_ACCEPTED, MQTT_CONNACK_IDENTIFIER_REJECTED, MQTT_CONNACK_SERVER_UNAVAILABLE,
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
