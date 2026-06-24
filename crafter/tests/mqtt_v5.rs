use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::mqtt::{
    MqttProperties, MqttProperty, MQTT_5_PROTOCOL_LEVEL, MQTT_REASON_BAD_AUTHENTICATION_METHOD,
    MQTT_REASON_NO_MATCHING_SUBSCRIBERS, MQTT_REASON_PACKET_IDENTIFIER_NOT_FOUND,
    MQTT_SUBOPT_RETAIN_SEND_IF_NEW,
};

const CONNECT_V5_WITH_PROPERTIES: &[u8] = &[
    0x10, 0x30, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x05, 0x06, 0x00, 0x1e, 0x08, 0x11, 0x00, 0x00,
    0x00, 0x3c, 0x21, 0x00, 0x0a, 0x00, 0x03, b'c', b'i', b'd', 0x07, 0x01, 0x01, 0x02, 0x00, 0x00,
    0x00, 0x05, 0x00, 0x06, b's', b't', b'a', b't', b'u', b's', 0x00, 0x06, b'o', b'n', b'l', b'i',
    b'n', b'e',
];

const CONNECT_311_BASELINE: &[u8] = &[
    0x10, 0x0f, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x1e, 0x00, 0x03, b'c', b'i',
    b'd',
];

const CONNACK_V5_WITH_PROPERTIES: &[u8] = &[
    0x20, 0x11, 0x01, 0x8c, 0x0e, 0x12, 0x00, 0x03, b's', b'r', b'v', 0x21, 0x00, 0x14, 0x1f, 0x00,
    0x02, b'n', b'o',
];

const CONNACK_311_BASELINE: &[u8] = &[0x20, 0x02, 0x01, 0x03];

const PUBLISH_V5_WITH_PROPERTIES: &[u8] = &[
    0x32, 0x2c, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b't', 0x12, 0x34, 0x1c,
    0x23, 0x00, 0x07, 0x03, 0x00, 0x0a, b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i', b'n',
    0x26, 0x00, 0x04, b's', b'i', b't', b'e', 0x00, 0x03, b'l', b'a', b'b', b'4', b'2',
];

const PUBLISH_311_BASELINE: &[u8] = &[
    0x32, 0x0f, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b't', 0x12, 0x34, b'4',
    b'2',
];

const PUBACK_V5_FULL: &[u8] = &[
    0x40, 0x0d, 0x12, 0x34, 0x10, 0x09, 0x1f, 0x00, 0x06, b'q', b'u', b'e', b'u', b'e', b'd',
];

const PUBACK_V5_SHORT: &[u8] = &[0x40, 0x02, 0x12, 0x34];

const PUBREL_V5_FULL: &[u8] = &[0x62, 0x04, 0x22, 0x22, 0x92, 0x00];

const SUBSCRIBE_V5_WITH_PROPERTIES: &[u8] = &[
    0x82, 0x12, 0x12, 0x34, 0x03, 0x0b, 0xc1, 0x02, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r',
    b's', b'/', b'+', 0x15,
];

const SUBSCRIBE_311_BASELINE: &[u8] = &[
    0x82, 0x0e, 0x12, 0x34, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b'+', 0x01,
];

fn mqtt_bytes(message: Mqtt) -> crafter::Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

fn decode_mqtt_payload(payload: &[u8]) -> crafter::Result<(Vec<u8>, Packet)> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Tcp::new()
            .sport(49_152)
            .dport(MQTT_PORT)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / Raw::from_bytes(payload.to_vec());
    let bytes = packet.compile()?.into_bytes();
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes)?;

    Ok((bytes, decoded))
}

fn connect_v5_message() -> Mqtt {
    Mqtt::connect()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .client_id("cid")
        .keep_alive(30)
        .will("status", b"online".to_vec())
        .connect_properties(
            MqttProperties::new()
                .property(MqttProperty::SessionExpiryInterval(60))
                .property(MqttProperty::ReceiveMaximum(10)),
        )
        .will_properties(
            MqttProperties::new()
                .property(MqttProperty::PayloadFormatIndicator(1))
                .property(MqttProperty::MessageExpiryInterval(5)),
        )
}

fn connack_v5_message() -> Mqtt {
    Mqtt::connack()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .session_present(true)
        .reason_code(MQTT_REASON_BAD_AUTHENTICATION_METHOD)
        .connack_properties(
            MqttProperties::new()
                .property(MqttProperty::AssignedClientIdentifier("srv".to_string()))
                .property(MqttProperty::ReceiveMaximum(20))
                .property(MqttProperty::ReasonString("no".to_string())),
        )
}

fn publish_v5_message() -> Mqtt {
    Mqtt::publish()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .topic("sensors/t")
        .qos(1)
        .packet_id(0x1234)
        .topic_alias(7)
        .content_type("text/plain")
        .user_property("site", "lab")
        .payload(b"42".to_vec())
}

fn puback_v5_full_message() -> Mqtt {
    Mqtt::puback()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .packet_id(0x1234)
        .reason_code(MQTT_REASON_NO_MATCHING_SUBSCRIBERS)
        .ack_property(MqttProperty::ReasonString("queued".to_string()))
}

fn subscribe_v5_message() -> Mqtt {
    Mqtt::subscribe()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .packet_id(0x1234)
        .subscription_identifier(321)
        .subscribe_topic_options("sensors/+", 1, true, false, MQTT_SUBOPT_RETAIN_SEND_IF_NEW)
}

#[test]
fn connect_v5_properties_compile_and_decode_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(connect_v5_message())?;
    assert_eq!(bytes, CONNECT_V5_WITH_PROPERTIES);

    let (packet_bytes, decoded) = decode_mqtt_payload(CONNECT_V5_WITH_PROPERTIES)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNECT layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connect);
    assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
    assert_eq!(mqtt.protocol_level_value(), Some(MQTT_5_PROTOCOL_LEVEL));
    assert_eq!(mqtt.connect_flags_value(), Some(0x06));
    assert_eq!(mqtt.keep_alive_value(), Some(30));
    assert_eq!(mqtt.client_id_value(), Some("cid"));
    assert_eq!(mqtt.will_topic_value(), Some("status"));
    assert_eq!(mqtt.will_message_value(), Some(&b"online"[..]));
    assert_eq!(
        mqtt.connect_properties_value()
            .expect("connect properties")
            .property_values(),
        &[
            MqttProperty::SessionExpiryInterval(60),
            MqttProperty::ReceiveMaximum(10),
        ]
    );
    assert_eq!(
        mqtt.will_properties_value()
            .expect("will properties")
            .property_values(),
        &[
            MqttProperty::PayloadFormatIndicator(1),
            MqttProperty::MessageExpiryInterval(5),
        ]
    );

    assert_eq!(decoded.compile()?.as_bytes(), packet_bytes.as_slice());
    Ok(())
}

#[test]
fn connect_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(
        Mqtt::connect()
            .client_id("cid")
            .keep_alive(30)
            .clean_session(true),
    )?;

    assert_eq!(bytes, CONNECT_311_BASELINE);
    Ok(())
}

#[test]
fn connack_v5_reason_code_and_properties_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(connack_v5_message())?;

    assert_eq!(bytes, CONNACK_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn connack_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(Mqtt::connack().session_present(true).return_code(0x03))?;

    assert_eq!(bytes, CONNACK_311_BASELINE);
    Ok(())
}

#[test]
fn publish_v5_properties_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(publish_v5_message())?;

    assert_eq!(bytes, PUBLISH_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn publish_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(
        Mqtt::publish()
            .topic("sensors/t")
            .qos(1)
            .packet_id(0x1234)
            .payload(b"42".to_vec()),
    )?;

    assert_eq!(bytes, PUBLISH_311_BASELINE);
    Ok(())
}

#[test]
fn pubacks_v5_puback_full_form_compiles_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(puback_v5_full_message())?;

    assert_eq!(bytes, PUBACK_V5_FULL);
    Ok(())
}

#[test]
fn pubacks_v5_puback_short_form_compiles_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(
        Mqtt::puback()
            .version(MQTT_5_PROTOCOL_LEVEL)
            .packet_id(0x1234),
    )?;

    assert_eq!(bytes, PUBACK_V5_SHORT);
    Ok(())
}

#[test]
fn pubacks_v5_pubrel_preserves_required_flag_nibble() -> crafter::Result<()> {
    let bytes = mqtt_bytes(
        Mqtt::pubrel()
            .version(MQTT_5_PROTOCOL_LEVEL)
            .packet_id(0x2222)
            .reason_code(MQTT_REASON_PACKET_IDENTIFIER_NOT_FOUND),
    )?;

    assert_eq!(bytes, PUBREL_V5_FULL);
    Ok(())
}

#[test]
fn subscribe_v5_properties_and_options_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(subscribe_v5_message())?;

    assert_eq!(bytes, SUBSCRIBE_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn subscribe_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(
        Mqtt::subscribe()
            .packet_id(0x1234)
            .subscribe_topic("sensors/+", 1),
    )?;

    assert_eq!(bytes, SUBSCRIBE_311_BASELINE);
    Ok(())
}
