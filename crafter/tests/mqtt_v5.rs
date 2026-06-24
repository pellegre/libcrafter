use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::mqtt::{
    MqttProperties, MqttProperty, MQTT_311_PROTOCOL_LEVEL, MQTT_5_PROTOCOL_LEVEL,
    MQTT_PUBLISH_QOS_2, MQTT_REASON_BAD_AUTHENTICATION_METHOD, MQTT_REASON_CONTINUE_AUTHENTICATION,
    MQTT_REASON_GRANTED_QOS_0, MQTT_REASON_GRANTED_QOS_1,
    MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR, MQTT_REASON_NO_MATCHING_SUBSCRIBERS,
    MQTT_REASON_NO_SUBSCRIPTION_EXISTED, MQTT_REASON_PACKET_IDENTIFIER_NOT_FOUND,
    MQTT_REASON_SESSION_TAKEN_OVER, MQTT_REASON_SUCCESS, MQTT_REASON_TOPIC_FILTER_INVALID,
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

const SUBACK_V5_WITH_PROPERTIES: &[u8] = &[
    0x90, 0x10, 0x43, 0x21, 0x0a, 0x1f, 0x00, 0x07, b'p', b'a', b'r', b't', b'i', b'a', b'l', 0x00,
    0x01, 0x83,
];

const SUBACK_311_BASELINE: &[u8] = &[0x90, 0x04, 0x12, 0x34, 0x01, 0x80];

const UNSUBSCRIBE_V5_WITH_PROPERTIES: &[u8] = &[
    0xa2, 0x1a, 0x12, 0x34, 0x0c, 0x26, 0x00, 0x06, b'c', b'l', b'i', b'e', b'n', b't', 0x00, 0x01,
    b'a', 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b'+',
];

const UNSUBSCRIBE_311_BASELINE: &[u8] = &[
    0xa2, 0x0d, 0x12, 0x34, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b'+',
];

const UNSUBACK_V5_WITH_PROPERTIES: &[u8] = &[
    0xb0, 0x0d, 0x43, 0x21, 0x07, 0x1f, 0x00, 0x04, b'g', b'o', b'n', b'e', 0x00, 0x11, 0x8f,
];

const UNSUBACK_311_BASELINE: &[u8] = &[0xb0, 0x02, 0x12, 0x34];

const DISCONNECT_V5_WITH_PROPERTIES: &[u8] =
    &[0xe0, 0x07, 0x8e, 0x05, 0x11, 0x00, 0x00, 0x00, 0x3c];

const DISCONNECT_SHORT: &[u8] = &[0xe0, 0x00];

const AUTH_V5_WITH_PROPERTIES: &[u8] = &[
    0xf0, 0x10, 0x18, 0x0e, 0x15, 0x00, 0x05, b's', b'c', b'r', b'a', b'm', 0x16, 0x00, 0x03, 0x01,
    0x02, 0x03,
];

const AUTH_SHORT: &[u8] = &[0xf0, 0x00];

fn mqtt_bytes(message: Mqtt) -> crafter::Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

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
        / Raw::from_bytes(payload.to_vec());
    Ok(packet.compile()?.into_bytes())
}

fn decode_mqtt_payload(payload: &[u8]) -> crafter::Result<(Vec<u8>, Packet)> {
    let bytes = mqtt_over_ipv4_tcp(payload)?;
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

fn suback_v5_message() -> Mqtt {
    Mqtt::suback()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .packet_id(0x4321)
        .suback_property(MqttProperty::ReasonString("partial".to_string()))
        .return_codes([
            MQTT_REASON_GRANTED_QOS_0,
            MQTT_REASON_GRANTED_QOS_1,
            MQTT_REASON_IMPLEMENTATION_SPECIFIC_ERROR,
        ])
}

fn unsubscribe_v5_message() -> Mqtt {
    Mqtt::unsubscribe()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .packet_id(0x1234)
        .unsubscribe_property(MqttProperty::user_property("client", "a"))
        .topic("sensors/+")
}

fn unsuback_v5_message() -> Mqtt {
    Mqtt::unsuback()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .packet_id(0x4321)
        .unsuback_property(MqttProperty::ReasonString("gone".to_string()))
        .unsuback_reason_codes([
            MQTT_REASON_SUCCESS,
            MQTT_REASON_NO_SUBSCRIPTION_EXISTED,
            MQTT_REASON_TOPIC_FILTER_INVALID,
        ])
}

fn disconnect_v5_message() -> Mqtt {
    Mqtt::disconnect()
        .version(MQTT_5_PROTOCOL_LEVEL)
        .reason_code(MQTT_REASON_SESSION_TAKEN_OVER)
        .disconnect_property(MqttProperty::SessionExpiryInterval(60))
}

fn auth_v5_message() -> Mqtt {
    Mqtt::auth()
        .reason_code(MQTT_REASON_CONTINUE_AUTHENTICATION)
        .authentication_method("scram")
        .authentication_data(vec![1, 2, 3])
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
fn version_connect_v5_decodes_from_protocol_level() -> crafter::Result<()> {
    let (_packet_bytes, decoded) = decode_mqtt_payload(CONNECT_V5_WITH_PROPERTIES)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNECT layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connect);
    assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
    assert_eq!(mqtt.protocol_level_value(), Some(MQTT_5_PROTOCOL_LEVEL));
    Ok(())
}

#[test]
fn version_connack_v5_decodes_with_explicit_default() -> crafter::Result<()> {
    let decoded = Mqtt::decode_payload_with_default_version(
        CONNACK_V5_WITH_PROPERTIES,
        MQTT_5_PROTOCOL_LEVEL,
    )?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNACK layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connack);
    assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
    assert_eq!(
        mqtt.reason_code_value(),
        Some(MQTT_REASON_BAD_AUTHENTICATION_METHOD)
    );
    assert_eq!(
        mqtt.connack_properties_value()
            .expect("connack properties")
            .property_values(),
        &[
            MqttProperty::AssignedClientIdentifier("srv".to_string()),
            MqttProperty::ReceiveMaximum(20),
            MqttProperty::ReasonString("no".to_string()),
        ]
    );
    assert_eq!(decoded.compile()?.as_bytes(), CONNACK_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn version_default_registry_path_decodes_baseline_connack() -> crafter::Result<()> {
    let (packet_bytes, decoded) = decode_mqtt_payload(CONNACK_311_BASELINE)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT CONNACK layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connack);
    assert_eq!(mqtt.version_value(), MQTT_311_PROTOCOL_LEVEL);
    assert_eq!(mqtt.return_code_value(), Some(0x03));
    assert_eq!(decoded.compile()?.as_bytes(), packet_bytes.as_slice());
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
fn qos2_v5_flow_decodes_packet_ids_and_reason_codes() -> crafter::Result<()> {
    let packet_id = 0x4567;
    let flow = [
        (
            Mqtt::publish()
                .version(MQTT_5_PROTOCOL_LEVEL)
                .topic("qos/two")
                .qos(MQTT_PUBLISH_QOS_2)
                .packet_id(packet_id)
                .payload(b"exactly".to_vec()),
            MqttControlPacketType::Publish,
            None,
        ),
        (
            Mqtt::pubrec()
                .version(MQTT_5_PROTOCOL_LEVEL)
                .packet_id(packet_id)
                .reason_code(MQTT_REASON_NO_MATCHING_SUBSCRIBERS),
            MqttControlPacketType::Pubrec,
            Some(MQTT_REASON_NO_MATCHING_SUBSCRIBERS),
        ),
        (
            Mqtt::pubrel()
                .version(MQTT_5_PROTOCOL_LEVEL)
                .packet_id(packet_id)
                .reason_code(MQTT_REASON_PACKET_IDENTIFIER_NOT_FOUND),
            MqttControlPacketType::Pubrel,
            Some(MQTT_REASON_PACKET_IDENTIFIER_NOT_FOUND),
        ),
        (
            Mqtt::pubcomp()
                .version(MQTT_5_PROTOCOL_LEVEL)
                .packet_id(packet_id)
                .reason_code(MQTT_REASON_SUCCESS),
            MqttControlPacketType::Pubcomp,
            Some(MQTT_REASON_SUCCESS),
        ),
    ];

    let mut decoded_types = Vec::new();
    let mut decoded_packet_ids = Vec::new();

    for (message, expected_type, expected_reason_code) in flow {
        let payload = mqtt_bytes(message)?;
        let packet_bytes = mqtt_over_ipv4_tcp(&payload)?;
        let decoded = Mqtt::decode_payload_with_default_version(&payload, MQTT_5_PROTOCOL_LEVEL)?;
        let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT QoS2 layer");

        decoded_types.push(mqtt.packet_type());
        decoded_packet_ids.push(mqtt.packet_id_value());

        assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
        assert_eq!(mqtt.packet_type(), expected_type);
        assert_eq!(mqtt.packet_id_value(), Some(packet_id));
        assert_eq!(mqtt.reason_code_value(), expected_reason_code);
        assert!(!packet_bytes.is_empty());
        assert_eq!(decoded.compile()?.as_bytes(), payload.as_slice());
    }

    assert_eq!(
        decoded_types,
        [
            MqttControlPacketType::Publish,
            MqttControlPacketType::Pubrec,
            MqttControlPacketType::Pubrel,
            MqttControlPacketType::Pubcomp,
        ]
    );
    assert_eq!(decoded_packet_ids.as_slice(), &[Some(packet_id); 4]);
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

#[test]
fn suback_v5_properties_and_reason_codes_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(suback_v5_message())?;

    assert_eq!(bytes, SUBACK_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn suback_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(Mqtt::suback().packet_id(0x1234).return_codes([0x01, 0x80]))?;

    assert_eq!(bytes, SUBACK_311_BASELINE);
    Ok(())
}

#[test]
fn unsubscribe_v5_properties_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(unsubscribe_v5_message())?;

    assert_eq!(bytes, UNSUBSCRIBE_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn unsubscribe_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(Mqtt::unsubscribe().packet_id(0x1234).topic("sensors/+"))?;

    assert_eq!(bytes, UNSUBSCRIBE_311_BASELINE);
    Ok(())
}

#[test]
fn unsuback_v5_properties_and_reason_codes_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(unsuback_v5_message())?;

    assert_eq!(bytes, UNSUBACK_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn unsuback_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(Mqtt::unsuback().packet_id(0x1234))?;

    assert_eq!(bytes, UNSUBACK_311_BASELINE);
    Ok(())
}

#[test]
fn disconnect_v5_reason_code_and_properties_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(disconnect_v5_message())?;

    assert_eq!(bytes, DISCONNECT_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn disconnect_v5_short_form_compiles_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(Mqtt::disconnect().version(MQTT_5_PROTOCOL_LEVEL))?;

    assert_eq!(bytes, DISCONNECT_SHORT);
    Ok(())
}

#[test]
fn disconnect_311_baseline_stays_unchanged() -> crafter::Result<()> {
    let bytes = mqtt_bytes(Mqtt::disconnect())?;

    assert_eq!(bytes, DISCONNECT_SHORT);
    Ok(())
}

#[test]
fn auth_v5_reason_code_and_properties_compile_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(auth_v5_message())?;

    assert_eq!(bytes, AUTH_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn auth_v5_short_form_compiles_byte_exact() -> crafter::Result<()> {
    let bytes = mqtt_bytes(Mqtt::auth())?;

    assert_eq!(bytes, AUTH_SHORT);
    Ok(())
}
