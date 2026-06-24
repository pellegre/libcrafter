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

const PUBLISH_V5_TOPIC_ALIAS_ONLY: &[u8] =
    &[0x30, 0x08, 0x00, 0x00, 0x03, 0x23, 0x00, 0x09, b'4', b'2'];

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

const COMMITTED_DOCS_CONNECT_V5_FRAME: &[u8] = &[
    // IPv4/TCP envelope from the documented `mqtt_session -- --v5` dry-run.
    // MQTT begins at offset 40: CONNECT fixed header 0x10, Remaining Length
    // 0x23, protocol level 5, Clean Start, keep-alive 30, Session Expiry 60,
    // Receive Maximum 10, and client id "crafter-client".
    0x45, 0x00, 0x00, 0x4d, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x8e, 0x58, 0xc0, 0x00, 0x02, 0x0a,
    0xc6, 0x33, 0x64, 0x14, 0xc0, 0x2a, 0x07, 0x5b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x50, 0x10, 0x20, 0x00, 0x21, 0xa3, 0x00, 0x00, 0x10, 0x23, 0x00, 0x04, b'M', b'Q', b'T', b'T',
    0x05, 0x02, 0x00, 0x1e, 0x08, 0x11, 0x00, 0x00, 0x00, 0x3c, 0x21, 0x00, 0x0a, 0x00, 0x0e, b'c',
    b'r', b'a', b'f', b't', b'e', b'r', b'-', b'c', b'l', b'i', b'e', b'n', b't',
];

const COMMITTED_DOCS_PUBLISH_V5_FRAME: &[u8] = &[
    // Same documentation envelope. MQTT begins at offset 40: PUBLISH fixed
    // header 0x32 (QoS 1), Remaining Length 0x44, topic
    // "crafter/demo/outbound", packet id 2, a User Property
    // "example"="mqtt_session", and payload "hello from crafter".
    0x45, 0x00, 0x00, 0x6e, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x8e, 0x37, 0xc0, 0x00, 0x02, 0x0a,
    0xc6, 0x33, 0x64, 0x14, 0xc0, 0x2a, 0x07, 0x5b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x50, 0x10, 0x20, 0x00, 0xb7, 0x62, 0x00, 0x00, 0x32, 0x44, 0x00, 0x15, b'c', b'r', b'a', b'f',
    b't', b'e', b'r', b'/', b'd', b'e', b'm', b'o', b'/', b'o', b'u', b't', b'b', b'o', b'u', b'n',
    b'd', 0x00, 0x02, 0x18, 0x26, 0x00, 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x00, 0x0c,
    b'm', b'q', b't', b't', b'_', b's', b'e', b's', b's', b'i', b'o', b'n', b'h', b'e', b'l', b'l',
    b'o', b' ', b'f', b'r', b'o', b'm', b' ', b'c', b'r', b'a', b'f', b't', b'e', b'r',
];

const COMMITTED_DOCS_CONNECT_V5_SUMMARY: &str = "Ipv4(src=192.0.2.10, dst=198.51.100.20, proto=tcp(6)) / Tcp(sport=49194, dport=1883, flags=ACK) / MQTT CONNECT client_id=crafter-client keep_alive=30 clean_session=true will=false username=false password=false";

const COMMITTED_DOCS_PUBLISH_V5_SUMMARY: &str = "Ipv4(src=192.0.2.10, dst=198.51.100.20, proto=tcp(6)) / Tcp(sport=49194, dport=1883, flags=ACK) / MQTT PUBLISH topic=crafter/demo/outbound qos=1 dup=false retain=false payload=18 bytes";

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
        / Raw::from_bytes(payload);
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

fn documented_mqtt_v5_packet(message: Mqtt) -> Packet {
    Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        .protocol(IPPROTO_TCP)
        / Tcp::new()
            .sport(49_194)
            .dport(MQTT_PORT)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / message
}

#[test]
fn committed_docs_v5_connect_and_publish_frames_match_expected_bytes() -> crafter::Result<()> {
    let connect = documented_mqtt_v5_packet(
        Mqtt::connect()
            .version(MQTT_5_PROTOCOL_LEVEL)
            .client_id("crafter-client")
            .keep_alive(30)
            .clean_session(true)
            .connect_property(MqttProperty::SessionExpiryInterval(60))
            .connect_property(MqttProperty::ReceiveMaximum(10)),
    );
    let connect_bytes = connect.compile()?;
    let connect_decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, connect_bytes.as_bytes())?;

    assert_eq!(connect.summary(), COMMITTED_DOCS_CONNECT_V5_SUMMARY);
    assert_eq!(connect_decoded.summary(), COMMITTED_DOCS_CONNECT_V5_SUMMARY);
    assert_eq!(connect_bytes.as_bytes(), COMMITTED_DOCS_CONNECT_V5_FRAME);

    let publish = documented_mqtt_v5_packet(
        Mqtt::publish()
            .version(MQTT_5_PROTOCOL_LEVEL)
            .topic("crafter/demo/outbound")
            .qos(1)
            .packet_id(2)
            .user_property("example", "mqtt_session")
            .payload(b"hello from crafter".to_vec()),
    );
    let publish_bytes = publish.compile()?;
    let publish_payload_decoded = Mqtt::decode_payload_with_default_version(
        &publish_bytes.as_bytes()[40..],
        MQTT_5_PROTOCOL_LEVEL,
    )?;

    assert_eq!(publish.summary(), COMMITTED_DOCS_PUBLISH_V5_SUMMARY);
    assert_eq!(
        publish_payload_decoded.summary(),
        "MQTT PUBLISH topic=crafter/demo/outbound qos=1 dup=false retain=false payload=18 bytes"
    );
    assert_eq!(publish_bytes.as_bytes(), COMMITTED_DOCS_PUBLISH_V5_FRAME);
    Ok(())
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
fn topic_alias_v5_publish_with_topic_round_trips() -> crafter::Result<()> {
    let bytes = mqtt_bytes(publish_v5_message())?;
    assert_eq!(bytes, PUBLISH_V5_WITH_PROPERTIES);

    let decoded = Mqtt::decode_payload_with_default_version(
        PUBLISH_V5_WITH_PROPERTIES,
        MQTT_5_PROTOCOL_LEVEL,
    )?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBLISH layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
    assert_eq!(mqtt.topic_value(), Some("sensors/t"));
    assert_eq!(
        mqtt.publish_properties_value()
            .expect("publish properties")
            .property_values(),
        &[
            MqttProperty::TopicAlias(7),
            MqttProperty::ContentType("text/plain".to_string()),
            MqttProperty::user_property("site", "lab"),
        ]
    );
    assert_eq!(decoded.compile()?.as_bytes(), PUBLISH_V5_WITH_PROPERTIES);
    Ok(())
}

#[test]
fn topic_alias_v5_publish_allows_empty_topic_alias_only() -> crafter::Result<()> {
    let bytes = mqtt_bytes(
        Mqtt::publish()
            .version(MQTT_5_PROTOCOL_LEVEL)
            .topic("")
            .topic_alias(9)
            .payload(b"42".to_vec()),
    )?;
    assert_eq!(bytes, PUBLISH_V5_TOPIC_ALIAS_ONLY);

    let decoded = Mqtt::decode_payload_with_default_version(&bytes, MQTT_5_PROTOCOL_LEVEL)?;
    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBLISH layer");

    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
    assert_eq!(mqtt.topic_value(), Some(""));
    assert_eq!(mqtt.payload_value(), Some(&b"42"[..]));
    assert_eq!(
        mqtt.publish_properties_value()
            .expect("publish properties")
            .property_values(),
        &[MqttProperty::TopicAlias(9)]
    );
    assert_eq!(decoded.compile()?.as_bytes(), PUBLISH_V5_TOPIC_ALIAS_ONLY);
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
