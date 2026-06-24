use std::net::Ipv4Addr;

use crafter::prelude::*;
use crafter::protocols::mqtt::MQTT_PUBLISH_QOS_1;

fn mqtt_tcp_packet(source_port: u16, destination_port: u16) -> Packet {
    Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Tcp::new()
            .sport(source_port)
            .dport(destination_port)
            .seq(0x0102_0304)
            .ack(0x0506_0708)
            .ack_segment()
        / Mqtt::raw(MqttControlPacketType::Publish, b"\0\x05topichello")
}

fn assert_default_registry_decodes_mqtt(
    source_port: u16,
    destination_port: u16,
) -> crafter::Result<()> {
    let packet = mqtt_tcp_packet(source_port, destination_port);
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, vec!["Ipv4", "Tcp", "MQTT"]);
    assert_eq!(layer_names.last(), Some(&"MQTT"));

    assert!(decoded.layer::<Ipv4>().is_some());
    let tcp = decoded.layer::<Tcp>().expect("decoded tcp layer");
    assert_eq!(tcp.source_port_value(), source_port);
    assert_eq!(tcp.destination_port_value(), destination_port);

    let mqtt_layers = decoded.layers::<Mqtt>().collect::<Vec<_>>();
    assert_eq!(mqtt_layers.len(), 1);
    assert_eq!(mqtt_layers[0].packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt_layers[0].topic_value(), Some("topic"));
    assert_eq!(mqtt_layers[0].qos_value(), Some(0));
    assert_eq!(mqtt_layers[0].packet_id_value(), None);
    assert_eq!(mqtt_layers[0].payload_value(), Some(&b"hello"[..]));

    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn default_registry_decodes_mqtt_destination_port_1883() -> crafter::Result<()> {
    assert_default_registry_decodes_mqtt(49_152, MQTT_PORT)
}

#[test]
fn default_registry_decodes_mqtt_source_port_1883() -> crafter::Result<()> {
    assert_default_registry_decodes_mqtt(MQTT_PORT, 49_152)
}

#[test]
fn prelude_exports_mqtt_packet_builder_surface() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 30))
        .dst(Ipv4Addr::new(198, 51, 100, 40))
        / Tcp::new().sport(49_152).dport(MQTT_PORT)
        / Mqtt::raw(MqttControlPacketType::Pingreq, []);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    let mqtt = decoded.layer::<Mqtt>().expect("decoded mqtt layer");
    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Pingreq);
    Ok(())
}

#[test]
fn stacked_mqtt_packets_decode_to_ordered_typed_layers() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 50))
        .dst(Ipv4Addr::new(198, 51, 100, 60))
        / Tcp::new()
            .sport(49_153)
            .dport(MQTT_PORT)
            .seq(0x1112_1314)
            .ack(0x2122_2324)
            .ack_segment()
        / Mqtt::connect().client_id("cid").keep_alive(30)
        / Mqtt::publish().topic("topic").payload(b"hello".to_vec())
        / Mqtt::subscribe()
            .packet_id(0x1234)
            .subscribe_topic("topic", MQTT_PUBLISH_QOS_1);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, ["Ipv4", "Tcp", "MQTT", "MQTT", "MQTT"]);

    let mqtt_layers = decoded.layers::<Mqtt>().collect::<Vec<_>>();
    assert_eq!(mqtt_layers.len(), 3);

    assert_eq!(mqtt_layers[0].packet_type(), MqttControlPacketType::Connect);
    assert_eq!(mqtt_layers[0].client_id_value(), Some("cid"));
    assert_eq!(mqtt_layers[0].keep_alive_value(), Some(30));

    assert_eq!(mqtt_layers[1].packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt_layers[1].topic_value(), Some("topic"));
    assert_eq!(mqtt_layers[1].payload_value(), Some(&b"hello"[..]));

    assert_eq!(
        mqtt_layers[2].packet_type(),
        MqttControlPacketType::Subscribe
    );
    assert_eq!(mqtt_layers[2].packet_id_value(), Some(0x1234));
    assert_eq!(
        mqtt_layers[2].subscribe_topics_value(),
        Some(&[("topic".to_string(), MQTT_PUBLISH_QOS_1)][..])
    );

    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn stacked_mqtt_decode_preserves_partial_tail_as_raw() -> crafter::Result<()> {
    let mqtt_payload = [0xc0, 0x00, 0xd0, 0x00, 0xe0];
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 70))
        .dst(Ipv4Addr::new(198, 51, 100, 80))
        / Tcp::new()
            .sport(49_154)
            .dport(MQTT_PORT)
            .seq(0x3132_3334)
            .ack(0x4142_4344)
            .ack_segment()
        / Raw::from_bytes(mqtt_payload);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, ["Ipv4", "Tcp", "MQTT", "MQTT", "Raw"]);

    let mqtt_layers = decoded.layers::<Mqtt>().collect::<Vec<_>>();
    assert_eq!(mqtt_layers.len(), 2);
    assert_eq!(mqtt_layers[0].packet_type(), MqttControlPacketType::Pingreq);
    assert_eq!(
        mqtt_layers[1].packet_type(),
        MqttControlPacketType::Pingresp
    );

    let raw = decoded.layer::<Raw>().expect("partial mqtt tail");
    assert_eq!(raw.as_bytes(), &[0xe0]);
    Ok(())
}
