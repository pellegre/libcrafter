use std::net::Ipv4Addr;

use crafter::prelude::*;

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
