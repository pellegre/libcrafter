use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crafter::prelude::*;
use crafter::protocols::mqtt::{MQTT_PUBLISH_QOS_1, MQTT_TLS_PORT};
use crafter::wire::backend::pcap::{PcapLinkType, PcapReader, PcapWriter};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

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
fn ethernet_ipv4_tcp_publish_decodes_from_link_to_mqtt() -> crafter::Result<()> {
    let packet = Ethernet::new()
        / Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 92))
            .dst(Ipv4Addr::new(198, 51, 100, 92))
        / Tcp::new()
            .sport(49_192)
            .dport(MQTT_PORT)
            .seq(0x7172_7374)
            .ack(0x8182_8384)
            .ack_segment()
        / Mqtt::publish()
            .topic("telemetry")
            .payload(b"online".to_vec());

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes())?;

    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, ["Ethernet", "Ipv4", "Tcp", "MQTT"]);

    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBLISH layer");
    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt.topic_value(), Some("telemetry"));
    assert_eq!(mqtt.payload_value(), Some(&b"online"[..]));
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn ethernet_ipv4_tcp_secure_mqtt_port_remains_raw_payload() -> crafter::Result<()> {
    let mqtt = Mqtt::publish()
        .topic("telemetry")
        .payload(b"online".to_vec());
    let mqtt_bytes = Packet::from_layer(mqtt.clone()).compile()?;
    let packet = Ethernet::new()
        / Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 93))
            .dst(Ipv4Addr::new(198, 51, 100, 93))
        / Tcp::new()
            .sport(49_193)
            .dport(MQTT_TLS_PORT)
            .seq(0x9192_9394)
            .ack(0xa1a2_a3a4)
            .ack_segment()
        // Port 8883 is registered for TLS-wrapped secure-mqtt, not cleartext MQTT.
        / mqtt;

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes())?;

    let layer_names = decoded.iter().map(|layer| layer.name()).collect::<Vec<_>>();
    assert_eq!(layer_names, ["Ethernet", "Ipv4", "Tcp", "Raw"]);
    assert!(decoded.layer::<Mqtt>().is_none());

    let raw = decoded.layer::<Raw>().expect("secure-mqtt opaque payload");
    assert_eq!(raw.as_bytes(), mqtt_bytes.as_bytes());
    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
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

#[test]
fn pcap_roundtrip_preserves_mqtt_publish_packet() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "crafter-mqtt-pcap-{}-{}.pcap",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos()
    ));
    let packet = Ethernet::with_addresses(
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]),
        MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x02]),
    ) / Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 91))
        .dst(Ipv4Addr::new(198, 51, 100, 91))
        / Tcp::new()
            .sport(49_191)
            .dport(MQTT_PORT)
            .seq(0x5152_5354)
            .ack(0x6162_6364)
            .ack_segment()
        / Mqtt::publish()
            .topic("telemetry")
            .qos(MQTT_PUBLISH_QOS_1)
            .packet_id(0x1234)
            .payload(b"online".to_vec());
    let written_bytes = packet.compile()?;

    {
        let mut writer = PcapWriter::create(&path, PcapLinkType::Ethernet)?;
        writer.write_packet(&packet)?;
        writer.flush()?;
    }

    let records = PcapReader::open(&path)?.collect_records()?;
    let packets = PcapReader::open(&path)?.collect_packets()?;
    std::fs::remove_file(&path)?;

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].pcap_link_type(), PcapLinkType::Ethernet);
    assert_eq!(records[0].data(), written_bytes.as_bytes());

    assert_eq!(packets.len(), 1);
    let decoded = packets[0].packet();
    assert_eq!(decoded.compile()?.as_bytes(), written_bytes.as_bytes());

    let mqtt = decoded.layer::<Mqtt>().expect("decoded MQTT PUBLISH layer");
    assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
    assert_eq!(mqtt.topic_value(), Some("telemetry"));
    assert_eq!(mqtt.qos_value(), Some(MQTT_PUBLISH_QOS_1));
    assert_eq!(mqtt.packet_id_value(), Some(0x1234));
    assert_eq!(mqtt.payload_value(), Some(&b"online"[..]));
    Ok(())
}
