//! MQTT decode entrypoints.

use crate::error::{CrafterError, Result};
use crate::packet::{Packet, Raw};
use crate::registry::ProtocolRegistry;

use super::header::MqttControlPacketType;
use super::varint::decode_remaining_length;
use super::Mqtt;

/// Decode a single MQTT control packet from the front of `bytes`.
pub(crate) fn decode_mqtt(bytes: &[u8]) -> Result<(Mqtt, usize)> {
    let first_byte = *bytes
        .first()
        .ok_or_else(|| CrafterError::buffer_too_short("mqtt.fixed_header", 1, bytes.len()))?;
    let packet_type = MqttControlPacketType::from_fixed_header_byte(first_byte)?;
    let flags = first_byte & 0x0f;

    let (remaining_length, remaining_length_len) = decode_remaining_length(&bytes[1..])?;
    let header_len = 1 + remaining_length_len;
    let body_len = usize::try_from(remaining_length).map_err(|_| {
        CrafterError::invalid_field_value("mqtt.remaining_length", "remaining length is too large")
    })?;
    let total_len = header_len.checked_add(body_len).ok_or_else(|| {
        CrafterError::invalid_field_value("mqtt.remaining_length", "remaining length is too large")
    })?;

    if bytes.len() < total_len {
        return Err(CrafterError::buffer_too_short(
            "mqtt.control_packet",
            total_len,
            bytes.len(),
        ));
    }

    let body = bytes[header_len..total_len].to_vec();
    let mqtt = Mqtt::raw(packet_type, body)
        .flags(flags)
        .remaining_length(remaining_length);

    Ok((mqtt, total_len))
}

/// Decode one or more MQTT control packets from a TCP payload.
pub(crate) fn append_mqtt_packet_with_registry(
    _registry: &ProtocolRegistry,
    mut packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let mut remaining = bytes;

    while !remaining.is_empty() {
        match decode_mqtt(remaining) {
            Ok((mqtt, consumed)) if consumed > 0 => {
                packet = packet.push(mqtt);
                remaining = &remaining[consumed..];
            }
            Ok((_mqtt, _consumed)) => {
                packet = packet.push(Raw::from_bytes(remaining));
                break;
            }
            Err(CrafterError::BufferTooShort { .. }) => {
                packet = packet.push(Raw::from_bytes(remaining));
                break;
            }
            Err(CrafterError::InvalidFieldValue {
                field: "mqtt.fixed_header.control_packet_type",
                ..
            }) => {
                packet = packet.push(Raw::from_bytes(remaining));
                break;
            }
            Err(err) => return Err(err),
        }
    }

    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Layer;

    #[test]
    fn decodes_single_raw_packet() {
        let bytes = [0x30, 0x03, b'a', b'b', b'c'];

        let (mqtt, consumed) = decode_mqtt(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(mqtt.name(), "MQTT");
        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
        assert_eq!(mqtt.flags_value(), 0x0);
        assert_eq!(mqtt.remaining_length_value(), 3);
        assert_eq!(mqtt.body(), b"abc");
    }

    #[test]
    fn truncated_final_packet_is_preserved_as_raw() {
        let payload = [0xc0, 0x00, 0xd0, 0x02, 0xaa];

        let packet =
            append_mqtt_packet_with_registry(&ProtocolRegistry::empty(), Packet::new(), &payload)
                .unwrap();
        let names = packet.iter().map(|layer| layer.name()).collect::<Vec<_>>();
        let mqtt_layers = packet.layers::<Mqtt>().collect::<Vec<_>>();
        let raw = packet.layer::<Raw>().unwrap();

        assert_eq!(names, ["MQTT", "Raw"]);
        assert_eq!(mqtt_layers.len(), 1);
        assert_eq!(mqtt_layers[0].packet_type(), MqttControlPacketType::Pingreq);
        assert_eq!(raw.as_bytes(), &[0xd0, 0x02, 0xaa]);
    }
}
