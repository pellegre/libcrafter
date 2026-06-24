//! MQTT decode entrypoints.

use crate::error::{CrafterError, Result};
use crate::packet::{Packet, Raw};
use crate::registry::ProtocolRegistry;

use super::constants::{
    MQTT_CONNECT_FLAG_PASSWORD, MQTT_CONNECT_FLAG_USER_NAME, MQTT_CONNECT_FLAG_WILL,
    MQTT_PUBLISH_FLAG_QOS_MASK,
};
use super::header::MqttControlPacketType;
use super::varint::decode_remaining_length;
use super::wire::{decode_binary, decode_string, decode_u16};
use super::Mqtt;

const PUBLISH_QOS_SHIFT: u8 = 1;

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

    let body = &bytes[header_len..total_len];
    let mqtt = match packet_type {
        MqttControlPacketType::Connect => decode_connect(flags, remaining_length, body)?,
        MqttControlPacketType::Connack => decode_connack(flags, remaining_length, body)?,
        MqttControlPacketType::Publish => decode_publish(flags, remaining_length, body)?,
        MqttControlPacketType::Puback => {
            decode_packet_identifier(packet_type, flags, remaining_length, body, "mqtt.puback")?
        }
        _ => Mqtt::raw(packet_type, body.to_vec())
            .flags(flags)
            .remaining_length(remaining_length),
    };

    Ok((mqtt, total_len))
}

fn decode_connect(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    let mut cursor = 0;

    let protocol_name = take_string(body, &mut cursor)?;
    let protocol_level = take_u8(body, &mut cursor, "mqtt.connect.protocol_level")?;
    let connect_flags = take_u8(body, &mut cursor, "mqtt.connect.flags")?;
    let keep_alive = take_u16(body, &mut cursor)?;
    let client_id = take_string(body, &mut cursor)?;

    let (will_topic, will_message) = if connect_flags & MQTT_CONNECT_FLAG_WILL != 0 {
        (
            Some(take_string(body, &mut cursor)?),
            Some(take_binary(body, &mut cursor)?),
        )
    } else {
        (None, None)
    };

    let username = if connect_flags & MQTT_CONNECT_FLAG_USER_NAME != 0 {
        Some(take_string(body, &mut cursor)?)
    } else {
        None
    };

    let password = if connect_flags & MQTT_CONNECT_FLAG_PASSWORD != 0 {
        Some(take_binary(body, &mut cursor)?)
    } else {
        None
    };

    if cursor != body.len() {
        return Err(CrafterError::invalid_field_value(
            "mqtt.connect.remaining_length",
            "CONNECT Remaining Length includes bytes not described by CONNECT flags",
        ));
    }

    Ok(Mqtt::connect_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        protocol_name,
        protocol_level,
        connect_flags,
        keep_alive,
        client_id,
        will_topic,
        will_message,
        username,
        password,
    ))
}

fn decode_connack(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    let mut cursor = 0;

    let ack_flags = take_u8(body, &mut cursor, "mqtt.connack.ack_flags")?;
    let return_code = take_u8(body, &mut cursor, "mqtt.connack.return_code")?;

    if cursor != body.len() {
        return Err(CrafterError::invalid_field_value(
            "mqtt.connack.remaining_length",
            "CONNACK Remaining Length must be 2",
        ));
    }

    Ok(Mqtt::connack_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        ack_flags,
        return_code,
    ))
}

fn decode_publish(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    let mut cursor = 0;

    let topic = take_string(body, &mut cursor)?;
    let packet_id = if publish_qos(fixed_header_flags) != 0 {
        Some(take_u16(body, &mut cursor)?)
    } else {
        None
    };
    let payload = body[cursor..].to_vec();

    Ok(Mqtt::publish_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        topic,
        packet_id,
        payload,
    ))
}

fn decode_packet_identifier(
    packet_type: MqttControlPacketType,
    fixed_header_flags: u8,
    remaining_length: u32,
    body: &[u8],
    context: &'static str,
) -> Result<Mqtt> {
    if body.len() < 2 {
        return Err(CrafterError::buffer_too_short(context, 2, body.len()));
    }
    if body.len() != 2 {
        return Err(CrafterError::invalid_field_value(
            "mqtt.packet_identifier.remaining_length",
            "packet identifier control packet Remaining Length must be 2",
        ));
    }

    let (packet_id, _consumed) = decode_u16(body)?;
    Ok(Mqtt::packet_identifier_from_decoded_parts(
        packet_type,
        fixed_header_flags,
        remaining_length,
        packet_id,
    ))
}

fn take_u8(bytes: &[u8], cursor: &mut usize, context: &'static str) -> Result<u8> {
    let Some(&value) = bytes.get(*cursor) else {
        return Err(CrafterError::buffer_too_short(
            context,
            cursor.saturating_add(1),
            bytes.len(),
        ));
    };

    *cursor += 1;
    Ok(value)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    let (value, consumed) = decode_u16(&bytes[*cursor..])?;
    *cursor += consumed;
    Ok(value)
}

fn take_string(bytes: &[u8], cursor: &mut usize) -> Result<String> {
    let (value, consumed) = decode_string(&bytes[*cursor..])?;
    *cursor += consumed;
    Ok(value)
}

fn take_binary(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
    let (value, consumed) = decode_binary(&bytes[*cursor..])?;
    *cursor += consumed;
    Ok(value)
}

fn publish_qos(flags: u8) -> u8 {
    (flags & MQTT_PUBLISH_FLAG_QOS_MASK) >> PUBLISH_QOS_SHIFT
}

fn is_incomplete_mqtt_frame(context: &'static str) -> bool {
    matches!(
        context,
        "mqtt.fixed_header" | "mqtt.remaining_length" | "mqtt.control_packet"
    )
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
            Err(CrafterError::BufferTooShort { context, .. })
                if is_incomplete_mqtt_frame(context) =>
            {
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
        let bytes = [0xb0, 0x03, b'a', b'b', b'c'];

        let (mqtt, consumed) = decode_mqtt(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(mqtt.name(), "MQTT");
        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Unsuback);
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

    #[test]
    fn decodes_typed_connack_and_rejects_inconsistent_lengths() {
        let (mqtt, consumed) = decode_mqtt(&[0x20, 0x02, 0x01, 0x03]).unwrap();

        assert_eq!(consumed, 4);
        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connack);
        assert_eq!(mqtt.session_present_value(), Some(true));
        assert_eq!(mqtt.return_code_value(), Some(0x03));

        match decode_mqtt(&[0x20, 0x01, 0x00]) {
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "mqtt.connack.return_code");
                assert_eq!(required, 2);
                assert_eq!(available, 1);
            }
            other => panic!("expected connack truncation error, got {other:?}"),
        }

        match decode_mqtt(&[0x20, 0x03, 0x00, 0x00, 0x00]) {
            Err(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "mqtt.connack.remaining_length");
                assert!(reason.contains("must be 2"));
            }
            other => panic!("expected connack length error, got {other:?}"),
        }
    }

    #[test]
    fn decodes_typed_puback_and_rejects_truncated_packet_identifier() {
        let (mqtt, consumed) = decode_mqtt(&[0x40, 0x02, 0x12, 0x34]).unwrap();

        assert_eq!(consumed, 4);
        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Puback);
        assert_eq!(mqtt.packet_id_value(), Some(0x1234));

        match decode_mqtt(&[0x40, 0x01, 0x12]) {
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "mqtt.puback");
                assert_eq!(required, 2);
                assert_eq!(available, 1);
            }
            other => panic!("expected puback truncation error, got {other:?}"),
        }
    }
}
