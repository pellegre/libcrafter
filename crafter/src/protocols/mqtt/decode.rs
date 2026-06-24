//! MQTT decode entrypoints.

use core::str;

use crate::error::{CrafterError, Result};
use crate::packet::{Packet, Raw};
use crate::registry::ProtocolRegistry;

use super::constants::{
    MQTT_311_PROTOCOL_LEVEL, MQTT_5_PROTOCOL_LEVEL, MQTT_CONNECT_FLAG_PASSWORD,
    MQTT_CONNECT_FLAG_USER_NAME, MQTT_CONNECT_FLAG_WILL, MQTT_PUBLISH_FLAG_QOS_MASK,
};
use super::header::MqttControlPacketType;
use super::property::MqttProperties;
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
        MqttControlPacketType::Pubrec => {
            decode_packet_identifier(packet_type, flags, remaining_length, body, "mqtt.pubrec")?
        }
        MqttControlPacketType::Pubrel => {
            // The decoded fixed-header flags are preserved exactly; callers can
            // decide whether to enforce MQTT 3.1.1's reserved PUBREL value.
            decode_packet_identifier(packet_type, flags, remaining_length, body, "mqtt.pubrel")?
        }
        MqttControlPacketType::Pubcomp => {
            decode_packet_identifier(packet_type, flags, remaining_length, body, "mqtt.pubcomp")?
        }
        MqttControlPacketType::Unsuback => {
            decode_packet_identifier(packet_type, flags, remaining_length, body, "mqtt.unsuback")?
        }
        MqttControlPacketType::Pingreq => {
            decode_empty_packet(packet_type, flags, remaining_length, body, "mqtt.pingreq")?
        }
        MqttControlPacketType::Pingresp => {
            decode_empty_packet(packet_type, flags, remaining_length, body, "mqtt.pingresp")?
        }
        MqttControlPacketType::Disconnect => decode_empty_packet(
            packet_type,
            flags,
            remaining_length,
            body,
            "mqtt.disconnect",
        )?,
        MqttControlPacketType::Auth => Mqtt::raw(packet_type, body.to_vec())
            .flags(flags)
            .remaining_length(remaining_length),
        MqttControlPacketType::Subscribe => decode_subscribe(flags, remaining_length, body)?,
        MqttControlPacketType::Suback => decode_suback(flags, remaining_length, body)?,
        MqttControlPacketType::Unsubscribe => decode_unsubscribe(flags, remaining_length, body)?,
    };

    Ok((mqtt, total_len))
}

fn decode_connect(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    let mut cursor = 0;

    let protocol_name = take_string(body, &mut cursor)?;
    let protocol_level = take_u8(body, &mut cursor, "mqtt.connect.protocol_level")?;
    let connect_flags = take_u8(body, &mut cursor, "mqtt.connect.flags")?;
    let keep_alive = take_u16(body, &mut cursor)?;
    let connect_properties = if protocol_level == MQTT_5_PROTOCOL_LEVEL {
        take_properties(body, &mut cursor)?
    } else {
        MqttProperties::new()
    };
    let client_id = take_string(body, &mut cursor)?;

    let (will_properties, will_topic, will_message) = if connect_flags & MQTT_CONNECT_FLAG_WILL != 0
    {
        let will_properties = if protocol_level == MQTT_5_PROTOCOL_LEVEL {
            take_properties(body, &mut cursor)?
        } else {
            MqttProperties::new()
        };
        (
            will_properties,
            Some(take_string(body, &mut cursor)?),
            Some(take_binary(body, &mut cursor)?),
        )
    } else {
        (MqttProperties::new(), None, None)
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
        connect_properties,
        client_id,
        will_properties,
        will_topic,
        will_message,
        username,
        password,
    ))
}

fn decode_connack(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    decode_connack_with_version(
        fixed_header_flags,
        remaining_length,
        MQTT_311_PROTOCOL_LEVEL,
        body,
    )
}

fn decode_connack_with_version(
    fixed_header_flags: u8,
    remaining_length: u32,
    version: u8,
    body: &[u8],
) -> Result<Mqtt> {
    let mut cursor = 0;

    let ack_flags = take_u8(body, &mut cursor, "mqtt.connack.ack_flags")?;
    let reason_code = take_u8(body, &mut cursor, "mqtt.connack.return_code")?;
    let properties = if version == MQTT_5_PROTOCOL_LEVEL {
        take_properties(body, &mut cursor)?
    } else {
        MqttProperties::new()
    };

    if cursor != body.len() {
        let reason = if version == MQTT_5_PROTOCOL_LEVEL {
            "CONNACK Remaining Length includes bytes outside the property block"
        } else {
            "CONNACK Remaining Length must be 2"
        };
        return Err(CrafterError::invalid_field_value(
            "mqtt.connack.remaining_length",
            reason,
        ));
    }

    Ok(Mqtt::connack_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        version,
        ack_flags,
        reason_code,
        properties,
    ))
}

fn decode_publish(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    decode_publish_with_version(
        fixed_header_flags,
        remaining_length,
        MQTT_311_PROTOCOL_LEVEL,
        body,
    )
}

fn decode_publish_with_version(
    fixed_header_flags: u8,
    remaining_length: u32,
    version: u8,
    body: &[u8],
) -> Result<Mqtt> {
    let mut cursor = 0;

    let topic = take_string(body, &mut cursor)?;
    let packet_id = if publish_qos(fixed_header_flags) != 0 {
        Some(take_u16(body, &mut cursor)?)
    } else {
        None
    };
    let properties = if version == MQTT_5_PROTOCOL_LEVEL {
        take_properties(body, &mut cursor)?
    } else {
        MqttProperties::new()
    };
    let payload = body[cursor..].to_vec();

    Ok(Mqtt::publish_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        version,
        topic,
        packet_id,
        properties,
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
    decode_packet_identifier_with_version(
        packet_type,
        fixed_header_flags,
        remaining_length,
        MQTT_311_PROTOCOL_LEVEL,
        body,
        context,
    )
}

fn decode_packet_identifier_with_version(
    packet_type: MqttControlPacketType,
    fixed_header_flags: u8,
    remaining_length: u32,
    version: u8,
    body: &[u8],
    context: &'static str,
) -> Result<Mqtt> {
    if body.len() < 2 {
        return Err(CrafterError::buffer_too_short(context, 2, body.len()));
    }
    if version != MQTT_5_PROTOCOL_LEVEL && body.len() != 2 {
        return Err(CrafterError::invalid_field_value(
            "mqtt.packet_identifier.remaining_length",
            "packet identifier control packet Remaining Length must be 2",
        ));
    }

    let mut cursor = 0;
    let packet_id = take_u16(body, &mut cursor)?;
    let (reason_code, properties) = if version == MQTT_5_PROTOCOL_LEVEL {
        if cursor == body.len() {
            (None, MqttProperties::new())
        } else {
            let reason_code = take_u8(body, &mut cursor, "mqtt.packet_identifier.reason_code")?;
            let properties = take_properties(body, &mut cursor)?;
            if cursor != body.len() {
                return Err(CrafterError::invalid_field_value(
                    "mqtt.packet_identifier.remaining_length",
                    "Remaining Length includes bytes outside the property block",
                ));
            }
            (Some(reason_code), properties)
        }
    } else {
        (None, MqttProperties::new())
    };

    Ok(Mqtt::packet_identifier_from_decoded_parts(
        packet_type,
        fixed_header_flags,
        remaining_length,
        version,
        packet_id,
        reason_code,
        properties,
    ))
}

fn decode_empty_packet(
    packet_type: MqttControlPacketType,
    fixed_header_flags: u8,
    remaining_length: u32,
    body: &[u8],
    context: &'static str,
) -> Result<Mqtt> {
    if !body.is_empty() {
        let field = match context {
            "mqtt.pingreq" => "mqtt.pingreq.remaining_length",
            "mqtt.pingresp" => "mqtt.pingresp.remaining_length",
            "mqtt.disconnect" => "mqtt.disconnect.remaining_length",
            _ => "mqtt.empty.remaining_length",
        };
        return Err(CrafterError::invalid_field_value(
            field,
            "empty MQTT control packet Remaining Length must be 0",
        ));
    }

    Ok(Mqtt::empty_from_decoded_parts(
        packet_type,
        fixed_header_flags,
        remaining_length,
    ))
}

fn decode_suback(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    let mut cursor = 0;

    if body.len() < 2 {
        return Err(CrafterError::buffer_too_short(
            "mqtt.suback.packet_identifier",
            2,
            body.len(),
        ));
    }
    let packet_id = take_u16(body, &mut cursor)?;
    let return_codes = body[cursor..].to_vec();

    Ok(Mqtt::suback_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        packet_id,
        return_codes,
    ))
}

fn decode_unsubscribe(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    let mut cursor = 0;

    if body.len() < 2 {
        return Err(CrafterError::buffer_too_short(
            "mqtt.unsubscribe.packet_identifier",
            2,
            body.len(),
        ));
    }
    let packet_id = take_u16(body, &mut cursor)?;
    let mut topics = Vec::new();

    while cursor < body.len() {
        let filter = take_string_with_context(
            body,
            &mut cursor,
            "mqtt.unsubscribe.topic_filter.length",
            "mqtt.unsubscribe.topic_filter",
        )?;
        topics.push(filter);
    }

    Ok(Mqtt::unsubscribe_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        packet_id,
        topics,
    ))
}

fn decode_subscribe(fixed_header_flags: u8, remaining_length: u32, body: &[u8]) -> Result<Mqtt> {
    decode_subscribe_with_version(
        fixed_header_flags,
        remaining_length,
        MQTT_311_PROTOCOL_LEVEL,
        body,
    )
}

fn decode_subscribe_with_version(
    fixed_header_flags: u8,
    remaining_length: u32,
    version: u8,
    body: &[u8],
) -> Result<Mqtt> {
    let mut cursor = 0;

    if body.len() < 2 {
        return Err(CrafterError::buffer_too_short(
            "mqtt.subscribe.packet_identifier",
            2,
            body.len(),
        ));
    }
    let packet_id = take_u16(body, &mut cursor)?;
    let properties = if version == MQTT_5_PROTOCOL_LEVEL {
        take_properties(body, &mut cursor)?
    } else {
        MqttProperties::new()
    };
    let mut topics = Vec::new();

    while cursor < body.len() {
        let filter = take_string_with_context(
            body,
            &mut cursor,
            "mqtt.subscribe.topic_filter.length",
            "mqtt.subscribe.topic_filter",
        )?;
        let qos = take_u8(body, &mut cursor, "mqtt.subscribe.requested_qos")?;
        topics.push((filter, qos));
    }

    Ok(Mqtt::subscribe_from_decoded_parts(
        fixed_header_flags,
        remaining_length,
        version,
        packet_id,
        properties,
        topics,
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

fn take_string_with_context(
    bytes: &[u8],
    cursor: &mut usize,
    length_context: &'static str,
    value_context: &'static str,
) -> Result<String> {
    let prefix_end = (*cursor).saturating_add(2);
    if bytes.len() < prefix_end {
        return Err(CrafterError::buffer_too_short(
            length_context,
            prefix_end,
            bytes.len(),
        ));
    }

    let length = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]) as usize;
    let value_end = prefix_end
        .checked_add(length)
        .ok_or_else(|| CrafterError::invalid_field_value(value_context, "length is too large"))?;
    if bytes.len() < value_end {
        return Err(CrafterError::buffer_too_short(
            value_context,
            value_end,
            bytes.len(),
        ));
    }

    let raw = &bytes[prefix_end..value_end];
    let value = str::from_utf8(raw).map_err(|_| {
        CrafterError::invalid_field_value(value_context, "string bytes must be valid UTF-8")
    })?;
    if value.as_bytes().contains(&0) {
        return Err(CrafterError::invalid_field_value(
            value_context,
            "string must not contain U+0000",
        ));
    }

    *cursor = value_end;
    Ok(value.to_owned())
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

fn take_properties(bytes: &[u8], cursor: &mut usize) -> Result<MqttProperties> {
    let (properties, consumed) = MqttProperties::decode(&bytes[*cursor..])?;
    *cursor += consumed;
    Ok(properties)
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
    use crate::protocols::mqtt::{MqttProperty, MqttSubscriptionOptions};

    #[test]
    fn decodes_typed_disconnect_and_rejects_declared_body() {
        let bytes = [0xe0, 0x00];

        let (mqtt, consumed) = decode_mqtt(&bytes).unwrap();

        assert_eq!(consumed, bytes.len());
        assert_eq!(mqtt.name(), "MQTT");
        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Disconnect);
        assert_eq!(mqtt.flags_value(), 0x0);
        assert_eq!(mqtt.remaining_length_value(), 0);
        assert!(mqtt.body().is_empty());

        match decode_mqtt(&[0xe0, 0x01, 0x00]) {
            Err(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "mqtt.disconnect.remaining_length");
                assert!(reason.contains("must be 0"));
            }
            other => panic!("expected disconnect remaining-length error, got {other:?}"),
        }
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
    fn decodes_v5_connack_with_reason_code_and_properties_when_version_is_supplied() {
        let body = [
            0x01, 0x8c, 0x0e, 0x12, 0x00, 0x03, b's', b'r', b'v', 0x21, 0x00, 0x14, 0x1f, 0x00,
            0x02, b'n', b'o',
        ];
        let mqtt = decode_connack_with_version(0, body.len() as u32, MQTT_5_PROTOCOL_LEVEL, &body)
            .unwrap();

        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Connack);
        assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
        assert_eq!(mqtt.session_present_value(), Some(true));
        assert_eq!(mqtt.reason_code_value(), Some(0x8c));
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

        let compiled = Packet::from_layer(mqtt).compile().unwrap();
        assert_eq!(
            compiled.as_bytes(),
            &[
                0x20, 0x11, 0x01, 0x8c, 0x0e, 0x12, 0x00, 0x03, b's', b'r', b'v', 0x21, 0x00, 0x14,
                0x1f, 0x00, 0x02, b'n', b'o',
            ]
        );
    }

    #[test]
    fn decodes_v5_publish_properties_before_payload_when_version_is_supplied() {
        let body = [
            0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b't', 0x12, 0x34, 0x1c,
            0x23, 0x00, 0x07, 0x03, 0x00, 0x0a, b't', b'e', b'x', b't', b'/', b'p', b'l', b'a',
            b'i', b'n', 0x26, 0x00, 0x04, b's', b'i', b't', b'e', 0x00, 0x03, b'l', b'a', b'b',
            b'4', b'2',
        ];
        let mqtt =
            decode_publish_with_version(0x02, body.len() as u32, MQTT_5_PROTOCOL_LEVEL, &body)
                .unwrap();

        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Publish);
        assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
        assert_eq!(mqtt.topic_value(), Some("sensors/t"));
        assert_eq!(mqtt.qos_value(), Some(1));
        assert_eq!(mqtt.packet_id_value(), Some(0x1234));
        assert_eq!(mqtt.payload_value(), Some(&b"42"[..]));
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

        let compiled = Packet::from_layer(mqtt).compile().unwrap();
        assert_eq!(
            compiled.as_bytes(),
            &[
                0x32, 0x2c, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r', b's', b'/', b't', 0x12,
                0x34, 0x1c, 0x23, 0x00, 0x07, 0x03, 0x00, 0x0a, b't', b'e', b'x', b't', b'/', b'p',
                b'l', b'a', b'i', b'n', 0x26, 0x00, 0x04, b's', b'i', b't', b'e', 0x00, 0x03, b'l',
                b'a', b'b', b'4', b'2',
            ]
        );
    }

    #[test]
    fn decodes_v5_puback_family_short_and_full_forms_when_version_is_supplied() {
        let full_body = [
            0x12, 0x34, 0x10, 0x09, 0x1f, 0x00, 0x06, b'q', b'u', b'e', b'u', b'e', b'd',
        ];
        let full = decode_packet_identifier_with_version(
            MqttControlPacketType::Puback,
            0x00,
            full_body.len() as u32,
            MQTT_5_PROTOCOL_LEVEL,
            &full_body,
            "mqtt.puback",
        )
        .unwrap();

        assert_eq!(full.version_value(), MQTT_5_PROTOCOL_LEVEL);
        assert_eq!(full.packet_id_value(), Some(0x1234));
        assert_eq!(full.reason_code_value(), Some(0x10));
        assert_eq!(
            full.ack_properties_value()
                .expect("ack properties")
                .property_values(),
            &[MqttProperty::ReasonString("queued".to_string())]
        );
        assert_eq!(
            Packet::from_layer(full).compile().unwrap().as_bytes(),
            &[
                0x40, 0x0d, 0x12, 0x34, 0x10, 0x09, 0x1f, 0x00, 0x06, b'q', b'u', b'e', b'u', b'e',
                b'd'
            ]
        );

        let short_body = [0x12, 0x34];
        let short = decode_packet_identifier_with_version(
            MqttControlPacketType::Puback,
            0x00,
            short_body.len() as u32,
            MQTT_5_PROTOCOL_LEVEL,
            &short_body,
            "mqtt.puback",
        )
        .unwrap();

        assert_eq!(short.reason_code_value(), Some(0x00));
        assert!(short
            .ack_properties_value()
            .expect("short-form ack properties")
            .property_values()
            .is_empty());
        assert_eq!(
            Packet::from_layer(short).compile().unwrap().as_bytes(),
            &[0x40, 0x02, 0x12, 0x34]
        );

        let pubrel_body = [0x22, 0x22, 0x92, 0x00];
        let pubrel = decode_packet_identifier_with_version(
            MqttControlPacketType::Pubrel,
            0x02,
            pubrel_body.len() as u32,
            MQTT_5_PROTOCOL_LEVEL,
            &pubrel_body,
            "mqtt.pubrel",
        )
        .unwrap();

        assert_eq!(pubrel.flags_value(), 0x02);
        assert_eq!(
            Packet::from_layer(pubrel).compile().unwrap().as_bytes(),
            &[0x62, 0x04, 0x22, 0x22, 0x92, 0x00]
        );
    }

    #[test]
    fn decodes_v5_subscribe_properties_and_subscription_options_when_version_is_supplied() {
        let body = [
            0x12, 0x34, 0x03, 0x0b, 0xc1, 0x02, 0x00, 0x09, b's', b'e', b'n', b's', b'o', b'r',
            b's', b'/', b'+', 0x15,
        ];
        let mqtt =
            decode_subscribe_with_version(0x02, body.len() as u32, MQTT_5_PROTOCOL_LEVEL, &body)
                .unwrap();

        assert_eq!(mqtt.packet_type(), MqttControlPacketType::Subscribe);
        assert_eq!(mqtt.version_value(), MQTT_5_PROTOCOL_LEVEL);
        assert_eq!(mqtt.packet_id_value(), Some(0x1234));
        assert_eq!(
            mqtt.subscribe_properties_value()
                .expect("subscribe properties")
                .property_values(),
            &[MqttProperty::SubscriptionIdentifier(321)]
        );

        let topics = mqtt
            .subscribe_topic_options_value()
            .expect("subscribe topic options");
        assert_eq!(topics.len(), 1);
        assert_eq!(topics[0].0, "sensors/+");
        let options = topics[0].1;
        assert_eq!(options, MqttSubscriptionOptions::from_bits(0x15));
        assert_eq!(options.qos(), 1);
        assert!(options.no_local());
        assert!(!options.retain_as_published());
        assert_eq!(options.retain_handling(), 1);

        assert_eq!(
            Packet::from_layer(mqtt).compile().unwrap().as_bytes(),
            &[
                0x82, 0x12, 0x12, 0x34, 0x03, 0x0b, 0xc1, 0x02, 0x00, 0x09, b's', b'e', b'n', b's',
                b'o', b'r', b's', b'/', b'+', 0x15,
            ]
        );
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
