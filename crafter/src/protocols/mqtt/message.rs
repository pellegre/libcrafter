//! MQTT control packet layer.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

use super::header::MqttControlPacketType;
use super::varint::encode_remaining_length;

/// MQTT control packet with an opaque variable-header/payload body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mqtt {
    packet_type: MqttControlPacketType,
    flags: Field<u8>,
    remaining_length: Field<u32>,
    body: Vec<u8>,
}

impl Mqtt {
    /// Build an MQTT control packet with an opaque body.
    pub fn raw(packet_type: MqttControlPacketType, body: impl Into<Vec<u8>>) -> Self {
        Self {
            packet_type,
            flags: Field::defaulted(packet_type.default_flags()),
            remaining_length: Field::unset(),
            body: body.into(),
        }
    }

    /// Set the fixed-header flags nibble.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Force the fixed-header Remaining Length field.
    pub fn remaining_length(mut self, remaining_length: u32) -> Self {
        self.remaining_length.set_user(remaining_length);
        self
    }

    /// MQTT control packet type.
    pub fn packet_type(&self) -> MqttControlPacketType {
        self.packet_type
    }

    /// Fixed-header flags nibble value.
    pub fn flags_value(&self) -> u8 {
        self.flags
            .value()
            .copied()
            .unwrap_or(self.packet_type.default_flags())
            & 0x0f
    }

    /// Effective Remaining Length value.
    pub fn remaining_length_value(&self) -> u32 {
        self.remaining_length
            .value()
            .copied()
            .unwrap_or_else(|| u32::try_from(self.body.len()).unwrap_or(u32::MAX))
    }

    /// Explicit Remaining Length value, if one was set.
    pub fn explicit_remaining_length(&self) -> Option<u32> {
        self.remaining_length.value().copied()
    }

    /// Opaque bytes after the fixed header.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    fn first_byte(&self) -> u8 {
        self.packet_type.high_nibble() | self.flags_value()
    }
}

impl Layer for Mqtt {
    fn name(&self) -> &'static str {
        "MQTT"
    }

    fn summary(&self) -> String {
        format!(
            "MQTT {} len={} body={} bytes",
            packet_type_name(self.packet_type),
            self.remaining_length_value(),
            self.body.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("type", packet_type_name(self.packet_type).to_string()),
            ("flags", format!("0x{:x}", self.flags_value())),
            (
                "remaining_length",
                self.remaining_length_value().to_string(),
            ),
            ("body_length", self.body.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        1 + remaining_length_encoded_len(self.remaining_length_value()) + self.body.len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.push(self.first_byte());
        encode_remaining_length(self.remaining_length_value(), out)?;
        out.extend_from_slice(&self.body);
        Ok(())
    }

    impl_layer_object!(Mqtt);
}

impl_layer_div!(Mqtt);

fn remaining_length_encoded_len(value: u32) -> usize {
    match value {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

fn packet_type_name(packet_type: MqttControlPacketType) -> &'static str {
    match packet_type {
        MqttControlPacketType::Connect => "CONNECT",
        MqttControlPacketType::Connack => "CONNACK",
        MqttControlPacketType::Publish => "PUBLISH",
        MqttControlPacketType::Puback => "PUBACK",
        MqttControlPacketType::Pubrec => "PUBREC",
        MqttControlPacketType::Pubrel => "PUBREL",
        MqttControlPacketType::Pubcomp => "PUBCOMP",
        MqttControlPacketType::Subscribe => "SUBSCRIBE",
        MqttControlPacketType::Suback => "SUBACK",
        MqttControlPacketType::Unsubscribe => "UNSUBSCRIBE",
        MqttControlPacketType::Unsuback => "UNSUBACK",
        MqttControlPacketType::Pingreq => "PINGREQ",
        MqttControlPacketType::Pingresp => "PINGRESP",
        MqttControlPacketType::Disconnect => "DISCONNECT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::ip::v4::Ipv4;
    use crate::protocols::transport::Tcp;

    #[test]
    fn raw_publish_compiles_after_ipv4_tcp() {
        let packet =
            Ipv4::new() / Tcp::new() / Mqtt::raw(MqttControlPacketType::Publish, b"abc");
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;

        assert_eq!(bytes[mqtt_offset], 0x30);
        assert_eq!(bytes[mqtt_offset + 1], 0x03);
        assert_eq!(&bytes[mqtt_offset + 2..mqtt_offset + 5], b"abc");
    }

    #[test]
    fn raw_subscribe_uses_default_flags_and_multibyte_remaining_length() {
        let body = vec![0xaa; 128];
        let packet =
            Ipv4::new() / Tcp::new() / Mqtt::raw(MqttControlPacketType::Subscribe, body);
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;

        assert_eq!(bytes[mqtt_offset], 0x82);
        assert_eq!(&bytes[mqtt_offset + 1..mqtt_offset + 3], &[0x80, 0x01]);
    }

    #[test]
    fn explicit_flags_and_remaining_length_are_honored() {
        let packet = Ipv4::new()
            / Tcp::new()
            / Mqtt::raw(MqttControlPacketType::Publish, b"abc").flags(0x0d).remaining_length(0);
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;

        assert_eq!(bytes[mqtt_offset], 0x3d);
        assert_eq!(bytes[mqtt_offset + 1], 0x00);
        assert_eq!(&bytes[mqtt_offset + 2..mqtt_offset + 5], b"abc");
    }
}
