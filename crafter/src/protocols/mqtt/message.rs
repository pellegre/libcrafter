//! MQTT control packet layer.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::Result;

use super::constants::{
    MQTT_311_PROTOCOL_LEVEL, MQTT_311_PROTOCOL_NAME, MQTT_CONNECT_FLAG_CLEAN_SESSION,
    MQTT_CONNECT_FLAG_PASSWORD, MQTT_CONNECT_FLAG_USER_NAME, MQTT_CONNECT_FLAG_WILL,
    MQTT_CONNECT_FLAG_WILL_QOS_MASK, MQTT_CONNECT_FLAG_WILL_RETAIN,
};
use super::header::MqttControlPacketType;
use super::varint::encode_remaining_length;
use super::wire::{encode_binary, encode_string, encode_u16};

const DEFAULT_CONNECT_KEEP_ALIVE: u16 = 60;
const CONNECT_WILL_QOS_SHIFT: u8 = 3;

/// MQTT CONNECT variable header and mandatory payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttConnect {
    protocol_name: Field<String>,
    protocol_level: Field<u8>,
    connect_flags: Field<u8>,
    keep_alive: Field<u16>,
    client_id: Field<String>,
    will_topic: Field<String>,
    will_message: Field<Vec<u8>>,
    username: Field<String>,
    password: Field<Vec<u8>>,
}

impl MqttConnect {
    fn new() -> Self {
        Self {
            protocol_name: Field::defaulted(MQTT_311_PROTOCOL_NAME.to_string()),
            protocol_level: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            connect_flags: Field::defaulted(MQTT_CONNECT_FLAG_CLEAN_SESSION),
            keep_alive: Field::defaulted(DEFAULT_CONNECT_KEEP_ALIVE),
            client_id: Field::defaulted(String::new()),
            will_topic: Field::unset(),
            will_message: Field::unset(),
            username: Field::unset(),
            password: Field::unset(),
        }
    }

    fn protocol_name(&self) -> &str {
        self.protocol_name
            .value()
            .map(String::as_str)
            .unwrap_or(MQTT_311_PROTOCOL_NAME)
    }

    fn protocol_level(&self) -> u8 {
        self.protocol_level
            .value()
            .copied()
            .unwrap_or(MQTT_311_PROTOCOL_LEVEL)
    }

    fn connect_flags(&self) -> u8 {
        self.connect_flags
            .value()
            .copied()
            .unwrap_or(MQTT_CONNECT_FLAG_CLEAN_SESSION)
    }

    fn keep_alive(&self) -> u16 {
        self.keep_alive
            .value()
            .copied()
            .unwrap_or(DEFAULT_CONNECT_KEEP_ALIVE)
    }

    fn client_id(&self) -> &str {
        self.client_id.value().map(String::as_str).unwrap_or("")
    }

    fn will_topic(&self) -> &str {
        self.will_topic.value().map(String::as_str).unwrap_or("")
    }

    fn will_message(&self) -> &[u8] {
        self.will_message.value().map(Vec::as_slice).unwrap_or(&[])
    }

    fn username(&self) -> &str {
        self.username.value().map(String::as_str).unwrap_or("")
    }

    fn password(&self) -> &[u8] {
        self.password.value().map(Vec::as_slice).unwrap_or(&[])
    }

    fn set_connect_flag_default(&mut self, mask: u8, enabled: bool) {
        if self.connect_flags.is_user_set() {
            return;
        }

        let mut flags = self.connect_flags();
        if enabled {
            flags |= mask;
        } else {
            flags &= !mask;
        }
        self.connect_flags = Field::defaulted(flags);
    }

    fn set_will_qos_default(&mut self, qos: u8) {
        if self.connect_flags.is_user_set() {
            return;
        }

        let mut flags = self.connect_flags() & !MQTT_CONNECT_FLAG_WILL_QOS_MASK;
        flags |= (qos << CONNECT_WILL_QOS_SHIFT) & MQTT_CONNECT_FLAG_WILL_QOS_MASK;
        if qos != 0 {
            flags |= MQTT_CONNECT_FLAG_WILL;
        }
        self.connect_flags = Field::defaulted(flags);
    }

    fn encoded_len(&self) -> usize {
        let flags = self.connect_flags();
        let mut len = 2 + self.protocol_name().len() + 1 + 1 + 2 + 2 + self.client_id().len();

        if flags & MQTT_CONNECT_FLAG_WILL != 0 {
            len += 2 + self.will_topic().len();
            len += 2 + self.will_message().len();
        }
        if flags & MQTT_CONNECT_FLAG_USER_NAME != 0 {
            len += 2 + self.username().len();
        }
        if flags & MQTT_CONNECT_FLAG_PASSWORD != 0 {
            len += 2 + self.password().len();
        }

        len
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        let flags = self.connect_flags();

        encode_string(self.protocol_name(), out)?;
        out.push(self.protocol_level());
        out.push(flags);
        encode_u16(self.keep_alive(), out);
        encode_string(self.client_id(), out)?;

        // Optional payload emission follows the effective flags byte. A direct
        // connect_flags() override is not reconciled with populated fields so
        // malformed CONNECT packets can be constructed intentionally.
        if flags & MQTT_CONNECT_FLAG_WILL != 0 {
            encode_string(self.will_topic(), out)?;
            encode_binary(self.will_message(), out)?;
        }
        if flags & MQTT_CONNECT_FLAG_USER_NAME != 0 {
            encode_string(self.username(), out)?;
        }
        if flags & MQTT_CONNECT_FLAG_PASSWORD != 0 {
            encode_binary(self.password(), out)?;
        }

        Ok(())
    }
}

/// MQTT control packet body bytes after the fixed header.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MqttBody {
    Raw(Vec<u8>),
    Connect(MqttConnect),
}

impl MqttBody {
    fn encoded_len(&self) -> usize {
        match self {
            Self::Raw(body) => body.len(),
            Self::Connect(connect) => connect.encoded_len(),
        }
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Raw(body) => out.extend_from_slice(body),
            Self::Connect(connect) => connect.write_body(out)?,
        }
        Ok(())
    }

    fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::Raw(body) => body,
            Self::Connect(_) => &[],
        }
    }
}

/// MQTT control packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mqtt {
    packet_type: MqttControlPacketType,
    flags: Field<u8>,
    remaining_length: Field<u32>,
    body: MqttBody,
}

impl Mqtt {
    /// Build an MQTT control packet with an opaque body.
    pub fn raw(packet_type: MqttControlPacketType, body: impl Into<Vec<u8>>) -> Self {
        Self {
            packet_type,
            flags: Field::defaulted(packet_type.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Raw(body.into()),
        }
    }

    /// Build an MQTT CONNECT packet with MQTT 3.1.1 defaults.
    pub fn connect() -> Self {
        Self {
            packet_type: MqttControlPacketType::Connect,
            flags: Field::defaulted(MqttControlPacketType::Connect.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Connect(MqttConnect::new()),
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

    /// Set the CONNECT protocol name.
    pub fn protocol_name(mut self, protocol_name: impl Into<String>) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.protocol_name.set_user(protocol_name.into());
        }
        self
    }

    /// Set the CONNECT protocol level.
    pub fn protocol_level(mut self, protocol_level: u8) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.protocol_level.set_user(protocol_level);
        }
        self
    }

    /// Force the CONNECT flags byte.
    pub fn connect_flags(mut self, connect_flags: u8) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.connect_flags.set_user(connect_flags);
        }
        self
    }

    /// Set the CONNECT client identifier.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.client_id.set_user(client_id.into());
        }
        self
    }

    /// Set the CONNECT keep-alive interval, in seconds.
    pub fn keep_alive(mut self, keep_alive: u16) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.keep_alive.set_user(keep_alive);
        }
        self
    }

    /// Set the CONNECT Will Topic and Will Message fields.
    pub fn will(mut self, topic: impl Into<String>, message: impl Into<Vec<u8>>) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.will_topic.set_user(topic.into());
            connect.will_message.set_user(message.into());
            connect.set_connect_flag_default(MQTT_CONNECT_FLAG_WILL, true);
        }
        self
    }

    /// Set the CONNECT Will QoS bits.
    pub fn will_qos(mut self, qos: u8) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.set_will_qos_default(qos);
        }
        self
    }

    /// Set or clear the CONNECT Will Retain flag.
    pub fn will_retain(mut self, will_retain: bool) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.set_connect_flag_default(MQTT_CONNECT_FLAG_WILL_RETAIN, will_retain);
            if will_retain && !connect.connect_flags.is_user_set() {
                connect.set_connect_flag_default(MQTT_CONNECT_FLAG_WILL, true);
            }
        }
        self
    }

    /// Set the CONNECT User Name field.
    pub fn username(mut self, username: impl Into<String>) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.username.set_user(username.into());
            connect.set_connect_flag_default(MQTT_CONNECT_FLAG_USER_NAME, true);
        }
        self
    }

    /// Set the CONNECT Password field.
    pub fn password(mut self, password: impl Into<Vec<u8>>) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.password.set_user(password.into());
            connect.set_connect_flag_default(MQTT_CONNECT_FLAG_PASSWORD, true);
            if !connect.connect_flags.is_user_set() {
                connect.set_connect_flag_default(MQTT_CONNECT_FLAG_USER_NAME, true);
            }
        }
        self
    }

    /// Set or clear the CONNECT Clean Session flag.
    pub fn clean_session(mut self, clean_session: bool) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.set_connect_flag_default(MQTT_CONNECT_FLAG_CLEAN_SESSION, clean_session);
        }
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
            .unwrap_or_else(|| u32::try_from(self.body.encoded_len()).unwrap_or(u32::MAX))
    }

    /// Explicit Remaining Length value, if one was set.
    pub fn explicit_remaining_length(&self) -> Option<u32> {
        self.remaining_length.value().copied()
    }

    /// Opaque bytes after the fixed header.
    pub fn body(&self) -> &[u8] {
        self.body.raw_bytes()
    }

    fn first_byte(&self) -> u8 {
        self.packet_type.high_nibble() | self.flags_value()
    }

    fn encoded_body(&self) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(self.body.encoded_len());
        self.body.write_body(&mut body)?;
        Ok(body)
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
            self.body.encoded_len()
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
            ("body_length", self.body.encoded_len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        1 + remaining_length_encoded_len(self.remaining_length_value()) + self.body.encoded_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let body = self.encoded_body()?;
        let remaining_length = self
            .remaining_length
            .value()
            .copied()
            .unwrap_or_else(|| u32::try_from(body.len()).unwrap_or(u32::MAX));

        out.push(self.first_byte());
        encode_remaining_length(remaining_length, out)?;
        out.extend_from_slice(&body);
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
    use crate::packet::Packet;
    use crate::protocols::ip::v4::Ipv4;
    use crate::protocols::transport::Tcp;

    fn mqtt_bytes(message: Mqtt) -> Vec<u8> {
        Packet::from_layer(message).compile().unwrap().into_bytes()
    }

    #[test]
    fn raw_publish_compiles_after_ipv4_tcp() {
        let packet = Ipv4::new() / Tcp::new() / Mqtt::raw(MqttControlPacketType::Publish, b"abc");
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;

        assert_eq!(bytes[mqtt_offset], 0x30);
        assert_eq!(bytes[mqtt_offset + 1], 0x03);
        assert_eq!(&bytes[mqtt_offset + 2..mqtt_offset + 5], b"abc");
    }

    #[test]
    fn raw_subscribe_uses_default_flags_and_multibyte_remaining_length() {
        let body = vec![0xaa; 128];
        let packet = Ipv4::new() / Tcp::new() / Mqtt::raw(MqttControlPacketType::Subscribe, body);
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;

        assert_eq!(bytes[mqtt_offset], 0x82);
        assert_eq!(&bytes[mqtt_offset + 1..mqtt_offset + 3], &[0x80, 0x01]);
    }

    #[test]
    fn explicit_flags_and_remaining_length_are_honored() {
        let packet = Ipv4::new()
            / Tcp::new()
            / Mqtt::raw(MqttControlPacketType::Publish, b"abc")
                .flags(0x0d)
                .remaining_length(0);
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;

        assert_eq!(bytes[mqtt_offset], 0x3d);
        assert_eq!(bytes[mqtt_offset + 1], 0x00);
        assert_eq!(&bytes[mqtt_offset + 2..mqtt_offset + 5], b"abc");
    }

    #[test]
    fn connect_compiles_mandatory_header_and_client_id() {
        let client_id = "crafter-client";
        let keep_alive = 30u16;
        let packet = Ipv4::new()
            / Tcp::new()
            / Mqtt::connect()
                .client_id(client_id)
                .keep_alive(keep_alive)
                .clean_session(true);
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;
        let body_offset = mqtt_offset + 2;

        assert_eq!(bytes[mqtt_offset], 0x10);
        assert_eq!(bytes[mqtt_offset + 1], (10 + 2 + client_id.len()) as u8);
        assert_eq!(&bytes[body_offset..body_offset + 2], &[0x00, 0x04]);
        assert_eq!(
            &bytes[body_offset + 2..body_offset + 6],
            MQTT_311_PROTOCOL_NAME.as_bytes()
        );
        assert_eq!(bytes[body_offset + 6], MQTT_311_PROTOCOL_LEVEL);
        assert_eq!(bytes[body_offset + 7], MQTT_CONNECT_FLAG_CLEAN_SESSION);
        assert_eq!(
            &bytes[body_offset + 8..body_offset + 10],
            &keep_alive.to_be_bytes()
        );
        assert_eq!(
            &bytes[body_offset + 10..body_offset + 12],
            &(client_id.len() as u16).to_be_bytes()
        );
        assert_eq!(
            &bytes[body_offset + 12..body_offset + 12 + client_id.len()],
            client_id.as_bytes()
        );
    }

    #[test]
    fn connect_remaining_length_and_connect_flags_overrides_are_honored() {
        let packet = Ipv4::new()
            / Tcp::new()
            / Mqtt::connect()
                .client_id("x")
                .connect_flags(0xff)
                .remaining_length(0);
        let bytes = packet.compile().unwrap();
        let mqtt_offset = 20 + 20;
        let body_offset = mqtt_offset + 2;

        assert_eq!(bytes[mqtt_offset], 0x10);
        assert_eq!(bytes[mqtt_offset + 1], 0x00);
        assert_eq!(bytes[body_offset + 7], 0xff);
        assert_eq!(&bytes[body_offset + 10..body_offset + 12], &[0x00, 0x01]);
        assert_eq!(bytes[body_offset + 12], b'x');
    }

    #[test]
    fn connect_will_username_and_password_match_manifest_order() {
        let bytes = mqtt_bytes(
            Mqtt::connect()
                .client_id("cid")
                .keep_alive(30)
                .will("status", vec![0xde, 0xad])
                .will_qos(1)
                .will_retain(true)
                .username("user")
                .password(vec![0xbe, 0xef]),
        );

        let expected = vec![
            0x10, 0x25, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0xee, 0x00, 0x1e, 0x00,
            0x03, b'c', b'i', b'd', 0x00, 0x06, b's', b't', b'a', b't', b'u', b's',
            0x00, 0x02, 0xde, 0xad, 0x00, 0x04, b'u', b's', b'e', b'r', 0x00, 0x02,
            0xbe, 0xef,
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn connect_username_without_password_omits_password_field() {
        let bytes = mqtt_bytes(Mqtt::connect().client_id("cid").username("user"));

        let expected = vec![
            0x10, 0x15, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x82, 0x00, 0x3c, 0x00,
            0x03, b'c', b'i', b'd', 0x00, 0x04, b'u', b's', b'e', b'r',
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn explicit_connect_flags_can_disagree_with_optional_fields() {
        let bytes = mqtt_bytes(
            Mqtt::connect()
                .connect_flags(MQTT_CONNECT_FLAG_CLEAN_SESSION)
                .client_id("cid")
                .will("status", vec![0xde, 0xad])
                .username("user")
                .password(vec![0xbe, 0xef]),
        );

        let expected = vec![
            0x10, 0x0f, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04,
            MQTT_CONNECT_FLAG_CLEAN_SESSION, 0x00, 0x3c, 0x00, 0x03, b'c', b'i', b'd',
        ];

        assert_eq!(bytes, expected);
    }
}
