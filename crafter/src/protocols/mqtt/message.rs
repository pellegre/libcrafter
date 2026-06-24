//! MQTT control packet layer.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{hex_bytes, impl_layer_div, impl_layer_object};
use crate::Result;

use super::constants::{
    MQTT_311_PROTOCOL_LEVEL, MQTT_311_PROTOCOL_NAME, MQTT_5_PROTOCOL_LEVEL, MQTT_CONNACK_ACCEPTED,
    MQTT_CONNECT_FLAG_CLEAN_SESSION, MQTT_CONNECT_FLAG_PASSWORD, MQTT_CONNECT_FLAG_USER_NAME,
    MQTT_CONNECT_FLAG_WILL, MQTT_CONNECT_FLAG_WILL_QOS_MASK, MQTT_CONNECT_FLAG_WILL_RETAIN,
    MQTT_PUBLISH_FLAG_DUP, MQTT_PUBLISH_FLAG_QOS_MASK, MQTT_PUBLISH_FLAG_RETAIN,
    MQTT_REASON_SUCCESS,
};
use super::header::MqttControlPacketType;
use super::property::{MqttProperties, MqttProperty};
use super::varint::encode_remaining_length;
use super::wire::{encode_binary, encode_string, encode_u16};

const DEFAULT_CONNECT_KEEP_ALIVE: u16 = 60;
const CONNECT_WILL_QOS_SHIFT: u8 = 3;
const CONNACK_FLAG_SESSION_PRESENT: u8 = 0x01;
const PUBLISH_QOS_SHIFT: u8 = 1;

/// MQTT CONNECT variable header and mandatory payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttConnect {
    protocol_name: Field<String>,
    protocol_level: Field<u8>,
    connect_flags: Field<u8>,
    keep_alive: Field<u16>,
    connect_properties: MqttProperties,
    client_id: Field<String>,
    will_properties: MqttProperties,
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
            connect_properties: MqttProperties::new(),
            client_id: Field::defaulted(String::new()),
            will_properties: MqttProperties::new(),
            will_topic: Field::unset(),
            will_message: Field::unset(),
            username: Field::unset(),
            password: Field::unset(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn from_decoded_parts(
        protocol_name: String,
        protocol_level: u8,
        connect_flags: u8,
        keep_alive: u16,
        connect_properties: MqttProperties,
        client_id: String,
        will_properties: MqttProperties,
        will_topic: Option<String>,
        will_message: Option<Vec<u8>>,
        username: Option<String>,
        password: Option<Vec<u8>>,
    ) -> Self {
        Self {
            protocol_name: Field::user(protocol_name),
            protocol_level: Field::user(protocol_level),
            connect_flags: Field::user(connect_flags),
            keep_alive: Field::user(keep_alive),
            connect_properties,
            client_id: Field::user(client_id),
            will_properties,
            will_topic: will_topic.map_or_else(Field::unset, Field::user),
            will_message: will_message.map_or_else(Field::unset, Field::user),
            username: username.map_or_else(Field::unset, Field::user),
            password: password.map_or_else(Field::unset, Field::user),
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

    fn is_v5(&self) -> bool {
        self.protocol_level() == MQTT_5_PROTOCOL_LEVEL
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

    fn connect_properties(&self) -> &MqttProperties {
        &self.connect_properties
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

    fn will_properties(&self) -> &MqttProperties {
        &self.will_properties
    }

    fn username(&self) -> &str {
        self.username.value().map(String::as_str).unwrap_or("")
    }

    fn password(&self) -> &[u8] {
        self.password.value().map(Vec::as_slice).unwrap_or(&[])
    }

    fn will_topic_value(&self) -> Option<&str> {
        self.will_topic.value().map(String::as_str)
    }

    fn will_message_value(&self) -> Option<&[u8]> {
        self.will_message.value().map(Vec::as_slice)
    }

    fn username_value(&self) -> Option<&str> {
        self.username.value().map(String::as_str)
    }

    fn password_value(&self) -> Option<&[u8]> {
        self.password.value().map(Vec::as_slice)
    }

    fn connect_properties_value(&self) -> Option<&MqttProperties> {
        self.is_v5().then_some(&self.connect_properties)
    }

    fn will_properties_value(&self) -> Option<&MqttProperties> {
        (self.is_v5() && self.connect_flags() & MQTT_CONNECT_FLAG_WILL != 0)
            .then_some(&self.will_properties)
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

        if self.is_v5() {
            len += encoded_properties_len(self.connect_properties());
        }
        if flags & MQTT_CONNECT_FLAG_WILL != 0 {
            if self.is_v5() {
                len += encoded_properties_len(self.will_properties());
            }
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
        if self.is_v5() {
            self.connect_properties.write(out)?;
        }
        encode_string(self.client_id(), out)?;

        // Optional payload emission follows the effective flags byte. A direct
        // connect_flags() override is not reconciled with populated fields so
        // malformed CONNECT packets can be constructed intentionally.
        if flags & MQTT_CONNECT_FLAG_WILL != 0 {
            if self.is_v5() {
                self.will_properties.write(out)?;
            }
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

/// MQTT CONNACK variable header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttConnack {
    ack_flags: Field<u8>,
    return_code: Field<u8>,
    properties: MqttProperties,
}

impl MqttConnack {
    fn new() -> Self {
        Self {
            ack_flags: Field::defaulted(0),
            return_code: Field::defaulted(MQTT_CONNACK_ACCEPTED),
            properties: MqttProperties::new(),
        }
    }

    fn from_decoded_parts(ack_flags: u8, return_code: u8, properties: MqttProperties) -> Self {
        Self {
            ack_flags: Field::user(ack_flags),
            return_code: Field::user(return_code),
            properties,
        }
    }

    fn ack_flags(&self) -> u8 {
        self.ack_flags.value().copied().unwrap_or(0)
    }

    fn session_present(&self) -> bool {
        self.ack_flags() & CONNACK_FLAG_SESSION_PRESENT != 0
    }

    fn return_code(&self) -> u8 {
        self.return_code
            .value()
            .copied()
            .unwrap_or(MQTT_CONNACK_ACCEPTED)
    }

    fn properties(&self) -> &MqttProperties {
        &self.properties
    }

    fn set_session_present(&mut self, session_present: bool) {
        let mut flags = self.ack_flags();
        if session_present {
            flags |= CONNACK_FLAG_SESSION_PRESENT;
        } else {
            flags &= !CONNACK_FLAG_SESSION_PRESENT;
        }
        self.ack_flags.set_user(flags);
    }

    fn encoded_len(&self, version: u8) -> usize {
        let mut len = 2;
        if version == MQTT_5_PROTOCOL_LEVEL {
            len += encoded_properties_len(self.properties());
        }
        len
    }

    fn write_body(&self, out: &mut Vec<u8>, version: u8) -> Result<()> {
        out.push(self.ack_flags());
        out.push(self.return_code());
        if version == MQTT_5_PROTOCOL_LEVEL {
            self.properties.write(out)?;
        }
        Ok(())
    }
}

/// MQTT PUBLISH variable header and payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttPublish {
    topic: Field<String>,
    packet_id: Field<u16>,
    properties: MqttProperties,
    payload: Field<Vec<u8>>,
}

impl MqttPublish {
    fn new() -> Self {
        Self {
            topic: Field::defaulted(String::new()),
            packet_id: Field::unset(),
            properties: MqttProperties::new(),
            payload: Field::defaulted(Vec::new()),
        }
    }

    fn from_decoded_parts(
        topic: String,
        packet_id: Option<u16>,
        properties: MqttProperties,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            topic: Field::user(topic),
            packet_id: packet_id.map_or_else(Field::unset, Field::user),
            properties,
            payload: Field::user(payload),
        }
    }

    fn topic(&self) -> &str {
        self.topic.value().map(String::as_str).unwrap_or("")
    }

    fn packet_id_value(&self) -> Option<u16> {
        self.packet_id.value().copied()
    }

    fn packet_id(&self) -> u16 {
        self.packet_id.value().copied().unwrap_or(0)
    }

    fn payload(&self) -> &[u8] {
        self.payload.value().map(Vec::as_slice).unwrap_or(&[])
    }

    fn properties(&self) -> &MqttProperties {
        &self.properties
    }

    fn encoded_len(&self, flags: u8, version: u8) -> usize {
        let mut len = 2 + self.topic().len() + self.payload().len();
        if publish_qos(flags) != 0 {
            len += 2;
        }
        if version == MQTT_5_PROTOCOL_LEVEL {
            len += encoded_properties_len(self.properties());
        }
        len
    }

    fn write_body(&self, out: &mut Vec<u8>, flags: u8, version: u8) -> Result<()> {
        encode_string(self.topic(), out)?;
        // Packet Identifier presence follows the effective QoS bits. Values
        // such as 0 are still emitted when set or defaulted for malformed
        // packet construction; validation belongs above the packet primitive.
        if publish_qos(flags) != 0 {
            encode_u16(self.packet_id(), out);
        }
        if version == MQTT_5_PROTOCOL_LEVEL {
            self.properties.write(out)?;
        }
        out.extend_from_slice(self.payload());
        Ok(())
    }
}

/// MQTT variable header containing only a Packet Identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttPacketIdentifier {
    packet_id: Field<u16>,
    reason_code: Field<u8>,
    properties: MqttProperties,
}

impl MqttPacketIdentifier {
    fn new() -> Self {
        Self {
            packet_id: Field::defaulted(0),
            reason_code: Field::unset(),
            properties: MqttProperties::new(),
        }
    }

    fn from_decoded_parts(
        packet_id: u16,
        reason_code: Option<u8>,
        properties: MqttProperties,
    ) -> Self {
        Self {
            packet_id: Field::user(packet_id),
            reason_code: reason_code.map_or_else(Field::unset, Field::user),
            properties,
        }
    }

    fn packet_id(&self) -> u16 {
        self.packet_id.value().copied().unwrap_or(0)
    }

    fn reason_code(&self) -> u8 {
        self.reason_code
            .value()
            .copied()
            .unwrap_or(MQTT_REASON_SUCCESS)
    }

    fn reason_code_value(&self, version: u8) -> Option<u8> {
        if version == MQTT_5_PROTOCOL_LEVEL {
            Some(self.reason_code())
        } else {
            self.reason_code.value().copied()
        }
    }

    fn properties(&self) -> &MqttProperties {
        &self.properties
    }

    fn has_v5_details(&self) -> bool {
        self.reason_code.value().is_some()
            || !self.properties.property_values().is_empty()
            || self.properties.property_length_override().is_some()
    }

    fn encoded_len(&self, version: u8) -> usize {
        let mut len = 2;
        if version == MQTT_5_PROTOCOL_LEVEL && self.has_v5_details() {
            len += 1 + encoded_properties_len(self.properties());
        }
        len
    }

    fn write_body(&self, out: &mut Vec<u8>, version: u8) -> Result<()> {
        encode_u16(self.packet_id(), out);
        if version == MQTT_5_PROTOCOL_LEVEL && self.has_v5_details() {
            out.push(self.reason_code());
            self.properties.write(out)?;
        }
        Ok(())
    }
}

/// MQTT SUBACK variable header and payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttSuback {
    packet_id: Field<u16>,
    return_codes: Vec<u8>,
}

impl MqttSuback {
    fn new() -> Self {
        Self {
            packet_id: Field::defaulted(0),
            return_codes: Vec::new(),
        }
    }

    fn from_decoded_parts(packet_id: u16, return_codes: Vec<u8>) -> Self {
        Self {
            packet_id: Field::user(packet_id),
            return_codes,
        }
    }

    fn packet_id(&self) -> u16 {
        self.packet_id.value().copied().unwrap_or(0)
    }

    fn return_codes(&self) -> &[u8] {
        &self.return_codes
    }

    fn push_return_code(&mut self, return_code: u8) {
        self.return_codes.push(return_code);
    }

    fn encoded_len(&self) -> usize {
        2 + self.return_codes.len()
    }

    fn write_body(&self, out: &mut Vec<u8>) {
        encode_u16(self.packet_id(), out);
        out.extend_from_slice(&self.return_codes);
    }
}

/// MQTT UNSUBSCRIBE variable header and payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttUnsubscribe {
    packet_id: Field<u16>,
    topics: Vec<String>,
}

impl MqttUnsubscribe {
    fn new() -> Self {
        Self {
            packet_id: Field::defaulted(0),
            topics: Vec::new(),
        }
    }

    fn from_decoded_parts(packet_id: u16, topics: Vec<String>) -> Self {
        Self {
            packet_id: Field::user(packet_id),
            topics,
        }
    }

    fn packet_id(&self) -> u16 {
        self.packet_id.value().copied().unwrap_or(0)
    }

    fn topics(&self) -> &[String] {
        &self.topics
    }

    fn push_topic(&mut self, filter: impl Into<String>) {
        self.topics.push(filter.into());
    }

    fn encoded_len(&self) -> usize {
        2 + self
            .topics
            .iter()
            .map(|filter| 2 + filter.len())
            .sum::<usize>()
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_u16(self.packet_id(), out);
        for filter in &self.topics {
            encode_string(filter, out)?;
        }
        Ok(())
    }
}

/// MQTT SUBSCRIBE variable header and payload fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttSubscribe {
    packet_id: Field<u16>,
    topics: Vec<(String, u8)>,
}

impl MqttSubscribe {
    fn new() -> Self {
        Self {
            packet_id: Field::defaulted(0),
            topics: Vec::new(),
        }
    }

    fn from_decoded_parts(packet_id: u16, topics: Vec<(String, u8)>) -> Self {
        Self {
            packet_id: Field::user(packet_id),
            topics,
        }
    }

    fn packet_id(&self) -> u16 {
        self.packet_id.value().copied().unwrap_or(0)
    }

    fn topics(&self) -> &[(String, u8)] {
        &self.topics
    }

    fn push_topic(&mut self, filter: impl Into<String>, qos: u8) {
        self.topics.push((filter.into(), qos));
    }

    fn encoded_len(&self) -> usize {
        2 + self
            .topics
            .iter()
            .map(|(filter, _qos)| 2 + filter.len() + 1)
            .sum::<usize>()
    }

    fn write_body(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_u16(self.packet_id(), out);
        for (filter, qos) in &self.topics {
            encode_string(filter, out)?;
            out.push(*qos);
        }
        Ok(())
    }
}

/// MQTT control packet body bytes after the fixed header.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MqttBody {
    Raw(Vec<u8>),
    Empty,
    Connect(MqttConnect),
    Connack(MqttConnack),
    Publish(MqttPublish),
    PacketIdentifier(MqttPacketIdentifier),
    Subscribe(MqttSubscribe),
    Suback(MqttSuback),
    Unsubscribe(MqttUnsubscribe),
}

impl MqttBody {
    fn encoded_len(&self, flags: u8, version: u8) -> usize {
        match self {
            Self::Raw(body) => body.len(),
            Self::Empty => 0,
            Self::Connect(connect) => connect.encoded_len(),
            Self::Connack(connack) => connack.encoded_len(version),
            Self::Publish(publish) => publish.encoded_len(flags, version),
            Self::PacketIdentifier(packet_identifier) => packet_identifier.encoded_len(version),
            Self::Subscribe(subscribe) => subscribe.encoded_len(),
            Self::Suback(suback) => suback.encoded_len(),
            Self::Unsubscribe(unsubscribe) => unsubscribe.encoded_len(),
        }
    }

    fn write_body(&self, out: &mut Vec<u8>, flags: u8, version: u8) -> Result<()> {
        match self {
            Self::Raw(body) => out.extend_from_slice(body),
            Self::Empty => {}
            Self::Connect(connect) => connect.write_body(out)?,
            Self::Connack(connack) => connack.write_body(out, version)?,
            Self::Publish(publish) => publish.write_body(out, flags, version)?,
            Self::PacketIdentifier(packet_identifier) => {
                packet_identifier.write_body(out, version)?
            }
            Self::Subscribe(subscribe) => subscribe.write_body(out)?,
            Self::Suback(suback) => suback.write_body(out),
            Self::Unsubscribe(unsubscribe) => unsubscribe.write_body(out)?,
        }
        Ok(())
    }

    fn raw_bytes(&self) -> &[u8] {
        match self {
            Self::Raw(body) => body,
            Self::Empty
            | Self::Connect(_)
            | Self::Connack(_)
            | Self::Publish(_)
            | Self::PacketIdentifier(_)
            | Self::Subscribe(_)
            | Self::Suback(_)
            | Self::Unsubscribe(_) => &[],
        }
    }
}

/// MQTT 3.1.1 control packet layer.
///
/// `Mqtt` represents one MQTT control packet, starting at the fixed header. It
/// can be used as a standalone application-layer packet with
/// `Packet::from_layer(Mqtt::...)` or stacked under TCP in a larger
/// [`crate::Packet`].
/// Constructors build typed MQTT 3.1.1 messages for the baseline cleartext
/// control packets, while [`Mqtt::raw`] preserves an opaque body for control
/// packet types whose body should not be interpreted.
///
/// `compile()` emits the fixed header, auto-fills Remaining Length from the
/// encoded body unless [`Mqtt::remaining_length`] was used, and preserves any
/// caller-supplied flag nibble from [`Mqtt::flags`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mqtt {
    packet_type: MqttControlPacketType,
    version: Field<u8>,
    flags: Field<u8>,
    remaining_length: Field<u32>,
    body: MqttBody,
}

impl Mqtt {
    /// Build an MQTT control packet with an opaque body.
    pub fn raw(packet_type: MqttControlPacketType, body: impl Into<Vec<u8>>) -> Self {
        Self {
            packet_type,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(packet_type.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Raw(body.into()),
        }
    }

    /// Build an MQTT CONNECT packet with MQTT 3.1.1 defaults.
    pub fn connect() -> Self {
        Self {
            packet_type: MqttControlPacketType::Connect,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Connect.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Connect(MqttConnect::new()),
        }
    }

    /// Build an MQTT CONNACK packet with MQTT 3.1.1 defaults.
    pub fn connack() -> Self {
        Self {
            packet_type: MqttControlPacketType::Connack,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Connack.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Connack(MqttConnack::new()),
        }
    }

    /// Build an MQTT PUBLISH packet with QoS 0 defaults.
    pub fn publish() -> Self {
        Self {
            packet_type: MqttControlPacketType::Publish,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Publish.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Publish(MqttPublish::new()),
        }
    }

    /// Build an MQTT PUBACK packet.
    pub fn puback() -> Self {
        Self {
            packet_type: MqttControlPacketType::Puback,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Puback.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::PacketIdentifier(MqttPacketIdentifier::new()),
        }
    }

    /// Build an MQTT PUBREC packet.
    pub fn pubrec() -> Self {
        Self {
            packet_type: MqttControlPacketType::Pubrec,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Pubrec.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::PacketIdentifier(MqttPacketIdentifier::new()),
        }
    }

    /// Build an MQTT PUBREL packet.
    pub fn pubrel() -> Self {
        Self {
            packet_type: MqttControlPacketType::Pubrel,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Pubrel.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::PacketIdentifier(MqttPacketIdentifier::new()),
        }
    }

    /// Build an MQTT PUBCOMP packet.
    pub fn pubcomp() -> Self {
        Self {
            packet_type: MqttControlPacketType::Pubcomp,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Pubcomp.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::PacketIdentifier(MqttPacketIdentifier::new()),
        }
    }

    /// Build an MQTT UNSUBACK packet.
    pub fn unsuback() -> Self {
        Self {
            packet_type: MqttControlPacketType::Unsuback,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Unsuback.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::PacketIdentifier(MqttPacketIdentifier::new()),
        }
    }

    /// Build an MQTT PINGREQ packet.
    pub fn pingreq() -> Self {
        Self {
            packet_type: MqttControlPacketType::Pingreq,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Pingreq.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Empty,
        }
    }

    /// Build an MQTT PINGRESP packet.
    pub fn pingresp() -> Self {
        Self {
            packet_type: MqttControlPacketType::Pingresp,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Pingresp.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Empty,
        }
    }

    /// Build an MQTT 3.1.1 DISCONNECT packet.
    pub fn disconnect() -> Self {
        Self {
            packet_type: MqttControlPacketType::Disconnect,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Disconnect.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Empty,
        }
    }

    /// Build an MQTT SUBSCRIBE packet.
    pub fn subscribe() -> Self {
        Self {
            packet_type: MqttControlPacketType::Subscribe,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Subscribe.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Subscribe(MqttSubscribe::new()),
        }
    }

    /// Build an MQTT SUBACK packet.
    pub fn suback() -> Self {
        Self {
            packet_type: MqttControlPacketType::Suback,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Suback.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Suback(MqttSuback::new()),
        }
    }

    /// Build an MQTT UNSUBSCRIBE packet.
    pub fn unsubscribe() -> Self {
        Self {
            packet_type: MqttControlPacketType::Unsubscribe,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::defaulted(MqttControlPacketType::Unsubscribe.default_flags()),
            remaining_length: Field::unset(),
            body: MqttBody::Unsubscribe(MqttUnsubscribe::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn connect_from_decoded_parts(
        fixed_header_flags: u8,
        remaining_length: u32,
        protocol_name: String,
        protocol_level: u8,
        connect_flags: u8,
        keep_alive: u16,
        connect_properties: MqttProperties,
        client_id: String,
        will_properties: MqttProperties,
        will_topic: Option<String>,
        will_message: Option<Vec<u8>>,
        username: Option<String>,
        password: Option<Vec<u8>>,
    ) -> Self {
        Self {
            packet_type: MqttControlPacketType::Connect,
            version: Field::user(protocol_level),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::Connect(MqttConnect::from_decoded_parts(
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
            )),
        }
    }

    pub(crate) fn connack_from_decoded_parts(
        fixed_header_flags: u8,
        remaining_length: u32,
        version: u8,
        ack_flags: u8,
        reason_code: u8,
        properties: MqttProperties,
    ) -> Self {
        Self {
            packet_type: MqttControlPacketType::Connack,
            version: Field::user(version),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::Connack(MqttConnack::from_decoded_parts(
                ack_flags,
                reason_code,
                properties,
            )),
        }
    }

    pub(crate) fn publish_from_decoded_parts(
        fixed_header_flags: u8,
        remaining_length: u32,
        version: u8,
        topic: String,
        packet_id: Option<u16>,
        properties: MqttProperties,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            packet_type: MqttControlPacketType::Publish,
            version: Field::user(version),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::Publish(MqttPublish::from_decoded_parts(
                topic, packet_id, properties, payload,
            )),
        }
    }

    pub(crate) fn packet_identifier_from_decoded_parts(
        packet_type: MqttControlPacketType,
        fixed_header_flags: u8,
        remaining_length: u32,
        version: u8,
        packet_id: u16,
        reason_code: Option<u8>,
        properties: MqttProperties,
    ) -> Self {
        Self {
            packet_type,
            version: Field::user(version),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::PacketIdentifier(MqttPacketIdentifier::from_decoded_parts(
                packet_id,
                reason_code,
                properties,
            )),
        }
    }

    pub(crate) fn subscribe_from_decoded_parts(
        fixed_header_flags: u8,
        remaining_length: u32,
        packet_id: u16,
        topics: Vec<(String, u8)>,
    ) -> Self {
        Self {
            packet_type: MqttControlPacketType::Subscribe,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::Subscribe(MqttSubscribe::from_decoded_parts(packet_id, topics)),
        }
    }

    pub(crate) fn suback_from_decoded_parts(
        fixed_header_flags: u8,
        remaining_length: u32,
        packet_id: u16,
        return_codes: Vec<u8>,
    ) -> Self {
        Self {
            packet_type: MqttControlPacketType::Suback,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::Suback(MqttSuback::from_decoded_parts(packet_id, return_codes)),
        }
    }

    pub(crate) fn unsubscribe_from_decoded_parts(
        fixed_header_flags: u8,
        remaining_length: u32,
        packet_id: u16,
        topics: Vec<String>,
    ) -> Self {
        Self {
            packet_type: MqttControlPacketType::Unsubscribe,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::Unsubscribe(MqttUnsubscribe::from_decoded_parts(packet_id, topics)),
        }
    }

    pub(crate) fn empty_from_decoded_parts(
        packet_type: MqttControlPacketType,
        fixed_header_flags: u8,
        remaining_length: u32,
    ) -> Self {
        Self {
            packet_type,
            version: Field::defaulted(MQTT_311_PROTOCOL_LEVEL),
            flags: Field::user(fixed_header_flags),
            remaining_length: Field::user(remaining_length),
            body: MqttBody::Empty,
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

    /// Set the MQTT protocol version selector for this layer.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.protocol_level.set_user(version);
        }
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
            self.version.set_user(protocol_level);
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

    /// Replace the MQTT 5.0 CONNECT properties block.
    pub fn connect_properties(mut self, properties: MqttProperties) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.connect_properties = properties;
        }
        self
    }

    /// Add one MQTT 5.0 CONNECT property.
    pub fn connect_property(mut self, property: MqttProperty) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.connect_properties.push(property);
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

    /// Replace the MQTT 5.0 Will Properties block.
    pub fn will_properties(mut self, properties: MqttProperties) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.will_properties = properties;
        }
        self
    }

    /// Add one MQTT 5.0 Will Property.
    pub fn will_property(mut self, property: MqttProperty) -> Self {
        if let MqttBody::Connect(connect) = &mut self.body {
            connect.will_properties.push(property);
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

    /// Set the PUBLISH topic name or add one UNSUBSCRIBE topic filter.
    pub fn topic(mut self, topic: impl Into<String>) -> Self {
        match &mut self.body {
            MqttBody::Publish(publish) => publish.topic.set_user(topic.into()),
            MqttBody::Unsubscribe(unsubscribe) => unsubscribe.push_topic(topic),
            _ => {}
        }
        self
    }

    /// Set the PUBLISH QoS bits.
    pub fn qos(mut self, qos: u8) -> Self {
        if matches!(&self.body, MqttBody::Publish(_)) {
            let mut flags = self.flags_value() & !MQTT_PUBLISH_FLAG_QOS_MASK;
            flags |= (qos << PUBLISH_QOS_SHIFT) & MQTT_PUBLISH_FLAG_QOS_MASK;
            self.flags.set_user(flags);
        }
        self
    }

    /// Set or clear the PUBLISH DUP bit.
    pub fn dup(mut self, dup: bool) -> Self {
        if matches!(&self.body, MqttBody::Publish(_)) {
            self.set_publish_flag(MQTT_PUBLISH_FLAG_DUP, dup);
        }
        self
    }

    /// Set or clear the PUBLISH RETAIN bit.
    pub fn retain(mut self, retain: bool) -> Self {
        if matches!(&self.body, MqttBody::Publish(_)) {
            self.set_publish_flag(MQTT_PUBLISH_FLAG_RETAIN, retain);
        }
        self
    }

    /// Replace the MQTT 5.0 PUBLISH properties block.
    pub fn publish_properties(mut self, properties: MqttProperties) -> Self {
        if let MqttBody::Publish(publish) = &mut self.body {
            publish.properties = properties;
        }
        self
    }

    /// Add one MQTT 5.0 PUBLISH property.
    pub fn publish_property(mut self, property: MqttProperty) -> Self {
        if let MqttBody::Publish(publish) = &mut self.body {
            publish.properties.push(property);
        }
        self
    }

    /// Add the MQTT 5.0 PUBLISH Content Type property.
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        if let MqttBody::Publish(publish) = &mut self.body {
            publish
                .properties
                .push(MqttProperty::ContentType(content_type.into()));
        }
        self
    }

    /// Add the MQTT 5.0 PUBLISH Topic Alias property.
    pub fn topic_alias(mut self, topic_alias: u16) -> Self {
        if let MqttBody::Publish(publish) = &mut self.body {
            publish
                .properties
                .push(MqttProperty::TopicAlias(topic_alias));
        }
        self
    }

    /// Add one MQTT 5.0 PUBLISH User Property.
    pub fn user_property(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        if let MqttBody::Publish(publish) = &mut self.body {
            publish
                .properties
                .push(MqttProperty::user_property(name, value));
        }
        self
    }

    /// Set the Packet Identifier for packet types that carry one.
    pub fn packet_id(mut self, packet_id: u16) -> Self {
        match &mut self.body {
            MqttBody::Publish(publish) => publish.packet_id.set_user(packet_id),
            MqttBody::PacketIdentifier(packet_identifier) => {
                packet_identifier.packet_id.set_user(packet_id);
            }
            MqttBody::Subscribe(subscribe) => subscribe.packet_id.set_user(packet_id),
            MqttBody::Suback(suback) => suback.packet_id.set_user(packet_id),
            MqttBody::Unsubscribe(unsubscribe) => unsubscribe.packet_id.set_user(packet_id),
            _ => {}
        }
        self
    }

    /// Add one SUBSCRIBE topic filter and requested QoS pair.
    pub fn subscribe_topic(mut self, filter: impl Into<String>, qos: u8) -> Self {
        if let MqttBody::Subscribe(subscribe) = &mut self.body {
            subscribe.push_topic(filter, qos);
        }
        self
    }

    /// Add SUBSCRIBE topic filter and requested QoS pairs.
    pub fn topics<I, S>(mut self, topics: I) -> Self
    where
        I: IntoIterator<Item = (S, u8)>,
        S: Into<String>,
    {
        if let MqttBody::Subscribe(subscribe) = &mut self.body {
            for (filter, qos) in topics {
                subscribe.push_topic(filter, qos);
            }
        }
        self
    }

    /// Add one SUBACK return code.
    pub fn return_code(mut self, return_code: u8) -> Self {
        match &mut self.body {
            MqttBody::Connack(connack) => connack.return_code.set_user(return_code),
            MqttBody::Suback(suback) => suback.push_return_code(return_code),
            _ => {}
        }
        self
    }

    /// Set the MQTT 5.0 reason code for packets that carry one.
    pub fn reason_code(mut self, reason_code: u8) -> Self {
        match &mut self.body {
            MqttBody::Connack(connack) => connack.return_code.set_user(reason_code),
            MqttBody::PacketIdentifier(packet_identifier) => {
                packet_identifier.reason_code.set_user(reason_code);
            }
            _ => {}
        }
        self
    }

    /// Replace the MQTT 5.0 CONNACK properties block.
    pub fn connack_properties(mut self, properties: MqttProperties) -> Self {
        if let MqttBody::Connack(connack) = &mut self.body {
            connack.properties = properties;
        }
        self
    }

    /// Add one MQTT 5.0 CONNACK property.
    pub fn connack_property(mut self, property: MqttProperty) -> Self {
        if let MqttBody::Connack(connack) = &mut self.body {
            connack.properties.push(property);
        }
        self
    }

    /// Replace the MQTT 5.0 PUBACK/PUBREC/PUBREL/PUBCOMP properties block.
    pub fn ack_properties(mut self, properties: MqttProperties) -> Self {
        if let MqttBody::PacketIdentifier(packet_identifier) = &mut self.body {
            packet_identifier.properties = properties;
        }
        self
    }

    /// Add one MQTT 5.0 PUBACK/PUBREC/PUBREL/PUBCOMP property.
    pub fn ack_property(mut self, property: MqttProperty) -> Self {
        if let MqttBody::PacketIdentifier(packet_identifier) = &mut self.body {
            packet_identifier.properties.push(property);
        }
        self
    }

    /// Add SUBACK return codes.
    pub fn return_codes<I>(mut self, return_codes: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        if let MqttBody::Suback(suback) = &mut self.body {
            for return_code in return_codes {
                suback.push_return_code(return_code);
            }
        }
        self
    }

    /// Set the PUBLISH application payload.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        if let MqttBody::Publish(publish) = &mut self.body {
            publish.payload.set_user(payload.into());
        }
        self
    }

    /// Set or clear the CONNACK Session Present flag.
    pub fn session_present(mut self, session_present: bool) -> Self {
        if let MqttBody::Connack(connack) = &mut self.body {
            connack.set_session_present(session_present);
        }
        self
    }

    /// MQTT control packet type.
    pub fn packet_type(&self) -> MqttControlPacketType {
        self.packet_type
    }

    /// MQTT protocol version selected for this layer.
    pub fn version_value(&self) -> u8 {
        self.version
            .value()
            .copied()
            .unwrap_or(MQTT_311_PROTOCOL_LEVEL)
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
        self.remaining_length.value().copied().unwrap_or_else(|| {
            u32::try_from(
                self.body
                    .encoded_len(self.flags_value(), self.version_value()),
            )
            .unwrap_or(u32::MAX)
        })
    }

    /// Explicit Remaining Length value, if one was set.
    pub fn explicit_remaining_length(&self) -> Option<u32> {
        self.remaining_length.value().copied()
    }

    /// Opaque bytes after the fixed header.
    pub fn body(&self) -> &[u8] {
        self.body.raw_bytes()
    }

    /// CONNECT protocol name, when this is a typed CONNECT packet.
    pub fn protocol_name_value(&self) -> Option<&str> {
        self.connect_body().map(MqttConnect::protocol_name)
    }

    /// CONNECT protocol level, when this is a typed CONNECT packet.
    pub fn protocol_level_value(&self) -> Option<u8> {
        self.connect_body().map(MqttConnect::protocol_level)
    }

    /// CONNECT flags byte, when this is a typed CONNECT packet.
    pub fn connect_flags_value(&self) -> Option<u8> {
        self.connect_body().map(MqttConnect::connect_flags)
    }

    /// CONNECT keep-alive interval in seconds, when this is a typed CONNECT packet.
    pub fn keep_alive_value(&self) -> Option<u16> {
        self.connect_body().map(MqttConnect::keep_alive)
    }

    /// CONNECT client identifier, when this is a typed CONNECT packet.
    pub fn client_id_value(&self) -> Option<&str> {
        self.connect_body().map(MqttConnect::client_id)
    }

    /// CONNECT Will Topic, when present on a typed CONNECT packet.
    pub fn will_topic_value(&self) -> Option<&str> {
        self.connect_body().and_then(MqttConnect::will_topic_value)
    }

    /// CONNECT Will Message bytes, when present on a typed CONNECT packet.
    pub fn will_message_value(&self) -> Option<&[u8]> {
        self.connect_body()
            .and_then(MqttConnect::will_message_value)
    }

    /// CONNECT User Name, when present on a typed CONNECT packet.
    pub fn username_value(&self) -> Option<&str> {
        self.connect_body().and_then(MqttConnect::username_value)
    }

    /// CONNECT Password bytes, when present on a typed CONNECT packet.
    pub fn password_value(&self) -> Option<&[u8]> {
        self.connect_body().and_then(MqttConnect::password_value)
    }

    /// MQTT 5.0 CONNECT properties, when this is a version-5 CONNECT packet.
    pub fn connect_properties_value(&self) -> Option<&MqttProperties> {
        self.connect_body()
            .and_then(MqttConnect::connect_properties_value)
    }

    /// MQTT 5.0 Will Properties, when present on a version-5 CONNECT packet.
    pub fn will_properties_value(&self) -> Option<&MqttProperties> {
        self.connect_body()
            .and_then(MqttConnect::will_properties_value)
    }

    /// CONNACK Session Present flag, when this is a typed CONNACK packet.
    pub fn session_present_value(&self) -> Option<bool> {
        self.connack_body().map(MqttConnack::session_present)
    }

    /// CONNACK return code, when this is a typed CONNACK packet.
    pub fn return_code_value(&self) -> Option<u8> {
        self.connack_body().map(MqttConnack::return_code)
    }

    /// MQTT 5.0 reason code, when this typed packet carries one.
    pub fn reason_code_value(&self) -> Option<u8> {
        if let Some(connack) = self.connack_body() {
            Some(connack.return_code())
        } else {
            self.packet_identifier_body()
                .and_then(|body| body.reason_code_value(self.version_value()))
        }
    }

    /// MQTT 5.0 CONNACK properties, when this is a version-5 CONNACK packet.
    pub fn connack_properties_value(&self) -> Option<&MqttProperties> {
        (self.version_value() == MQTT_5_PROTOCOL_LEVEL)
            .then(|| self.connack_body().map(MqttConnack::properties))
            .flatten()
    }

    /// MQTT 5.0 PUBACK/PUBREC/PUBREL/PUBCOMP properties, when this is a version-5 packet.
    pub fn ack_properties_value(&self) -> Option<&MqttProperties> {
        (self.version_value() == MQTT_5_PROTOCOL_LEVEL)
            .then(|| {
                self.packet_identifier_body()
                    .map(MqttPacketIdentifier::properties)
            })
            .flatten()
    }

    /// PUBLISH topic name, when this is a typed PUBLISH packet.
    pub fn topic_value(&self) -> Option<&str> {
        self.publish_body().map(MqttPublish::topic)
    }

    /// PUBLISH QoS value from the fixed-header flags, when this is a typed PUBLISH packet.
    pub fn qos_value(&self) -> Option<u8> {
        self.publish_body().map(|_| publish_qos(self.flags_value()))
    }

    /// PUBLISH DUP flag, when this is a typed PUBLISH packet.
    pub fn dup_value(&self) -> Option<bool> {
        self.publish_body()
            .map(|_| self.flags_value() & MQTT_PUBLISH_FLAG_DUP != 0)
    }

    /// PUBLISH RETAIN flag, when this is a typed PUBLISH packet.
    pub fn retain_value(&self) -> Option<bool> {
        self.publish_body()
            .map(|_| self.flags_value() & MQTT_PUBLISH_FLAG_RETAIN != 0)
    }

    /// MQTT 5.0 PUBLISH properties, when this is a version-5 PUBLISH packet.
    pub fn publish_properties_value(&self) -> Option<&MqttProperties> {
        (self.version_value() == MQTT_5_PROTOCOL_LEVEL)
            .then(|| self.publish_body().map(MqttPublish::properties))
            .flatten()
    }

    /// Packet Identifier, when present on a typed packet.
    pub fn packet_id_value(&self) -> Option<u16> {
        self.publish_body()
            .and_then(MqttPublish::packet_id_value)
            .or_else(|| {
                self.packet_identifier_body()
                    .map(MqttPacketIdentifier::packet_id)
            })
            .or_else(|| self.subscribe_body().map(MqttSubscribe::packet_id))
            .or_else(|| self.suback_body().map(MqttSuback::packet_id))
            .or_else(|| self.unsubscribe_body().map(MqttUnsubscribe::packet_id))
    }

    /// SUBSCRIBE topic filter and requested QoS pairs, when this is a typed SUBSCRIBE packet.
    pub fn subscribe_topics_value(&self) -> Option<&[(String, u8)]> {
        self.subscribe_body().map(MqttSubscribe::topics)
    }

    /// SUBACK return codes, when this is a typed SUBACK packet.
    pub fn suback_return_codes_value(&self) -> Option<&[u8]> {
        self.suback_body().map(MqttSuback::return_codes)
    }

    /// UNSUBSCRIBE topic filters, when this is a typed UNSUBSCRIBE packet.
    pub fn unsubscribe_topics_value(&self) -> Option<&[String]> {
        self.unsubscribe_body().map(MqttUnsubscribe::topics)
    }

    /// PUBLISH application payload bytes, when this is a typed PUBLISH packet.
    pub fn payload_value(&self) -> Option<&[u8]> {
        self.publish_body().map(MqttPublish::payload)
    }

    fn connect_body(&self) -> Option<&MqttConnect> {
        match &self.body {
            MqttBody::Connect(connect) => Some(connect),
            MqttBody::Raw(_)
            | MqttBody::Empty
            | MqttBody::Connack(_)
            | MqttBody::Publish(_)
            | MqttBody::PacketIdentifier(_)
            | MqttBody::Subscribe(_)
            | MqttBody::Suback(_)
            | MqttBody::Unsubscribe(_) => None,
        }
    }

    fn connack_body(&self) -> Option<&MqttConnack> {
        match &self.body {
            MqttBody::Connack(connack) => Some(connack),
            MqttBody::Raw(_)
            | MqttBody::Empty
            | MqttBody::Connect(_)
            | MqttBody::Publish(_)
            | MqttBody::PacketIdentifier(_)
            | MqttBody::Subscribe(_)
            | MqttBody::Suback(_)
            | MqttBody::Unsubscribe(_) => None,
        }
    }

    fn publish_body(&self) -> Option<&MqttPublish> {
        match &self.body {
            MqttBody::Publish(publish) => Some(publish),
            MqttBody::Raw(_)
            | MqttBody::Empty
            | MqttBody::Connect(_)
            | MqttBody::Connack(_)
            | MqttBody::PacketIdentifier(_)
            | MqttBody::Subscribe(_)
            | MqttBody::Suback(_)
            | MqttBody::Unsubscribe(_) => None,
        }
    }

    fn packet_identifier_body(&self) -> Option<&MqttPacketIdentifier> {
        match &self.body {
            MqttBody::PacketIdentifier(packet_identifier) => Some(packet_identifier),
            MqttBody::Raw(_)
            | MqttBody::Empty
            | MqttBody::Connect(_)
            | MqttBody::Connack(_)
            | MqttBody::Publish(_)
            | MqttBody::Subscribe(_)
            | MqttBody::Suback(_)
            | MqttBody::Unsubscribe(_) => None,
        }
    }

    fn subscribe_body(&self) -> Option<&MqttSubscribe> {
        match &self.body {
            MqttBody::Subscribe(subscribe) => Some(subscribe),
            MqttBody::Raw(_)
            | MqttBody::Empty
            | MqttBody::Connect(_)
            | MqttBody::Connack(_)
            | MqttBody::Publish(_)
            | MqttBody::PacketIdentifier(_)
            | MqttBody::Suback(_)
            | MqttBody::Unsubscribe(_) => None,
        }
    }

    fn suback_body(&self) -> Option<&MqttSuback> {
        match &self.body {
            MqttBody::Suback(suback) => Some(suback),
            MqttBody::Raw(_)
            | MqttBody::Empty
            | MqttBody::Connect(_)
            | MqttBody::Connack(_)
            | MqttBody::Publish(_)
            | MqttBody::PacketIdentifier(_)
            | MqttBody::Subscribe(_)
            | MqttBody::Unsubscribe(_) => None,
        }
    }

    fn unsubscribe_body(&self) -> Option<&MqttUnsubscribe> {
        match &self.body {
            MqttBody::Unsubscribe(unsubscribe) => Some(unsubscribe),
            MqttBody::Raw(_)
            | MqttBody::Empty
            | MqttBody::Connect(_)
            | MqttBody::Connack(_)
            | MqttBody::Publish(_)
            | MqttBody::PacketIdentifier(_)
            | MqttBody::Subscribe(_)
            | MqttBody::Suback(_) => None,
        }
    }

    fn set_publish_flag(&mut self, mask: u8, enabled: bool) {
        let mut flags = self.flags_value();
        if enabled {
            flags |= mask;
        } else {
            flags &= !mask;
        }
        self.flags.set_user(flags);
    }

    fn first_byte(&self) -> u8 {
        self.packet_type.high_nibble() | self.flags_value()
    }

    fn encoded_body(&self) -> Result<Vec<u8>> {
        let flags = self.flags_value();
        let version = self.version_value();
        let mut body = Vec::with_capacity(self.body.encoded_len(flags, version));
        self.body.write_body(&mut body, flags, version)?;
        Ok(body)
    }
}

impl Layer for Mqtt {
    fn name(&self) -> &'static str {
        "MQTT"
    }

    fn summary(&self) -> String {
        match &self.body {
            MqttBody::Raw(body) => format!(
                "MQTT {} raw len={} body={} bytes",
                packet_type_name(self.packet_type),
                self.remaining_length_value(),
                body.len()
            ),
            MqttBody::Empty => format!(
                "MQTT {} len={}",
                packet_type_name(self.packet_type),
                self.remaining_length_value()
            ),
            MqttBody::Connect(connect) => {
                let flags = connect.connect_flags();
                format!(
                    "MQTT CONNECT client_id={} keep_alive={} clean_session={} will={} username={} password={}",
                    connect.client_id(),
                    connect.keep_alive(),
                    connect_clean_session(flags),
                    connect_will_flag(flags),
                    connect_username_flag(flags),
                    connect_password_flag(flags)
                )
            }
            MqttBody::Connack(connack) => format!(
                "MQTT CONNACK session_present={} return_code={}",
                connack.session_present(),
                connack.return_code()
            ),
            MqttBody::Publish(publish) => format!(
                "MQTT PUBLISH topic={} qos={} dup={} retain={} payload={} bytes",
                publish.topic(),
                publish_qos(self.flags_value()),
                self.flags_value() & MQTT_PUBLISH_FLAG_DUP != 0,
                self.flags_value() & MQTT_PUBLISH_FLAG_RETAIN != 0,
                publish.payload().len()
            ),
            MqttBody::PacketIdentifier(packet_identifier) => format!(
                "MQTT {} packet_id={}",
                packet_type_name(self.packet_type),
                packet_identifier.packet_id()
            ),
            MqttBody::Subscribe(subscribe) => format!(
                "MQTT SUBSCRIBE packet_id={} topics={}",
                subscribe.packet_id(),
                subscribe_topic_summary(subscribe.topics())
            ),
            MqttBody::Suback(suback) => format!(
                "MQTT SUBACK packet_id={} return_codes={}",
                suback.packet_id(),
                byte_list_summary(suback.return_codes())
            ),
            MqttBody::Unsubscribe(unsubscribe) => format!(
                "MQTT UNSUBSCRIBE packet_id={} topics={}",
                unsubscribe.packet_id(),
                topic_list_summary(unsubscribe.topics())
            ),
        }
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("type", packet_type_name(self.packet_type).to_string()),
            ("flags", format!("0x{:x}", self.flags_value())),
            (
                "remaining_length",
                self.remaining_length_value().to_string(),
            ),
            (
                "body_length",
                self.body
                    .encoded_len(self.flags_value(), self.version_value())
                    .to_string(),
            ),
        ];

        match &self.body {
            MqttBody::Raw(body) => {
                fields.push(("raw_body_length", body.len().to_string()));
                fields.push(("raw_body", hex_bytes(body)));
            }
            MqttBody::Empty => {}
            MqttBody::Connect(connect) => {
                let flags = connect.connect_flags();
                fields.push(("protocol_name", connect.protocol_name().to_string()));
                fields.push(("protocol_level", connect.protocol_level().to_string()));
                fields.push(("connect_flags", format!("0x{:x}", flags)));
                fields.push(("clean_session", connect_clean_session(flags).to_string()));
                fields.push(("keep_alive", connect.keep_alive().to_string()));
                fields.push(("client_id", connect.client_id().to_string()));
                fields.push(("will", connect_will_flag(flags).to_string()));
                fields.push(("will_qos", connect_will_qos(flags).to_string()));
                fields.push(("will_retain", connect_will_retain_flag(flags).to_string()));
                if let Some(will_topic) = connect.will_topic_value() {
                    fields.push(("will_topic", will_topic.to_string()));
                }
                if let Some(will_message) = connect.will_message_value() {
                    fields.push(("will_message_length", will_message.len().to_string()));
                    fields.push(("will_message", hex_bytes(will_message)));
                }
                if let Some(username) = connect.username_value() {
                    fields.push(("username", username.to_string()));
                }
                if let Some(password) = connect.password_value() {
                    fields.push(("password_length", password.len().to_string()));
                }
            }
            MqttBody::Connack(connack) => {
                fields.push(("ack_flags", format!("0x{:x}", connack.ack_flags())));
                fields.push(("session_present", connack.session_present().to_string()));
                fields.push(("return_code", connack.return_code().to_string()));
            }
            MqttBody::Publish(publish) => {
                fields.push(("topic", publish.topic().to_string()));
                fields.push(("qos", publish_qos(self.flags_value()).to_string()));
                fields.push((
                    "dup",
                    (self.flags_value() & MQTT_PUBLISH_FLAG_DUP != 0).to_string(),
                ));
                fields.push((
                    "retain",
                    (self.flags_value() & MQTT_PUBLISH_FLAG_RETAIN != 0).to_string(),
                ));
                if let Some(packet_id) = publish.packet_id_value() {
                    fields.push(("packet_id", packet_id.to_string()));
                }
                fields.push(("payload_length", publish.payload().len().to_string()));
                fields.push(("payload", hex_bytes(publish.payload())));
            }
            MqttBody::PacketIdentifier(packet_identifier) => {
                fields.push(("packet_id", packet_identifier.packet_id().to_string()));
            }
            MqttBody::Subscribe(subscribe) => {
                fields.push(("packet_id", subscribe.packet_id().to_string()));
                fields.push(("topics", subscribe_topic_summary(subscribe.topics())));
                for (filter, qos) in subscribe.topics() {
                    fields.push(("topic_filter", format!("{filter}:qos{qos}")));
                }
            }
            MqttBody::Suback(suback) => {
                fields.push(("packet_id", suback.packet_id().to_string()));
                fields.push(("return_codes", byte_list_summary(suback.return_codes())));
            }
            MqttBody::Unsubscribe(unsubscribe) => {
                fields.push(("packet_id", unsubscribe.packet_id().to_string()));
                fields.push(("topics", topic_list_summary(unsubscribe.topics())));
                for topic in unsubscribe.topics() {
                    fields.push(("topic_filter", topic.clone()));
                }
            }
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        1 + remaining_length_encoded_len(self.remaining_length_value())
            + self
                .body
                .encoded_len(self.flags_value(), self.version_value())
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

fn publish_qos(flags: u8) -> u8 {
    (flags & MQTT_PUBLISH_FLAG_QOS_MASK) >> PUBLISH_QOS_SHIFT
}

fn remaining_length_encoded_len(value: u32) -> usize {
    match value {
        0..=127 => 1,
        128..=16_383 => 2,
        16_384..=2_097_151 => 3,
        _ => 4,
    }
}

fn encoded_properties_len(properties: &MqttProperties) -> usize {
    properties
        .to_vec()
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
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
        MqttControlPacketType::Auth => "AUTH",
    }
}

fn connect_clean_session(flags: u8) -> bool {
    flags & MQTT_CONNECT_FLAG_CLEAN_SESSION != 0
}

fn connect_will_flag(flags: u8) -> bool {
    flags & MQTT_CONNECT_FLAG_WILL != 0
}

fn connect_will_qos(flags: u8) -> u8 {
    (flags & MQTT_CONNECT_FLAG_WILL_QOS_MASK) >> CONNECT_WILL_QOS_SHIFT
}

fn connect_will_retain_flag(flags: u8) -> bool {
    flags & MQTT_CONNECT_FLAG_WILL_RETAIN != 0
}

fn connect_username_flag(flags: u8) -> bool {
    flags & MQTT_CONNECT_FLAG_USER_NAME != 0
}

fn connect_password_flag(flags: u8) -> bool {
    flags & MQTT_CONNECT_FLAG_PASSWORD != 0
}

fn subscribe_topic_summary(topics: &[(String, u8)]) -> String {
    if topics.is_empty() {
        return "[]".to_string();
    }

    format!(
        "[{}]",
        topics
            .iter()
            .map(|(filter, qos)| format!("{filter}:qos{qos}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn topic_list_summary(topics: &[String]) -> String {
    if topics.is_empty() {
        return "[]".to_string();
    }

    format!("[{}]", topics.join(","))
}

fn byte_list_summary(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "[]".to_string();
    }

    format!(
        "[{}]",
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",")
    )
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
    fn publish_qos0_omits_packet_identifier() {
        let bytes = mqtt_bytes(Mqtt::publish().topic("a/b").payload(b"hi".to_vec()));

        let expected = vec![0x30, 0x07, 0x00, 0x03, b'a', b'/', b'b', b'h', b'i'];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn publish_qos1_includes_packet_identifier() {
        let bytes = mqtt_bytes(
            Mqtt::publish()
                .topic("topic")
                .qos(1)
                .packet_id(0x1234)
                .payload(vec![0xde, 0xad]),
        );

        let expected = vec![
            0x32, 0x0b, 0x00, 0x05, b't', b'o', b'p', b'i', b'c', 0x12, 0x34, 0xde, 0xad,
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn publish_dup_qos2_and_retain_bits_land_in_fixed_header() {
        let bytes = mqtt_bytes(
            Mqtt::publish()
                .topic("x")
                .qos(2)
                .dup(true)
                .retain(true)
                .packet_id(7),
        );

        let expected = vec![0x3d, 0x05, 0x00, 0x01, b'x', 0x00, 0x07];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn publish_explicit_packet_identifier_value_is_preserved() {
        let bytes = mqtt_bytes(Mqtt::publish().topic("x").qos(1).packet_id(0));

        let expected = vec![0x32, 0x05, 0x00, 0x01, b'x', 0x00, 0x00];
        assert_eq!(bytes, expected);
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
    fn subscribe_compiles_packet_identifier_and_topic_filters() {
        let bytes = mqtt_bytes(
            Mqtt::subscribe()
                .packet_id(0x1234)
                .topics([("a/b", 0), ("c/d", 1)]),
        );

        let expected = vec![
            0x82, 0x0e, 0x12, 0x34, 0x00, 0x03, b'a', b'/', b'b', 0x00, 0x00, 0x03, b'c', b'/',
            b'd', 0x01,
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn subscribe_empty_topic_list_is_not_filled_implicitly() {
        let bytes = mqtt_bytes(Mqtt::subscribe().packet_id(0x1234));

        assert_eq!(bytes, [0x82, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn suback_compiles_packet_identifier_and_return_codes() {
        let bytes = mqtt_bytes(Mqtt::suback().packet_id(0x1234).return_codes([0x01, 0x80]));

        assert_eq!(bytes, [0x90, 0x04, 0x12, 0x34, 0x01, 0x80]);
    }

    #[test]
    fn unsubscribe_compiles_packet_identifier_and_topic_filters() {
        let bytes = mqtt_bytes(
            Mqtt::unsubscribe()
                .packet_id(0x1234)
                .topic("a/b")
                .topic("c/d"),
        );

        let expected = vec![
            0xa2, 0x0c, 0x12, 0x34, 0x00, 0x03, b'a', b'/', b'b', 0x00, 0x03, b'c', b'/', b'd',
        ];
        assert_eq!(bytes, expected);
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
    fn connack_defaults_to_accepted_without_session_present() {
        let bytes = mqtt_bytes(Mqtt::connack());

        assert_eq!(bytes, [0x20, 0x02, 0x00, MQTT_CONNACK_ACCEPTED]);
    }

    #[test]
    fn connack_session_present_return_code_and_remaining_length_override_are_honored() {
        let bytes = mqtt_bytes(
            Mqtt::connack()
                .session_present(true)
                .return_code(0x03)
                .remaining_length(0),
        );

        assert_eq!(bytes, [0x20, 0x00, 0x01, 0x03]);
    }

    #[test]
    fn puback_compiles_packet_identifier() {
        let bytes = mqtt_bytes(Mqtt::puback().packet_id(0x1234));

        assert_eq!(bytes, [0x40, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn pubrec_compiles_packet_identifier() {
        let bytes = mqtt_bytes(Mqtt::pubrec().packet_id(0x1234));

        assert_eq!(bytes, [0x50, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn pubrel_compiles_packet_identifier_with_fixed_flags() {
        let bytes = mqtt_bytes(Mqtt::pubrel().packet_id(0x1234));

        assert_eq!(bytes, [0x62, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn pubcomp_compiles_packet_identifier() {
        let bytes = mqtt_bytes(Mqtt::pubcomp().packet_id(0x1234));

        assert_eq!(bytes, [0x70, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn unsuback_compiles_packet_identifier() {
        let bytes = mqtt_bytes(Mqtt::unsuback().packet_id(0x1234));

        assert_eq!(bytes, [0xb0, 0x02, 0x12, 0x34]);
    }

    #[test]
    fn pingreq_compiles_empty_body() {
        let bytes = mqtt_bytes(Mqtt::pingreq());

        assert_eq!(bytes, [0xc0, 0x00]);
    }

    #[test]
    fn pingresp_compiles_empty_body() {
        let bytes = mqtt_bytes(Mqtt::pingresp());

        assert_eq!(bytes, [0xd0, 0x00]);
    }

    #[test]
    fn disconnect_compiles_empty_body() {
        let bytes = mqtt_bytes(Mqtt::disconnect());

        assert_eq!(bytes, [0xe0, 0x00]);
    }

    #[test]
    fn summary_show_and_hexdump_cover_baseline_packets() {
        let messages = vec![
            Mqtt::connect().client_id("cid"),
            Mqtt::connack(),
            Mqtt::publish().topic("topic").payload(b"hello".to_vec()),
            Mqtt::puback().packet_id(1),
            Mqtt::pubrec().packet_id(2),
            Mqtt::pubrel().packet_id(3),
            Mqtt::pubcomp().packet_id(4),
            Mqtt::subscribe().packet_id(5).subscribe_topic("topic", 1),
            Mqtt::suback().packet_id(5).return_code(1),
            Mqtt::unsubscribe().packet_id(6).topic("topic"),
            Mqtt::unsuback().packet_id(6),
            Mqtt::pingreq(),
            Mqtt::pingresp(),
            Mqtt::disconnect(),
        ];

        for message in messages {
            let packet = Ipv4::new() / Tcp::new() / message;
            let summary = packet.summary();
            assert!(summary.contains("MQTT"), "summary was: {summary}");

            let show = packet.show();
            assert!(show.contains("[2] MQTT"), "show was:\n{show}");
            assert!(show.contains("type:"), "show was:\n{show}");

            let hexdump = packet.hexdump().expect("hexdump");
            assert!(!hexdump.is_empty());
        }
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
            0x10, 0x25, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0xee, 0x00, 0x1e, 0x00, 0x03,
            b'c', b'i', b'd', 0x00, 0x06, b's', b't', b'a', b't', b'u', b's', 0x00, 0x02, 0xde,
            0xad, 0x00, 0x04, b'u', b's', b'e', b'r', 0x00, 0x02, 0xbe, 0xef,
        ];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn connect_username_without_password_omits_password_field() {
        let bytes = mqtt_bytes(Mqtt::connect().client_id("cid").username("user"));

        let expected = vec![
            0x10, 0x15, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x82, 0x00, 0x3c, 0x00, 0x03,
            b'c', b'i', b'd', 0x00, 0x04, b'u', b's', b'e', b'r',
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
            0x10,
            0x0f,
            0x00,
            0x04,
            b'M',
            b'Q',
            b'T',
            b'T',
            0x04,
            MQTT_CONNECT_FLAG_CLEAN_SESSION,
            0x00,
            0x3c,
            0x00,
            0x03,
            b'c',
            b'i',
            b'd',
        ];

        assert_eq!(bytes, expected);
    }
}
