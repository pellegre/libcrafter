//! MQTT 5.0 property encoding.
//!
//! MQTT properties are encoded as a variable-byte-integer property length,
//! followed by zero or more identifier/value pairs. Each identifier has a fixed
//! wire type from OASIS MQTT 5.0 section 2.2.2.2. Unknown property identifiers
//! are rejected during decode because the identifier determines the value
//! length; without that type, there is no safe boundary for a raw value.

use crate::field::Field;
use crate::{CrafterError, Result};

use super::constants::*;
use super::varint::{decode_remaining_length, encode_remaining_length};
use super::wire::{
    decode_binary, decode_string, decode_u16, decode_u32, encode_binary, encode_string, encode_u16,
    encode_u32,
};

/// One typed MQTT 5.0 property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttProperty {
    /// Payload Format Indicator, Byte.
    PayloadFormatIndicator(u8),
    /// Message Expiry Interval, Four Byte Integer.
    MessageExpiryInterval(u32),
    /// Content Type, UTF-8 Encoded String.
    ContentType(String),
    /// Response Topic, UTF-8 Encoded String.
    ResponseTopic(String),
    /// Correlation Data, Binary Data.
    CorrelationData(Vec<u8>),
    /// Subscription Identifier, Variable Byte Integer.
    SubscriptionIdentifier(u32),
    /// Session Expiry Interval, Four Byte Integer.
    SessionExpiryInterval(u32),
    /// Assigned Client Identifier, UTF-8 Encoded String.
    AssignedClientIdentifier(String),
    /// Server Keep Alive, Two Byte Integer.
    ServerKeepAlive(u16),
    /// Authentication Method, UTF-8 Encoded String.
    AuthenticationMethod(String),
    /// Authentication Data, Binary Data.
    AuthenticationData(Vec<u8>),
    /// Request Problem Information, Byte.
    RequestProblemInformation(u8),
    /// Will Delay Interval, Four Byte Integer.
    WillDelayInterval(u32),
    /// Request Response Information, Byte.
    RequestResponseInformation(u8),
    /// Response Information, UTF-8 Encoded String.
    ResponseInformation(String),
    /// Server Reference, UTF-8 Encoded String.
    ServerReference(String),
    /// Reason String, UTF-8 Encoded String.
    ReasonString(String),
    /// Receive Maximum, Two Byte Integer.
    ReceiveMaximum(u16),
    /// Topic Alias Maximum, Two Byte Integer.
    TopicAliasMaximum(u16),
    /// Topic Alias, Two Byte Integer.
    TopicAlias(u16),
    /// Maximum QoS, Byte.
    MaximumQos(u8),
    /// Retain Available, Byte.
    RetainAvailable(u8),
    /// User Property, UTF-8 String Pair. This property may appear more than once.
    UserProperty { name: String, value: String },
    /// Maximum Packet Size, Four Byte Integer.
    MaximumPacketSize(u32),
    /// Wildcard Subscription Available, Byte.
    WildcardSubscriptionAvailable(u8),
    /// Subscription Identifier Available, Byte.
    SubscriptionIdentifierAvailable(u8),
    /// Shared Subscription Available, Byte.
    SharedSubscriptionAvailable(u8),
}

impl MqttProperty {
    /// Build a User Property string pair.
    pub fn user_property(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::UserProperty {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Return this property's MQTT 5.0 property identifier.
    pub const fn identifier(&self) -> u8 {
        match self {
            Self::PayloadFormatIndicator(_) => MQTT_PROP_PAYLOAD_FORMAT_INDICATOR,
            Self::MessageExpiryInterval(_) => MQTT_PROP_MESSAGE_EXPIRY_INTERVAL,
            Self::ContentType(_) => MQTT_PROP_CONTENT_TYPE,
            Self::ResponseTopic(_) => MQTT_PROP_RESPONSE_TOPIC,
            Self::CorrelationData(_) => MQTT_PROP_CORRELATION_DATA,
            Self::SubscriptionIdentifier(_) => MQTT_PROP_SUBSCRIPTION_IDENTIFIER,
            Self::SessionExpiryInterval(_) => MQTT_PROP_SESSION_EXPIRY_INTERVAL,
            Self::AssignedClientIdentifier(_) => MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER,
            Self::ServerKeepAlive(_) => MQTT_PROP_SERVER_KEEP_ALIVE,
            Self::AuthenticationMethod(_) => MQTT_PROP_AUTHENTICATION_METHOD,
            Self::AuthenticationData(_) => MQTT_PROP_AUTHENTICATION_DATA,
            Self::RequestProblemInformation(_) => MQTT_PROP_REQUEST_PROBLEM_INFORMATION,
            Self::WillDelayInterval(_) => MQTT_PROP_WILL_DELAY_INTERVAL,
            Self::RequestResponseInformation(_) => MQTT_PROP_REQUEST_RESPONSE_INFORMATION,
            Self::ResponseInformation(_) => MQTT_PROP_RESPONSE_INFORMATION,
            Self::ServerReference(_) => MQTT_PROP_SERVER_REFERENCE,
            Self::ReasonString(_) => MQTT_PROP_REASON_STRING,
            Self::ReceiveMaximum(_) => MQTT_PROP_RECEIVE_MAXIMUM,
            Self::TopicAliasMaximum(_) => MQTT_PROP_TOPIC_ALIAS_MAXIMUM,
            Self::TopicAlias(_) => MQTT_PROP_TOPIC_ALIAS,
            Self::MaximumQos(_) => MQTT_PROP_MAXIMUM_QOS,
            Self::RetainAvailable(_) => MQTT_PROP_RETAIN_AVAILABLE,
            Self::UserProperty { .. } => MQTT_PROP_USER_PROPERTY,
            Self::MaximumPacketSize(_) => MQTT_PROP_MAXIMUM_PACKET_SIZE,
            Self::WildcardSubscriptionAvailable(_) => MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE,
            Self::SubscriptionIdentifierAvailable(_) => MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE,
            Self::SharedSubscriptionAvailable(_) => MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE,
        }
    }

    /// Append the identifier and typed value for this property.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        encode_remaining_length(u32::from(self.identifier()), out)?;

        match self {
            Self::PayloadFormatIndicator(value)
            | Self::RequestProblemInformation(value)
            | Self::RequestResponseInformation(value)
            | Self::MaximumQos(value)
            | Self::RetainAvailable(value)
            | Self::WildcardSubscriptionAvailable(value)
            | Self::SubscriptionIdentifierAvailable(value)
            | Self::SharedSubscriptionAvailable(value) => out.push(*value),

            Self::ServerKeepAlive(value)
            | Self::ReceiveMaximum(value)
            | Self::TopicAliasMaximum(value)
            | Self::TopicAlias(value) => encode_u16(*value, out),

            Self::MessageExpiryInterval(value)
            | Self::SessionExpiryInterval(value)
            | Self::WillDelayInterval(value)
            | Self::MaximumPacketSize(value) => encode_u32(*value, out),

            Self::SubscriptionIdentifier(value) => encode_remaining_length(*value, out)?,

            Self::ContentType(value)
            | Self::ResponseTopic(value)
            | Self::AssignedClientIdentifier(value)
            | Self::AuthenticationMethod(value)
            | Self::ResponseInformation(value)
            | Self::ServerReference(value)
            | Self::ReasonString(value) => encode_string(value, out)?,

            Self::CorrelationData(value) | Self::AuthenticationData(value) => {
                encode_binary(value, out)?
            }

            Self::UserProperty { name, value } => {
                encode_string(name, out)?;
                encode_string(value, out)?;
            }
        }

        Ok(())
    }
}

/// An MQTT 5.0 property sequence with its length prefix.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MqttProperties {
    property_length: Field<u32>,
    properties: Vec<MqttProperty>,
}

impl MqttProperties {
    /// Create an empty MQTT 5.0 property sequence.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the property list.
    pub fn properties(mut self, properties: impl Into<Vec<MqttProperty>>) -> Self {
        self.properties = properties.into();
        self
    }

    /// Add one property.
    pub fn property(mut self, property: MqttProperty) -> Self {
        self.properties.push(property);
        self
    }

    /// Append one property in-place.
    pub fn push(&mut self, property: MqttProperty) -> &mut Self {
        self.properties.push(property);
        self
    }

    /// Set an explicit property length prefix, including intentionally wrong values.
    pub fn property_length(mut self, property_length: u32) -> Self {
        self.property_length.set_user(property_length);
        self
    }

    /// Current explicitly configured property length, if any.
    pub fn property_length_override(&self) -> Option<u32> {
        self.property_length.value().copied()
    }

    /// The contained properties in wire order.
    pub fn property_values(&self) -> &[MqttProperty] {
        &self.properties
    }

    /// Append the full MQTT properties field, including the property-length prefix.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut body = Vec::new();
        for property in &self.properties {
            property.write(&mut body)?;
        }

        let property_length = match self.property_length.value().copied() {
            Some(value) => value,
            None => u32::try_from(body.len()).map_err(|_| {
                CrafterError::invalid_field_value(
                    "mqtt.property_length",
                    "property length must fit in four bytes",
                )
            })?,
        };

        encode_remaining_length(property_length, out)?;
        out.extend_from_slice(&body);
        Ok(())
    }

    /// Encode the full MQTT properties field into a new byte vector.
    pub fn to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.write(&mut out)?;
        Ok(out)
    }

    /// Decode a full MQTT properties field, returning the collection and consumed bytes.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        let (property_length, prefix_len) = decode_remaining_length(bytes)?;
        let body_len = usize::try_from(property_length).map_err(|_| {
            CrafterError::invalid_field_value(
                "mqtt.property_length",
                "property length is too large",
            )
        })?;
        let total_len = prefix_len.checked_add(body_len).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "mqtt.property_length",
                "property length is too large",
            )
        })?;

        if bytes.len() < total_len {
            return Err(CrafterError::buffer_too_short(
                "mqtt.properties",
                total_len,
                bytes.len(),
            ));
        }

        let body = &bytes[prefix_len..total_len];
        let mut cursor = 0;
        let mut properties = Vec::new();
        while cursor < body.len() {
            let (identifier, consumed) = decode_remaining_length(&body[cursor..])?;
            cursor += consumed;
            properties.push(decode_property(identifier, body, &mut cursor)?);
        }

        Ok((
            Self {
                property_length: Field::user(property_length),
                properties,
            },
            total_len,
        ))
    }
}

impl From<Vec<MqttProperty>> for MqttProperties {
    fn from(properties: Vec<MqttProperty>) -> Self {
        Self::new().properties(properties)
    }
}

fn decode_property(identifier: u32, body: &[u8], cursor: &mut usize) -> Result<MqttProperty> {
    match identifier {
        id if id == u32::from(MQTT_PROP_PAYLOAD_FORMAT_INDICATOR) => Ok(
            MqttProperty::PayloadFormatIndicator(take_u8(body, cursor, "mqtt.property.byte")?),
        ),
        id if id == u32::from(MQTT_PROP_MESSAGE_EXPIRY_INTERVAL) => {
            Ok(MqttProperty::MessageExpiryInterval(take_u32(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_CONTENT_TYPE) => {
            Ok(MqttProperty::ContentType(take_string(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_RESPONSE_TOPIC) => {
            Ok(MqttProperty::ResponseTopic(take_string(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_CORRELATION_DATA) => {
            Ok(MqttProperty::CorrelationData(take_binary(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_SUBSCRIPTION_IDENTIFIER) => Ok(
            MqttProperty::SubscriptionIdentifier(take_variable_integer(body, cursor)?),
        ),
        id if id == u32::from(MQTT_PROP_SESSION_EXPIRY_INTERVAL) => {
            Ok(MqttProperty::SessionExpiryInterval(take_u32(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_ASSIGNED_CLIENT_IDENTIFIER) => Ok(
            MqttProperty::AssignedClientIdentifier(take_string(body, cursor)?),
        ),
        id if id == u32::from(MQTT_PROP_SERVER_KEEP_ALIVE) => {
            Ok(MqttProperty::ServerKeepAlive(take_u16(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_AUTHENTICATION_METHOD) => Ok(
            MqttProperty::AuthenticationMethod(take_string(body, cursor)?),
        ),
        id if id == u32::from(MQTT_PROP_AUTHENTICATION_DATA) => {
            Ok(MqttProperty::AuthenticationData(take_binary(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_REQUEST_PROBLEM_INFORMATION) => Ok(
            MqttProperty::RequestProblemInformation(take_u8(body, cursor, "mqtt.property.byte")?),
        ),
        id if id == u32::from(MQTT_PROP_WILL_DELAY_INTERVAL) => {
            Ok(MqttProperty::WillDelayInterval(take_u32(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_REQUEST_RESPONSE_INFORMATION) => Ok(
            MqttProperty::RequestResponseInformation(take_u8(body, cursor, "mqtt.property.byte")?),
        ),
        id if id == u32::from(MQTT_PROP_RESPONSE_INFORMATION) => Ok(
            MqttProperty::ResponseInformation(take_string(body, cursor)?),
        ),
        id if id == u32::from(MQTT_PROP_SERVER_REFERENCE) => {
            Ok(MqttProperty::ServerReference(take_string(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_REASON_STRING) => {
            Ok(MqttProperty::ReasonString(take_string(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_RECEIVE_MAXIMUM) => {
            Ok(MqttProperty::ReceiveMaximum(take_u16(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_TOPIC_ALIAS_MAXIMUM) => {
            Ok(MqttProperty::TopicAliasMaximum(take_u16(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_TOPIC_ALIAS) => {
            Ok(MqttProperty::TopicAlias(take_u16(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_MAXIMUM_QOS) => Ok(MqttProperty::MaximumQos(take_u8(
            body,
            cursor,
            "mqtt.property.byte",
        )?)),
        id if id == u32::from(MQTT_PROP_RETAIN_AVAILABLE) => Ok(MqttProperty::RetainAvailable(
            take_u8(body, cursor, "mqtt.property.byte")?,
        )),
        id if id == u32::from(MQTT_PROP_USER_PROPERTY) => Ok(MqttProperty::UserProperty {
            name: take_string(body, cursor)?,
            value: take_string(body, cursor)?,
        }),
        id if id == u32::from(MQTT_PROP_MAXIMUM_PACKET_SIZE) => {
            Ok(MqttProperty::MaximumPacketSize(take_u32(body, cursor)?))
        }
        id if id == u32::from(MQTT_PROP_WILDCARD_SUBSCRIPTION_AVAILABLE) => {
            Ok(MqttProperty::WildcardSubscriptionAvailable(take_u8(
                body,
                cursor,
                "mqtt.property.byte",
            )?))
        }
        id if id == u32::from(MQTT_PROP_SUBSCRIPTION_IDENTIFIER_AVAILABLE) => {
            Ok(MqttProperty::SubscriptionIdentifierAvailable(take_u8(
                body,
                cursor,
                "mqtt.property.byte",
            )?))
        }
        id if id == u32::from(MQTT_PROP_SHARED_SUBSCRIPTION_AVAILABLE) => Ok(
            MqttProperty::SharedSubscriptionAvailable(take_u8(body, cursor, "mqtt.property.byte")?),
        ),
        _ => Err(CrafterError::invalid_field_value(
            "mqtt.property.identifier",
            "unknown MQTT property identifier cannot be decoded without a wire type",
        )),
    }
}

fn take_u8(bytes: &[u8], cursor: &mut usize, context: &'static str) -> Result<u8> {
    let Some(&value) = bytes.get(*cursor) else {
        return Err(CrafterError::buffer_too_short(
            context,
            *cursor + 1,
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

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let (value, consumed) = decode_u32(&bytes[*cursor..])?;
    *cursor += consumed;
    Ok(value)
}

fn take_variable_integer(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let (value, consumed) = decode_remaining_length(&bytes[*cursor..])?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(property: MqttProperty) -> Vec<u8> {
        MqttProperties::new().property(property).to_vec().unwrap()
    }

    #[test]
    fn empty_property_set_encodes_zero_length() {
        assert_eq!(MqttProperties::new().to_vec().unwrap(), [0x00]);
    }

    #[test]
    fn byte_property_encodes_identifier_and_value() {
        assert_eq!(
            encode(MqttProperty::PayloadFormatIndicator(1)),
            [0x02, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 0x01]
        );
    }

    #[test]
    fn two_byte_integer_property_encodes_big_endian_value() {
        assert_eq!(
            encode(MqttProperty::ReceiveMaximum(10)),
            [0x03, MQTT_PROP_RECEIVE_MAXIMUM, 0x00, 0x0a]
        );
    }

    #[test]
    fn four_byte_integer_property_encodes_big_endian_value() {
        assert_eq!(
            encode(MqttProperty::MessageExpiryInterval(60)),
            [
                0x05,
                MQTT_PROP_MESSAGE_EXPIRY_INTERVAL,
                0x00,
                0x00,
                0x00,
                0x3c
            ]
        );
    }

    #[test]
    fn variable_byte_integer_property_encodes_remaining_length_form() {
        assert_eq!(
            encode(MqttProperty::SubscriptionIdentifier(321)),
            [0x03, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, 0xc1, 0x02]
        );
    }

    #[test]
    fn string_property_encodes_utf8_length_prefixed_value() {
        assert_eq!(
            encode(MqttProperty::ContentType("text/plain".to_string())),
            [
                0x0d,
                MQTT_PROP_CONTENT_TYPE,
                0x00,
                0x0a,
                b't',
                b'e',
                b'x',
                b't',
                b'/',
                b'p',
                b'l',
                b'a',
                b'i',
                b'n',
            ]
        );
    }

    #[test]
    fn binary_property_encodes_length_prefixed_value() {
        assert_eq!(
            encode(MqttProperty::CorrelationData(vec![0xde, 0xad])),
            [0x05, MQTT_PROP_CORRELATION_DATA, 0x00, 0x02, 0xde, 0xad]
        );
    }

    #[test]
    fn string_pair_property_encodes_two_utf8_values() {
        assert_eq!(
            encode(MqttProperty::user_property("k", "v")),
            [
                0x07,
                MQTT_PROP_USER_PROPERTY,
                0x00,
                0x01,
                b'k',
                0x00,
                0x01,
                b'v'
            ]
        );
    }

    #[test]
    fn repeated_user_properties_remain_in_order() {
        assert_eq!(
            MqttProperties::new()
                .property(MqttProperty::user_property("k", "v"))
                .property(MqttProperty::user_property("x", "y"))
                .to_vec()
                .unwrap(),
            [
                0x0e,
                MQTT_PROP_USER_PROPERTY,
                0x00,
                0x01,
                b'k',
                0x00,
                0x01,
                b'v',
                MQTT_PROP_USER_PROPERTY,
                0x00,
                0x01,
                b'x',
                0x00,
                0x01,
                b'y',
            ]
        );
    }

    #[test]
    fn explicit_length_override_is_honored() {
        assert_eq!(
            MqttProperties::new()
                .property(MqttProperty::user_property("k", "v"))
                .property_length(1)
                .to_vec()
                .unwrap(),
            [
                0x01,
                MQTT_PROP_USER_PROPERTY,
                0x00,
                0x01,
                b'k',
                0x00,
                0x01,
                b'v'
            ]
        );
    }

    #[test]
    fn typed_properties_decode_round_trip_each_wire_type() {
        for property in [
            MqttProperty::PayloadFormatIndicator(1),
            MqttProperty::ReceiveMaximum(10),
            MqttProperty::MessageExpiryInterval(60),
            MqttProperty::SubscriptionIdentifier(321),
            MqttProperty::ContentType("text/plain".to_string()),
            MqttProperty::CorrelationData(vec![0xde, 0xad]),
            MqttProperty::user_property("k", "v"),
        ] {
            let encoded = MqttProperties::new()
                .property(property.clone())
                .to_vec()
                .unwrap();
            let (decoded, consumed) = MqttProperties::decode(&encoded).unwrap();

            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded.property_values(), &[property]);
            assert_eq!(decoded.to_vec().unwrap(), encoded);
        }
    }

    #[test]
    fn repeated_user_properties_decode_in_order() {
        let encoded = MqttProperties::new()
            .property(MqttProperty::user_property("k", "v"))
            .property(MqttProperty::user_property("x", "y"))
            .to_vec()
            .unwrap();
        let (decoded, consumed) = MqttProperties::decode(&encoded).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(
            decoded.property_values(),
            &[
                MqttProperty::user_property("k", "v"),
                MqttProperty::user_property("x", "y")
            ]
        );
    }

    #[test]
    fn truncated_property_value_errors_without_panic() {
        let result = std::panic::catch_unwind(|| {
            MqttProperties::decode(&[0x02, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, 0x00])
        });
        assert!(result.is_ok());

        match result.unwrap() {
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "mqtt.u32");
                assert_eq!(required, 4);
                assert_eq!(available, 1);
            }
            other => panic!("expected buffer-too-short error, got {other:?}"),
        }
    }

    #[test]
    fn overrunning_property_length_errors_without_panic() {
        let result = std::panic::catch_unwind(|| {
            MqttProperties::decode(&[0x05, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, 0x01])
        });
        assert!(result.is_ok());

        match result.unwrap() {
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "mqtt.properties");
                assert_eq!(required, 6);
                assert_eq!(available, 3);
            }
            other => panic!("expected buffer-too-short error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_property_identifier_errors_without_panic() {
        let result = std::panic::catch_unwind(|| MqttProperties::decode(&[0x01, 0x7f]));
        assert!(result.is_ok());

        match result.unwrap() {
            Err(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "mqtt.property.identifier");
                assert!(reason.contains("unknown"));
            }
            other => panic!("expected invalid-field-value error, got {other:?}"),
        }
    }
}
