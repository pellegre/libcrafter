//! MQTT fixed-header control packet type helpers.

use crate::error::{CrafterError, Result};

use super::constants::{
    MQTT_FLAGS_CONNACK, MQTT_FLAGS_CONNECT, MQTT_FLAGS_DISCONNECT, MQTT_FLAGS_PINGREQ,
    MQTT_FLAGS_PINGRESP, MQTT_FLAGS_PUBACK, MQTT_FLAGS_PUBCOMP, MQTT_FLAGS_PUBREC,
    MQTT_FLAGS_PUBREL, MQTT_FLAGS_SUBACK, MQTT_FLAGS_SUBSCRIBE, MQTT_FLAGS_UNSUBACK,
    MQTT_FLAGS_UNSUBSCRIBE, MQTT_TYPE_CONNACK, MQTT_TYPE_CONNECT, MQTT_TYPE_DISCONNECT,
    MQTT_TYPE_PINGREQ, MQTT_TYPE_PINGRESP, MQTT_TYPE_PUBACK, MQTT_TYPE_PUBCOMP, MQTT_TYPE_PUBLISH,
    MQTT_TYPE_PUBREC, MQTT_TYPE_PUBREL, MQTT_TYPE_SUBACK, MQTT_TYPE_SUBSCRIBE, MQTT_TYPE_UNSUBACK,
    MQTT_TYPE_UNSUBSCRIBE,
};

/// MQTT 3.1.1 fixed-header control packet type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MqttControlPacketType {
    /// Client request to connect to a server.
    Connect,
    /// Server acknowledgement of a connection request.
    Connack,
    /// Publish message.
    Publish,
    /// QoS 1 publish acknowledgement.
    Puback,
    /// QoS 2 publish received.
    Pubrec,
    /// QoS 2 publish release.
    Pubrel,
    /// QoS 2 publish complete.
    Pubcomp,
    /// Client subscribe request.
    Subscribe,
    /// Server subscribe acknowledgement.
    Suback,
    /// Client unsubscribe request.
    Unsubscribe,
    /// Server unsubscribe acknowledgement.
    Unsuback,
    /// Ping request.
    Pingreq,
    /// Ping response.
    Pingresp,
    /// Client disconnect notification.
    Disconnect,
}

impl MqttControlPacketType {
    /// Return the MQTT control packet type value before it is shifted into the
    /// fixed header's high nibble.
    pub const fn type_value(self) -> u8 {
        match self {
            Self::Connect => MQTT_TYPE_CONNECT,
            Self::Connack => MQTT_TYPE_CONNACK,
            Self::Publish => MQTT_TYPE_PUBLISH,
            Self::Puback => MQTT_TYPE_PUBACK,
            Self::Pubrec => MQTT_TYPE_PUBREC,
            Self::Pubrel => MQTT_TYPE_PUBREL,
            Self::Pubcomp => MQTT_TYPE_PUBCOMP,
            Self::Subscribe => MQTT_TYPE_SUBSCRIBE,
            Self::Suback => MQTT_TYPE_SUBACK,
            Self::Unsubscribe => MQTT_TYPE_UNSUBSCRIBE,
            Self::Unsuback => MQTT_TYPE_UNSUBACK,
            Self::Pingreq => MQTT_TYPE_PINGREQ,
            Self::Pingresp => MQTT_TYPE_PINGRESP,
            Self::Disconnect => MQTT_TYPE_DISCONNECT,
        }
    }

    /// Return the MQTT control packet type positioned in the fixed header's
    /// high nibble.
    pub const fn high_nibble(self) -> u8 {
        self.type_value() << 4
    }

    /// Parse a control packet type value after extracting the fixed header's
    /// high nibble.
    pub fn from_type_value(value: u8) -> Result<Self> {
        match value {
            MQTT_TYPE_CONNECT => Ok(Self::Connect),
            MQTT_TYPE_CONNACK => Ok(Self::Connack),
            MQTT_TYPE_PUBLISH => Ok(Self::Publish),
            MQTT_TYPE_PUBACK => Ok(Self::Puback),
            MQTT_TYPE_PUBREC => Ok(Self::Pubrec),
            MQTT_TYPE_PUBREL => Ok(Self::Pubrel),
            MQTT_TYPE_PUBCOMP => Ok(Self::Pubcomp),
            MQTT_TYPE_SUBSCRIBE => Ok(Self::Subscribe),
            MQTT_TYPE_SUBACK => Ok(Self::Suback),
            MQTT_TYPE_UNSUBSCRIBE => Ok(Self::Unsubscribe),
            MQTT_TYPE_UNSUBACK => Ok(Self::Unsuback),
            MQTT_TYPE_PINGREQ => Ok(Self::Pingreq),
            MQTT_TYPE_PINGRESP => Ok(Self::Pingresp),
            MQTT_TYPE_DISCONNECT => Ok(Self::Disconnect),
            _ => Err(CrafterError::invalid_field_value(
                "mqtt.fixed_header.control_packet_type",
                "control packet type must be 1..=14",
            )),
        }
    }

    /// Parse the control packet type from a complete fixed-header first byte.
    pub fn from_fixed_header_byte(byte: u8) -> Result<Self> {
        Self::from_type_value(byte >> 4)
    }

    /// Return the default fixed-header flag nibble for this control packet type.
    pub const fn default_flags(self) -> u8 {
        match self {
            Self::Connect => MQTT_FLAGS_CONNECT,
            Self::Connack => MQTT_FLAGS_CONNACK,
            Self::Publish => 0x0,
            Self::Puback => MQTT_FLAGS_PUBACK,
            Self::Pubrec => MQTT_FLAGS_PUBREC,
            Self::Pubrel => MQTT_FLAGS_PUBREL,
            Self::Pubcomp => MQTT_FLAGS_PUBCOMP,
            Self::Subscribe => MQTT_FLAGS_SUBSCRIBE,
            Self::Suback => MQTT_FLAGS_SUBACK,
            Self::Unsubscribe => MQTT_FLAGS_UNSUBSCRIBE,
            Self::Unsuback => MQTT_FLAGS_UNSUBACK,
            Self::Pingreq => MQTT_FLAGS_PINGREQ,
            Self::Pingresp => MQTT_FLAGS_PINGRESP,
            Self::Disconnect => MQTT_FLAGS_DISCONNECT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TYPES: &[(MqttControlPacketType, u8, u8)] = &[
        (
            MqttControlPacketType::Connect,
            MQTT_TYPE_CONNECT,
            MQTT_FLAGS_CONNECT,
        ),
        (
            MqttControlPacketType::Connack,
            MQTT_TYPE_CONNACK,
            MQTT_FLAGS_CONNACK,
        ),
        (MqttControlPacketType::Publish, MQTT_TYPE_PUBLISH, 0x0),
        (
            MqttControlPacketType::Puback,
            MQTT_TYPE_PUBACK,
            MQTT_FLAGS_PUBACK,
        ),
        (
            MqttControlPacketType::Pubrec,
            MQTT_TYPE_PUBREC,
            MQTT_FLAGS_PUBREC,
        ),
        (
            MqttControlPacketType::Pubrel,
            MQTT_TYPE_PUBREL,
            MQTT_FLAGS_PUBREL,
        ),
        (
            MqttControlPacketType::Pubcomp,
            MQTT_TYPE_PUBCOMP,
            MQTT_FLAGS_PUBCOMP,
        ),
        (
            MqttControlPacketType::Subscribe,
            MQTT_TYPE_SUBSCRIBE,
            MQTT_FLAGS_SUBSCRIBE,
        ),
        (
            MqttControlPacketType::Suback,
            MQTT_TYPE_SUBACK,
            MQTT_FLAGS_SUBACK,
        ),
        (
            MqttControlPacketType::Unsubscribe,
            MQTT_TYPE_UNSUBSCRIBE,
            MQTT_FLAGS_UNSUBSCRIBE,
        ),
        (
            MqttControlPacketType::Unsuback,
            MQTT_TYPE_UNSUBACK,
            MQTT_FLAGS_UNSUBACK,
        ),
        (
            MqttControlPacketType::Pingreq,
            MQTT_TYPE_PINGREQ,
            MQTT_FLAGS_PINGREQ,
        ),
        (
            MqttControlPacketType::Pingresp,
            MQTT_TYPE_PINGRESP,
            MQTT_FLAGS_PINGRESP,
        ),
        (
            MqttControlPacketType::Disconnect,
            MQTT_TYPE_DISCONNECT,
            MQTT_FLAGS_DISCONNECT,
        ),
    ];

    #[test]
    fn type_values_round_trip() {
        for &(packet_type, value, _) in ALL_TYPES {
            assert_eq!(packet_type.type_value(), value);
            assert_eq!(packet_type.high_nibble(), value << 4);
            assert_eq!(
                MqttControlPacketType::from_type_value(value).unwrap(),
                packet_type
            );
            assert_eq!(
                MqttControlPacketType::from_fixed_header_byte(value << 4).unwrap(),
                packet_type
            );
        }
    }

    #[test]
    fn default_flags_match_fixed_header_table() {
        for &(packet_type, _, flags) in ALL_TYPES {
            assert_eq!(packet_type.default_flags(), flags);
        }
    }

    #[test]
    fn out_of_range_type_values_error() {
        for value in [0, 15, 16, u8::MAX] {
            assert!(MqttControlPacketType::from_type_value(value).is_err());
        }
    }
}
