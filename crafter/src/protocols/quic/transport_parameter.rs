//! QUIC transport-parameter tuple helpers.
//!
//! RFC 9000 carries QUIC transport parameters as a sequence of
//! `(Parameter ID, Length, Value)` tuples where the first two fields are QUIC
//! variable-length integers. This module keeps that tuple layer
//! byte-preserving: value-specific interpretation and endpoint negotiation
//! policy are added by later steps.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::constants::quic_version_label;
use super::frame::QUIC_STATELESS_RESET_TOKEN_LEN;
use super::QuicConnectionId;
use super::{varint::encoded_len_from_prefix, QuicVarInt};
use crate::protocols::transport::common::hex_bytes;
use crate::{CrafterError, Result};

/// Default-eligible QUIC transport parameters selected from the reviewed
/// registry evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicKnownTransportParameter {
    /// `original_destination_connection_id` (`0x00`).
    OriginalDestinationConnectionId,
    /// `max_idle_timeout` (`0x01`).
    MaxIdleTimeout,
    /// `stateless_reset_token` (`0x02`).
    StatelessResetToken,
    /// `max_udp_payload_size` (`0x03`).
    MaxUdpPayloadSize,
    /// `initial_max_data` (`0x04`).
    InitialMaxData,
    /// `initial_max_stream_data_bidi_local` (`0x05`).
    InitialMaxStreamDataBidiLocal,
    /// `initial_max_stream_data_bidi_remote` (`0x06`).
    InitialMaxStreamDataBidiRemote,
    /// `initial_max_stream_data_uni` (`0x07`).
    InitialMaxStreamDataUni,
    /// `initial_max_streams_bidi` (`0x08`).
    InitialMaxStreamsBidi,
    /// `initial_max_streams_uni` (`0x09`).
    InitialMaxStreamsUni,
    /// `ack_delay_exponent` (`0x0a`).
    AckDelayExponent,
    /// `max_ack_delay` (`0x0b`).
    MaxAckDelay,
    /// `disable_active_migration` (`0x0c`).
    DisableActiveMigration,
    /// `preferred_address` (`0x0d`).
    PreferredAddress,
    /// `active_connection_id_limit` (`0x0e`).
    ActiveConnectionIdLimit,
    /// `initial_source_connection_id` (`0x0f`).
    InitialSourceConnectionId,
    /// `retry_source_connection_id` (`0x10`).
    RetrySourceConnectionId,
    /// `version_information` (`0x11`, RFC 9368).
    VersionInformation,
    /// `max_datagram_frame_size` (`0x20`, RFC 9221).
    MaxDatagramFrameSize,
    /// `grease_quic_bit` (`0x2ab2`, RFC 9287).
    GreaseQuicBit,
}

impl QuicKnownTransportParameter {
    /// Return the numeric transport-parameter identifier.
    pub const fn id(self) -> QuicVarInt {
        QuicVarInt::from_u64_unchecked(match self {
            Self::OriginalDestinationConnectionId => 0x00,
            Self::MaxIdleTimeout => 0x01,
            Self::StatelessResetToken => 0x02,
            Self::MaxUdpPayloadSize => 0x03,
            Self::InitialMaxData => 0x04,
            Self::InitialMaxStreamDataBidiLocal => 0x05,
            Self::InitialMaxStreamDataBidiRemote => 0x06,
            Self::InitialMaxStreamDataUni => 0x07,
            Self::InitialMaxStreamsBidi => 0x08,
            Self::InitialMaxStreamsUni => 0x09,
            Self::AckDelayExponent => 0x0a,
            Self::MaxAckDelay => 0x0b,
            Self::DisableActiveMigration => 0x0c,
            Self::PreferredAddress => 0x0d,
            Self::ActiveConnectionIdLimit => 0x0e,
            Self::InitialSourceConnectionId => 0x0f,
            Self::RetrySourceConnectionId => 0x10,
            Self::VersionInformation => 0x11,
            Self::MaxDatagramFrameSize => 0x20,
            Self::GreaseQuicBit => 0x2ab2,
        })
    }

    /// Return the registry name used in summaries and inspection output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::OriginalDestinationConnectionId => "original_destination_connection_id",
            Self::MaxIdleTimeout => "max_idle_timeout",
            Self::StatelessResetToken => "stateless_reset_token",
            Self::MaxUdpPayloadSize => "max_udp_payload_size",
            Self::InitialMaxData => "initial_max_data",
            Self::InitialMaxStreamDataBidiLocal => "initial_max_stream_data_bidi_local",
            Self::InitialMaxStreamDataBidiRemote => "initial_max_stream_data_bidi_remote",
            Self::InitialMaxStreamDataUni => "initial_max_stream_data_uni",
            Self::InitialMaxStreamsBidi => "initial_max_streams_bidi",
            Self::InitialMaxStreamsUni => "initial_max_streams_uni",
            Self::AckDelayExponent => "ack_delay_exponent",
            Self::MaxAckDelay => "max_ack_delay",
            Self::DisableActiveMigration => "disable_active_migration",
            Self::PreferredAddress => "preferred_address",
            Self::ActiveConnectionIdLimit => "active_connection_id_limit",
            Self::InitialSourceConnectionId => "initial_source_connection_id",
            Self::RetrySourceConnectionId => "retry_source_connection_id",
            Self::VersionInformation => "version_information",
            Self::MaxDatagramFrameSize => "max_datagram_frame_size",
            Self::GreaseQuicBit => "grease_quic_bit",
        }
    }

    /// Map a transport-parameter identifier to a selected known type.
    pub const fn from_id(id: QuicVarInt) -> Option<Self> {
        match id.value() {
            0x00 => Some(Self::OriginalDestinationConnectionId),
            0x01 => Some(Self::MaxIdleTimeout),
            0x02 => Some(Self::StatelessResetToken),
            0x03 => Some(Self::MaxUdpPayloadSize),
            0x04 => Some(Self::InitialMaxData),
            0x05 => Some(Self::InitialMaxStreamDataBidiLocal),
            0x06 => Some(Self::InitialMaxStreamDataBidiRemote),
            0x07 => Some(Self::InitialMaxStreamDataUni),
            0x08 => Some(Self::InitialMaxStreamsBidi),
            0x09 => Some(Self::InitialMaxStreamsUni),
            0x0a => Some(Self::AckDelayExponent),
            0x0b => Some(Self::MaxAckDelay),
            0x0c => Some(Self::DisableActiveMigration),
            0x0d => Some(Self::PreferredAddress),
            0x0e => Some(Self::ActiveConnectionIdLimit),
            0x0f => Some(Self::InitialSourceConnectionId),
            0x10 => Some(Self::RetrySourceConnectionId),
            0x11 => Some(Self::VersionInformation),
            0x20 => Some(Self::MaxDatagramFrameSize),
            0x2ab2 => Some(Self::GreaseQuicBit),
            _ => None,
        }
    }
}

/// Known transport parameters whose value format is one QUIC varint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicIntegerTransportParameter {
    /// `max_idle_timeout` (`0x01`).
    MaxIdleTimeout,
    /// `max_udp_payload_size` (`0x03`).
    MaxUdpPayloadSize,
    /// `initial_max_data` (`0x04`).
    InitialMaxData,
    /// `initial_max_stream_data_bidi_local` (`0x05`).
    InitialMaxStreamDataBidiLocal,
    /// `initial_max_stream_data_bidi_remote` (`0x06`).
    InitialMaxStreamDataBidiRemote,
    /// `initial_max_stream_data_uni` (`0x07`).
    InitialMaxStreamDataUni,
    /// `initial_max_streams_bidi` (`0x08`).
    InitialMaxStreamsBidi,
    /// `initial_max_streams_uni` (`0x09`).
    InitialMaxStreamsUni,
    /// `ack_delay_exponent` (`0x0a`).
    AckDelayExponent,
    /// `max_ack_delay` (`0x0b`).
    MaxAckDelay,
    /// `active_connection_id_limit` (`0x0e`).
    ActiveConnectionIdLimit,
    /// `max_datagram_frame_size` (`0x20`).
    MaxDatagramFrameSize,
}

impl QuicIntegerTransportParameter {
    /// Return the corresponding known transport-parameter registry row.
    pub const fn known_parameter(self) -> QuicKnownTransportParameter {
        match self {
            Self::MaxIdleTimeout => QuicKnownTransportParameter::MaxIdleTimeout,
            Self::MaxUdpPayloadSize => QuicKnownTransportParameter::MaxUdpPayloadSize,
            Self::InitialMaxData => QuicKnownTransportParameter::InitialMaxData,
            Self::InitialMaxStreamDataBidiLocal => {
                QuicKnownTransportParameter::InitialMaxStreamDataBidiLocal
            }
            Self::InitialMaxStreamDataBidiRemote => {
                QuicKnownTransportParameter::InitialMaxStreamDataBidiRemote
            }
            Self::InitialMaxStreamDataUni => QuicKnownTransportParameter::InitialMaxStreamDataUni,
            Self::InitialMaxStreamsBidi => QuicKnownTransportParameter::InitialMaxStreamsBidi,
            Self::InitialMaxStreamsUni => QuicKnownTransportParameter::InitialMaxStreamsUni,
            Self::AckDelayExponent => QuicKnownTransportParameter::AckDelayExponent,
            Self::MaxAckDelay => QuicKnownTransportParameter::MaxAckDelay,
            Self::ActiveConnectionIdLimit => QuicKnownTransportParameter::ActiveConnectionIdLimit,
            Self::MaxDatagramFrameSize => QuicKnownTransportParameter::MaxDatagramFrameSize,
        }
    }

    /// Return the numeric transport-parameter identifier.
    pub const fn id(self) -> QuicVarInt {
        self.known_parameter().id()
    }

    /// Return the registry name used in summaries and validation output.
    pub const fn name(self) -> &'static str {
        self.known_parameter().name()
    }

    /// Map a selected known transport-parameter row to an integer parameter.
    pub const fn from_known(known: QuicKnownTransportParameter) -> Option<Self> {
        match known {
            QuicKnownTransportParameter::MaxIdleTimeout => Some(Self::MaxIdleTimeout),
            QuicKnownTransportParameter::MaxUdpPayloadSize => Some(Self::MaxUdpPayloadSize),
            QuicKnownTransportParameter::InitialMaxData => Some(Self::InitialMaxData),
            QuicKnownTransportParameter::InitialMaxStreamDataBidiLocal => {
                Some(Self::InitialMaxStreamDataBidiLocal)
            }
            QuicKnownTransportParameter::InitialMaxStreamDataBidiRemote => {
                Some(Self::InitialMaxStreamDataBidiRemote)
            }
            QuicKnownTransportParameter::InitialMaxStreamDataUni => {
                Some(Self::InitialMaxStreamDataUni)
            }
            QuicKnownTransportParameter::InitialMaxStreamsBidi => Some(Self::InitialMaxStreamsBidi),
            QuicKnownTransportParameter::InitialMaxStreamsUni => Some(Self::InitialMaxStreamsUni),
            QuicKnownTransportParameter::AckDelayExponent => Some(Self::AckDelayExponent),
            QuicKnownTransportParameter::MaxAckDelay => Some(Self::MaxAckDelay),
            QuicKnownTransportParameter::ActiveConnectionIdLimit => {
                Some(Self::ActiveConnectionIdLimit)
            }
            QuicKnownTransportParameter::MaxDatagramFrameSize => Some(Self::MaxDatagramFrameSize),
            _ => None,
        }
    }

    /// Map a transport-parameter identifier to an integer parameter.
    pub const fn from_id(id: QuicVarInt) -> Option<Self> {
        match QuicKnownTransportParameter::from_id(id) {
            Some(known) => Self::from_known(known),
            None => None,
        }
    }

    /// Return the documented default value when the notes record one.
    pub const fn default_value(self) -> Option<QuicVarInt> {
        match self {
            Self::MaxIdleTimeout => Some(QuicVarInt::from_u64_unchecked(0)),
            Self::MaxUdpPayloadSize => Some(QuicVarInt::from_u64_unchecked(65_527)),
            Self::AckDelayExponent => Some(QuicVarInt::from_u64_unchecked(3)),
            Self::MaxAckDelay => Some(QuicVarInt::from_u64_unchecked(25)),
            Self::ActiveConnectionIdLimit => Some(QuicVarInt::from_u64_unchecked(2)),
            Self::MaxDatagramFrameSize => Some(QuicVarInt::from_u64_unchecked(0)),
            _ => None,
        }
    }

    /// Return an endpoint-validation finding for byte-complete values whose
    /// protocol policy is invalid. These are not decode truncation errors.
    pub const fn validation_finding(
        self,
        value: QuicVarInt,
    ) -> Option<QuicIntegerTransportParameterValidation> {
        match self {
            Self::MaxUdpPayloadSize if value.value() < 1200 => {
                Some(QuicIntegerTransportParameterValidation::MaxUdpPayloadSizeBelowMinimum)
            }
            Self::InitialMaxStreamsBidi | Self::InitialMaxStreamsUni
                if value.value() > (1u64 << 60) =>
            {
                Some(QuicIntegerTransportParameterValidation::InitialMaxStreamsExceedsLimit)
            }
            Self::AckDelayExponent if value.value() > 20 => {
                Some(QuicIntegerTransportParameterValidation::AckDelayExponentExceedsLimit)
            }
            Self::MaxAckDelay if value.value() >= (1u64 << 14) => {
                Some(QuicIntegerTransportParameterValidation::MaxAckDelayExceedsLimit)
            }
            Self::ActiveConnectionIdLimit if value.value() < 2 => {
                Some(QuicIntegerTransportParameterValidation::ActiveConnectionIdLimitBelowMinimum)
            }
            _ => None,
        }
    }
}

/// Endpoint-validation finding for a byte-complete integer transport parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicIntegerTransportParameterValidation {
    /// `max_udp_payload_size` is below 1200.
    MaxUdpPayloadSizeBelowMinimum,
    /// `initial_max_streams_bidi` or `initial_max_streams_uni` is above `2^60`.
    InitialMaxStreamsExceedsLimit,
    /// `ack_delay_exponent` is above 20.
    AckDelayExponentExceedsLimit,
    /// `max_ack_delay` is greater than or equal to `2^14`.
    MaxAckDelayExceedsLimit,
    /// `active_connection_id_limit` is below 2.
    ActiveConnectionIdLimitBelowMinimum,
}

impl QuicIntegerTransportParameterValidation {
    /// Stable validation label for summaries or agent diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::MaxUdpPayloadSizeBelowMinimum => "max_udp_payload_size_below_1200",
            Self::InitialMaxStreamsExceedsLimit => "initial_max_streams_above_2^60",
            Self::AckDelayExponentExceedsLimit => "ack_delay_exponent_above_20",
            Self::MaxAckDelayExceedsLimit => "max_ack_delay_at_or_above_2^14",
            Self::ActiveConnectionIdLimitBelowMinimum => "active_connection_id_limit_below_2",
        }
    }
}

/// Known transport parameters whose value format is raw connection ID bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicConnectionIdTransportParameter {
    /// `original_destination_connection_id` (`0x00`).
    OriginalDestinationConnectionId,
    /// `initial_source_connection_id` (`0x0f`).
    InitialSourceConnectionId,
    /// `retry_source_connection_id` (`0x10`).
    RetrySourceConnectionId,
}

impl QuicConnectionIdTransportParameter {
    /// Return the corresponding known transport-parameter registry row.
    pub const fn known_parameter(self) -> QuicKnownTransportParameter {
        match self {
            Self::OriginalDestinationConnectionId => {
                QuicKnownTransportParameter::OriginalDestinationConnectionId
            }
            Self::InitialSourceConnectionId => {
                QuicKnownTransportParameter::InitialSourceConnectionId
            }
            Self::RetrySourceConnectionId => QuicKnownTransportParameter::RetrySourceConnectionId,
        }
    }

    /// Return the numeric transport-parameter identifier.
    pub const fn id(self) -> QuicVarInt {
        self.known_parameter().id()
    }

    /// Return the registry name used in summaries and inspection output.
    pub const fn name(self) -> &'static str {
        self.known_parameter().name()
    }

    /// Map a selected known transport-parameter row to a connection-ID parameter.
    pub const fn from_known(known: QuicKnownTransportParameter) -> Option<Self> {
        match known {
            QuicKnownTransportParameter::OriginalDestinationConnectionId => {
                Some(Self::OriginalDestinationConnectionId)
            }
            QuicKnownTransportParameter::InitialSourceConnectionId => {
                Some(Self::InitialSourceConnectionId)
            }
            QuicKnownTransportParameter::RetrySourceConnectionId => {
                Some(Self::RetrySourceConnectionId)
            }
            _ => None,
        }
    }

    /// Map a transport-parameter identifier to a connection-ID parameter.
    pub const fn from_id(id: QuicVarInt) -> Option<Self> {
        match QuicKnownTransportParameter::from_id(id) {
            Some(known) => Self::from_known(known),
            None => None,
        }
    }
}

/// Fixed-size QUIC Stateless Reset Token carried by transport parameters and
/// NEW_CONNECTION_ID frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuicStatelessResetToken {
    bytes: [u8; QUIC_STATELESS_RESET_TOKEN_LEN],
}

impl QuicStatelessResetToken {
    /// Construct a Stateless Reset Token from exactly 16 bytes.
    pub const fn new(bytes: [u8; QUIC_STATELESS_RESET_TOKEN_LEN]) -> Self {
        Self { bytes }
    }

    /// Decode a Stateless Reset Token from a byte slice that must be exactly
    /// 16 bytes long.
    pub fn try_from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        decode_stateless_reset_token_value(bytes.as_ref())
    }

    /// Borrow the token bytes.
    pub const fn as_bytes(&self) -> &[u8; QUIC_STATELESS_RESET_TOKEN_LEN] {
        &self.bytes
    }

    /// Return the token as lowercase hexadecimal without separators.
    pub fn to_hex(&self) -> String {
        let mut output = String::with_capacity(QUIC_STATELESS_RESET_TOKEN_LEN * 2);
        for byte in self.bytes {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }

    /// Return the token as lowercase hexadecimal with spaces between octets.
    pub fn to_spaced_hex(&self) -> String {
        hex_bytes(&self.bytes)
    }
}

impl From<[u8; QUIC_STATELESS_RESET_TOKEN_LEN]> for QuicStatelessResetToken {
    fn from(bytes: [u8; QUIC_STATELESS_RESET_TOKEN_LEN]) -> Self {
        Self::new(bytes)
    }
}

impl AsRef<[u8]> for QuicStatelessResetToken {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Parsed or buildable QUIC `preferred_address` transport parameter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicPreferredAddress {
    ipv4_address: Ipv4Addr,
    ipv4_port: u16,
    ipv6_address: Ipv6Addr,
    ipv6_port: u16,
    connection_id_length: Option<u8>,
    connection_id: QuicConnectionId,
    stateless_reset_token: QuicStatelessResetToken,
}

impl QuicPreferredAddress {
    /// Construct a preferred address value. The Connection ID Length byte is
    /// auto-filled from the connection ID unless overridden.
    pub fn new(
        ipv4_address: Ipv4Addr,
        ipv4_port: u16,
        ipv6_address: Ipv6Addr,
        ipv6_port: u16,
        connection_id: QuicConnectionId,
        stateless_reset_token: QuicStatelessResetToken,
    ) -> Self {
        Self {
            ipv4_address,
            ipv4_port,
            ipv6_address,
            ipv6_port,
            connection_id_length: None,
            connection_id,
            stateless_reset_token,
        }
    }

    /// Preserve an explicit Connection ID Length byte, even when it does not
    /// match the stored connection ID bytes.
    pub fn with_connection_id_length(mut self, connection_id_length: u8) -> Self {
        self.connection_id_length = Some(connection_id_length);
        self
    }

    /// Return the IPv4 address field.
    pub const fn ipv4_address(&self) -> Ipv4Addr {
        self.ipv4_address
    }

    /// Return the IPv4 port field.
    pub const fn ipv4_port(&self) -> u16 {
        self.ipv4_port
    }

    /// Return the IPv6 address field.
    pub const fn ipv6_address(&self) -> Ipv6Addr {
        self.ipv6_address
    }

    /// Return the IPv6 port field.
    pub const fn ipv6_port(&self) -> u16 {
        self.ipv6_port
    }

    /// Return a caller-pinned Connection ID Length byte when present.
    pub const fn connection_id_length_override(&self) -> Option<u8> {
        self.connection_id_length
    }

    /// Return the advertised Connection ID Length byte.
    pub fn connection_id_length(&self) -> Result<u8> {
        if let Some(connection_id_length) = self.connection_id_length {
            return Ok(connection_id_length);
        }
        u8::try_from(self.connection_id.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "quic.transport_parameter.preferred_address.connection_id_length",
                "preferred_address connection ID length exceeds u8",
            )
        })
    }

    /// Borrow the preferred-address connection ID bytes.
    pub fn connection_id(&self) -> &QuicConnectionId {
        &self.connection_id
    }

    /// Borrow the 16-byte Stateless Reset Token.
    pub const fn stateless_reset_token(&self) -> &QuicStatelessResetToken {
        &self.stateless_reset_token
    }

    /// Return endpoint-validation findings for byte-complete preferred-address
    /// values. These facts do not make tuple parsing fail.
    pub fn validation_findings(&self) -> Vec<QuicPreferredAddressValidation> {
        let mut findings = Vec::new();
        if self.connection_id.is_empty() {
            findings.push(QuicPreferredAddressValidation::ZeroLengthConnectionId);
        }
        if self.connection_id.len() > 20 {
            findings.push(QuicPreferredAddressValidation::ConnectionIdExceedsV1V2Limit);
        }
        if self.ipv4_address.is_unspecified() && self.ipv4_port == 0 {
            findings.push(QuicPreferredAddressValidation::Ipv4AddressFamilyOmitted);
        }
        if self.ipv6_address.is_unspecified() && self.ipv6_port == 0 {
            findings.push(QuicPreferredAddressValidation::Ipv6AddressFamilyOmitted);
        }
        findings
    }

    /// Append the preferred-address value encoding.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.ipv4_address.octets());
        out.extend_from_slice(&self.ipv4_port.to_be_bytes());
        out.extend_from_slice(&self.ipv6_address.octets());
        out.extend_from_slice(&self.ipv6_port.to_be_bytes());
        out.push(self.connection_id_length()?);
        out.extend_from_slice(self.connection_id.as_bytes());
        out.extend_from_slice(self.stateless_reset_token.as_bytes());
        Ok(())
    }

    /// Return the preferred-address value encoding as a new vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(41 + self.connection_id.len());
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a preferred-address value.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        decode_preferred_address_value(bytes.as_ref())
    }

    /// Stable preferred-address summary for packet inspection.
    pub fn summary(&self) -> String {
        format!(
            "ipv4={}:{} ipv6=[{}]:{} connection_id_len={} connection_id={}",
            self.ipv4_address,
            self.ipv4_port,
            self.ipv6_address,
            self.ipv6_port,
            self.connection_id_length
                .map(usize::from)
                .unwrap_or_else(|| self.connection_id.len()),
            self.connection_id.to_hex(),
        )
    }

    /// Stable field/value pairs for preferred-address inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let findings = self
            .validation_findings()
            .into_iter()
            .map(|finding| finding.label())
            .collect::<Vec<_>>()
            .join(",");
        vec![
            ("preferred_ipv4_address", self.ipv4_address.to_string()),
            ("preferred_ipv4_port", self.ipv4_port.to_string()),
            ("preferred_ipv6_address", self.ipv6_address.to_string()),
            ("preferred_ipv6_port", self.ipv6_port.to_string()),
            (
                "preferred_connection_id_length",
                self.connection_id_length
                    .map(|len| len.to_string())
                    .unwrap_or_else(|| self.connection_id.len().to_string()),
            ),
            ("preferred_connection_id", self.connection_id.to_hex()),
            (
                "preferred_stateless_reset_token",
                self.stateless_reset_token.to_spaced_hex(),
            ),
            (
                "preferred_validation",
                if findings.is_empty() {
                    "ok".to_string()
                } else {
                    findings
                },
            ),
        ]
    }
}

/// Endpoint-validation finding for a byte-complete preferred-address value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPreferredAddressValidation {
    /// Preferred-address connection IDs are endpoint-invalid when zero length.
    ZeroLengthConnectionId,
    /// Preferred-address connection IDs are endpoint-invalid above 20 bytes.
    ConnectionIdExceedsV1V2Limit,
    /// The IPv4 address family is omitted via `0.0.0.0:0`.
    Ipv4AddressFamilyOmitted,
    /// The IPv6 address family is omitted via `[::]:0`.
    Ipv6AddressFamilyOmitted,
}

impl QuicPreferredAddressValidation {
    /// Stable validation label for summaries or agent diagnostics.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ZeroLengthConnectionId => "preferred_address_zero_length_connection_id",
            Self::ConnectionIdExceedsV1V2Limit => "preferred_address_connection_id_above_20",
            Self::Ipv4AddressFamilyOmitted => "preferred_address_ipv4_omitted",
            Self::Ipv6AddressFamilyOmitted => "preferred_address_ipv6_omitted",
        }
    }
}

/// Parsed or buildable `version_information` transport parameter value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicVersionInformation {
    chosen_version: u32,
    available_versions: Vec<u32>,
}

impl QuicVersionInformation {
    /// Construct a compatible version negotiation value.
    pub fn new(chosen_version: u32, available_versions: impl IntoIterator<Item = u32>) -> Self {
        Self {
            chosen_version,
            available_versions: available_versions.into_iter().collect(),
        }
    }

    /// Return the chosen version.
    pub const fn chosen_version(&self) -> u32 {
        self.chosen_version
    }

    /// Borrow available versions in wire order.
    pub fn available_versions(&self) -> &[u32] {
        &self.available_versions
    }

    /// Return endpoint-validation findings for byte-complete version
    /// information values. These facts do not make tuple parsing fail.
    pub fn validation_findings(&self) -> Vec<QuicVersionInformationValidation> {
        let mut findings = Vec::new();
        if self.chosen_version == 0 {
            findings.push(QuicVersionInformationValidation::ChosenVersionZero);
        }
        for (index, version) in self.available_versions.iter().copied().enumerate() {
            if version == 0 {
                findings.push(QuicVersionInformationValidation::AvailableVersionZero { index });
            }
        }
        findings
    }

    /// Append the version-information value encoding.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.chosen_version.to_be_bytes());
        for version in &self.available_versions {
            out.extend_from_slice(&version.to_be_bytes());
        }
    }

    /// Return the version-information value encoding as a new vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.available_versions.len() * 4);
        self.encode(&mut out);
        out
    }

    /// Decode a version-information value.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        decode_version_information_value(bytes.as_ref())
    }

    /// Stable version-information summary for packet inspection.
    pub fn summary(&self) -> String {
        format!(
            "chosen_version={} available_versions={}",
            format_quic_version_hex(self.chosen_version),
            format_quic_version_list(&self.available_versions)
        )
    }

    /// Stable field/value pairs for version-information inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let findings = self
            .validation_findings()
            .into_iter()
            .map(|finding| finding.label().to_string())
            .collect::<Vec<_>>()
            .join(",");
        vec![
            (
                "version_information_chosen_version",
                format_quic_version_hex(self.chosen_version),
            ),
            (
                "version_information_chosen_version_label",
                quic_version_label(self.chosen_version),
            ),
            (
                "version_information_available_versions",
                format_quic_version_list(&self.available_versions),
            ),
            (
                "version_information_validation",
                if findings.is_empty() {
                    "ok".to_string()
                } else {
                    findings
                },
            ),
        ]
    }
}

/// Endpoint-validation finding for a byte-complete version-information value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicVersionInformationValidation {
    /// The chosen version is zero.
    ChosenVersionZero,
    /// An available-version entry is zero.
    AvailableVersionZero {
        /// Zero-based index within the Available Versions list.
        index: usize,
    },
}

impl QuicVersionInformationValidation {
    /// Stable validation label for summaries or agent diagnostics.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::ChosenVersionZero => "version_information_chosen_version_zero",
            Self::AvailableVersionZero { .. } => "version_information_available_version_zero",
        }
    }
}

/// Broad transport-parameter identifier classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicTransportParameterKind {
    /// A selected permanent/default-eligible registry row.
    Known(QuicKnownTransportParameter),
    /// A reserved identifier matching the `31 * N + 27` grease pattern.
    Grease,
    /// A byte-complete identifier outside the selected known set.
    Unknown,
    /// No identifier was supplied yet.
    Unset,
}

impl QuicTransportParameterKind {
    /// Stable kind label for summaries and inspection output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Known(known) => known.name(),
            Self::Grease => "grease",
            Self::Unknown => "unknown",
            Self::Unset => "unset",
        }
    }
}

/// Return true when an identifier matches the RFC 9000 transport-parameter
/// grease pattern `31 * N + 27`.
pub const fn is_grease_transport_parameter_id(id: QuicVarInt) -> bool {
    let value = id.value();
    value >= 27 && (value - 27) % 31 == 0
}

/// One duplicate transport-parameter identifier occurrence in a sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicTransportParameterDuplicate {
    identifier: QuicVarInt,
    first_index: usize,
    duplicate_index: usize,
}

impl QuicTransportParameterDuplicate {
    /// Construct a duplicate report from sequence indexes.
    pub const fn new(identifier: QuicVarInt, first_index: usize, duplicate_index: usize) -> Self {
        Self {
            identifier,
            first_index,
            duplicate_index,
        }
    }

    /// Return the duplicated transport-parameter identifier.
    pub const fn identifier(self) -> QuicVarInt {
        self.identifier
    }

    /// Return the first sequence index that used this identifier.
    pub const fn first_index(self) -> usize {
        self.first_index
    }

    /// Return the later sequence index that duplicated this identifier.
    pub const fn duplicate_index(self) -> usize {
        self.duplicate_index
    }
}

/// Raw-preserving QUIC transport parameter tuple.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicTransportParameter {
    identifier: Option<QuicVarInt>,
    value: Vec<u8>,
    identifier_encoded_len: Option<usize>,
    length_encoded_len: Option<usize>,
    declared_value_len: Option<QuicVarInt>,
}

impl QuicTransportParameter {
    /// Preserve a transport parameter identifier and raw value bytes.
    pub fn raw(identifier: QuicVarInt, value: impl AsRef<[u8]>) -> Self {
        Self {
            identifier: Some(identifier),
            value: value.as_ref().to_vec(),
            identifier_encoded_len: None,
            length_encoded_len: None,
            declared_value_len: None,
        }
    }

    /// Construct a selected known transport parameter with raw value bytes.
    pub fn known(known: QuicKnownTransportParameter, value: impl AsRef<[u8]>) -> Self {
        Self::raw(known.id(), value)
    }

    /// Construct an integer-valued transport parameter with a canonical QUIC
    /// varint value.
    pub fn integer(kind: QuicIntegerTransportParameter, value: QuicVarInt) -> Result<Self> {
        let mut encoded = Vec::new();
        value.encode(&mut encoded)?;
        Ok(Self::known(kind.known_parameter(), encoded))
    }

    /// Construct `max_idle_timeout`.
    pub fn max_idle_timeout(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::MaxIdleTimeout, value)
    }

    /// Construct `max_udp_payload_size`.
    pub fn max_udp_payload_size(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::MaxUdpPayloadSize, value)
    }

    /// Construct `initial_max_data`.
    pub fn initial_max_data(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::InitialMaxData, value)
    }

    /// Construct `initial_max_stream_data_bidi_local`.
    pub fn initial_max_stream_data_bidi_local(value: QuicVarInt) -> Result<Self> {
        Self::integer(
            QuicIntegerTransportParameter::InitialMaxStreamDataBidiLocal,
            value,
        )
    }

    /// Construct `initial_max_stream_data_bidi_remote`.
    pub fn initial_max_stream_data_bidi_remote(value: QuicVarInt) -> Result<Self> {
        Self::integer(
            QuicIntegerTransportParameter::InitialMaxStreamDataBidiRemote,
            value,
        )
    }

    /// Construct `initial_max_stream_data_uni`.
    pub fn initial_max_stream_data_uni(value: QuicVarInt) -> Result<Self> {
        Self::integer(
            QuicIntegerTransportParameter::InitialMaxStreamDataUni,
            value,
        )
    }

    /// Construct `initial_max_streams_bidi`.
    pub fn initial_max_streams_bidi(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::InitialMaxStreamsBidi, value)
    }

    /// Construct `initial_max_streams_uni`.
    pub fn initial_max_streams_uni(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::InitialMaxStreamsUni, value)
    }

    /// Construct `ack_delay_exponent`.
    pub fn ack_delay_exponent(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::AckDelayExponent, value)
    }

    /// Construct `max_ack_delay`.
    pub fn max_ack_delay(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::MaxAckDelay, value)
    }

    /// Construct `active_connection_id_limit`.
    pub fn active_connection_id_limit(value: QuicVarInt) -> Result<Self> {
        Self::integer(
            QuicIntegerTransportParameter::ActiveConnectionIdLimit,
            value,
        )
    }

    /// Construct `max_datagram_frame_size`.
    pub fn max_datagram_frame_size(value: QuicVarInt) -> Result<Self> {
        Self::integer(QuicIntegerTransportParameter::MaxDatagramFrameSize, value)
    }

    /// Construct a connection-ID-valued transport parameter.
    pub fn connection_id(
        kind: QuicConnectionIdTransportParameter,
        connection_id: QuicConnectionId,
    ) -> Self {
        Self::known(kind.known_parameter(), connection_id.as_bytes())
    }

    /// Construct `original_destination_connection_id`.
    pub fn original_destination_connection_id(connection_id: QuicConnectionId) -> Self {
        Self::connection_id(
            QuicConnectionIdTransportParameter::OriginalDestinationConnectionId,
            connection_id,
        )
    }

    /// Construct `initial_source_connection_id`.
    pub fn initial_source_connection_id(connection_id: QuicConnectionId) -> Self {
        Self::connection_id(
            QuicConnectionIdTransportParameter::InitialSourceConnectionId,
            connection_id,
        )
    }

    /// Construct `retry_source_connection_id`.
    pub fn retry_source_connection_id(connection_id: QuicConnectionId) -> Self {
        Self::connection_id(
            QuicConnectionIdTransportParameter::RetrySourceConnectionId,
            connection_id,
        )
    }

    /// Construct `stateless_reset_token`.
    pub fn stateless_reset_token(token: impl Into<QuicStatelessResetToken>) -> Self {
        Self::known(
            QuicKnownTransportParameter::StatelessResetToken,
            token.into().as_bytes(),
        )
    }

    /// Construct `preferred_address`.
    pub fn preferred_address(preferred_address: QuicPreferredAddress) -> Result<Self> {
        Ok(Self::known(
            QuicKnownTransportParameter::PreferredAddress,
            preferred_address.encode_to_vec()?,
        ))
    }

    /// Construct `version_information`.
    pub fn version_information(version_information: QuicVersionInformation) -> Self {
        Self::known(
            QuicKnownTransportParameter::VersionInformation,
            version_information.encode_to_vec(),
        )
    }

    /// Preserve a caller-pinned identifier varint width.
    pub fn with_identifier_encoded_len(mut self, len: usize) -> Self {
        self.identifier_encoded_len = Some(len);
        self
    }

    /// Preserve a caller-pinned value-length varint width.
    pub fn with_length_encoded_len(mut self, len: usize) -> Self {
        self.length_encoded_len = Some(len);
        self
    }

    /// Preserve a caller-pinned declared value length.
    pub fn with_declared_value_len(mut self, declared_value_len: QuicVarInt) -> Self {
        self.declared_value_len = Some(declared_value_len);
        self
    }

    /// Return the preserved identifier, if present.
    pub const fn identifier(&self) -> Option<QuicVarInt> {
        self.identifier
    }

    /// Return the selected known parameter type, if this identifier is known.
    pub const fn known_type(&self) -> Option<QuicKnownTransportParameter> {
        match self.identifier {
            Some(identifier) => QuicKnownTransportParameter::from_id(identifier),
            None => None,
        }
    }

    /// Return the integer parameter type when this is a registered integer
    /// parameter.
    pub const fn integer_type(&self) -> Option<QuicIntegerTransportParameter> {
        match self.identifier {
            Some(identifier) => QuicIntegerTransportParameter::from_id(identifier),
            None => None,
        }
    }

    /// Decode the value of a registered integer transport parameter. Unknown,
    /// grease, provisional, and non-integer known parameters return `Ok(None)`.
    pub fn integer_value(&self) -> Result<Option<QuicVarInt>> {
        if self.integer_type().is_none() {
            return Ok(None);
        }
        decode_integer_transport_parameter_value(&self.value).map(Some)
    }

    /// Return the endpoint-validation finding for this integer value, if any.
    pub fn integer_validation_finding(
        &self,
    ) -> Result<Option<QuicIntegerTransportParameterValidation>> {
        let Some(kind) = self.integer_type() else {
            return Ok(None);
        };
        let value = decode_integer_transport_parameter_value(&self.value)?;
        Ok(kind.validation_finding(value))
    }

    /// Return the connection-ID parameter type when this is a registered
    /// connection-ID-valued transport parameter.
    pub const fn connection_id_type(&self) -> Option<QuicConnectionIdTransportParameter> {
        match self.identifier {
            Some(identifier) => QuicConnectionIdTransportParameter::from_id(identifier),
            None => None,
        }
    }

    /// Decode the value of a registered connection-ID transport parameter.
    /// Unknown, grease, provisional, and non-connection-ID known parameters
    /// return `None`.
    pub fn connection_id_value(&self) -> Option<QuicConnectionId> {
        self.connection_id_type()?;
        Some(QuicConnectionId::from_bytes(&self.value))
    }

    /// Return true when this is the registered `stateless_reset_token`
    /// transport parameter.
    pub const fn is_stateless_reset_token(&self) -> bool {
        matches!(
            self.known_type(),
            Some(QuicKnownTransportParameter::StatelessResetToken)
        )
    }

    /// Decode the value of the registered Stateless Reset Token transport
    /// parameter. Unknown, grease, provisional, and other known parameters
    /// return `Ok(None)`.
    pub fn stateless_reset_token_value(&self) -> Result<Option<QuicStatelessResetToken>> {
        if !self.is_stateless_reset_token() {
            return Ok(None);
        }
        decode_stateless_reset_token_value(&self.value).map(Some)
    }

    /// Return true when this is the registered `preferred_address` transport
    /// parameter.
    pub const fn is_preferred_address(&self) -> bool {
        matches!(
            self.known_type(),
            Some(QuicKnownTransportParameter::PreferredAddress)
        )
    }

    /// Decode the value of the registered preferred-address transport
    /// parameter. Unknown, grease, provisional, and other known parameters
    /// return `Ok(None)`.
    pub fn preferred_address_value(&self) -> Result<Option<QuicPreferredAddress>> {
        if !self.is_preferred_address() {
            return Ok(None);
        }
        decode_preferred_address_value(&self.value).map(Some)
    }

    /// Return true when this is the registered `version_information` transport
    /// parameter.
    pub const fn is_version_information(&self) -> bool {
        matches!(
            self.known_type(),
            Some(QuicKnownTransportParameter::VersionInformation)
        )
    }

    /// Decode the value of the registered version-information transport
    /// parameter. Unknown, grease, provisional, and other known parameters
    /// return `Ok(None)`.
    pub fn version_information_value(&self) -> Result<Option<QuicVersionInformation>> {
        if !self.is_version_information() {
            return Ok(None);
        }
        decode_version_information_value(&self.value).map(Some)
    }

    /// Return the broad parameter identifier classification.
    pub const fn kind(&self) -> QuicTransportParameterKind {
        match self.identifier {
            Some(identifier) => match QuicKnownTransportParameter::from_id(identifier) {
                Some(known) => QuicTransportParameterKind::Known(known),
                None if is_grease_transport_parameter_id(identifier) => {
                    QuicTransportParameterKind::Grease
                }
                None => QuicTransportParameterKind::Unknown,
            },
            None => QuicTransportParameterKind::Unset,
        }
    }

    /// Borrow the preserved value bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Length of the preserved value bytes.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Return true when the preserved value is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Return the caller-pinned identifier varint width, if any.
    pub const fn identifier_encoded_len(&self) -> Option<usize> {
        self.identifier_encoded_len
    }

    /// Return the caller-pinned value-length varint width, if any.
    pub const fn length_encoded_len(&self) -> Option<usize> {
        self.length_encoded_len
    }

    /// Return the caller-pinned declared value length, if any.
    pub const fn declared_value_len_override(&self) -> Option<QuicVarInt> {
        self.declared_value_len
    }

    /// Return the effective declared value length. When unset, it is the raw
    /// value byte length encoded as a QUIC varint.
    pub fn declared_value_len(&self) -> Result<QuicVarInt> {
        match self.declared_value_len {
            Some(length) => Ok(length),
            None => value_len_varint(self.value.len()),
        }
    }

    /// Return the full encoded tuple length without materializing bytes.
    pub fn encoded_len(&self) -> Result<usize> {
        let identifier = self.identifier.ok_or_else(|| {
            CrafterError::invalid_field_value(
                "quic.transport_parameter.id",
                "transport parameter identifier is unset",
            )
        })?;
        let declared_value_len = self.declared_value_len()?;

        Ok(
            encoded_varint_width(identifier, self.identifier_encoded_len)?
                + encoded_varint_width(declared_value_len, self.length_encoded_len)?
                + self.value.len(),
        )
    }

    /// Encode this transport-parameter tuple.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let identifier = self.identifier.ok_or_else(|| {
            CrafterError::invalid_field_value(
                "quic.transport_parameter.id",
                "transport parameter identifier is unset",
            )
        })?;
        encode_varint(identifier, self.identifier_encoded_len, out)?;
        encode_varint(self.declared_value_len()?, self.length_encoded_len, out)?;
        out.extend_from_slice(&self.value);
        Ok(())
    }

    /// Encode this transport-parameter tuple as a new vector.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a bounded transport-parameter sequence.
    pub fn decode_sequence(bytes: impl AsRef<[u8]>) -> Result<Vec<Self>> {
        let bytes = bytes.as_ref();
        let mut parameters = Vec::new();
        let mut offset = 0;

        while offset < bytes.len() {
            let (identifier, identifier_end) =
                decode_parameter_varint(bytes, offset, "quic.transport_parameter.id")?;
            let identifier_encoded_len = identifier_end - offset;
            offset = identifier_end;

            let (value_length, length_end) =
                decode_parameter_varint(bytes, offset, "quic.transport_parameter.length")?;
            let length_encoded_len = length_end - offset;
            offset = length_end;

            let value_len = usize::try_from(value_length.value()).map_err(|_| {
                CrafterError::invalid_field_value(
                    "quic.transport_parameter.length",
                    "length exceeds usize",
                )
            })?;
            let available = bytes.len().saturating_sub(offset);
            if available < value_len {
                return Err(CrafterError::buffer_too_short(
                    "quic.transport_parameter.value",
                    value_len,
                    available,
                ));
            }

            let end = offset + value_len;
            parameters.push(
                Self::raw(identifier, &bytes[offset..end])
                    .with_identifier_encoded_len(identifier_encoded_len)
                    .with_length_encoded_len(length_encoded_len)
                    .with_declared_value_len(value_length),
            );
            if let Some(parameter) = parameters.last() {
                if parameter.integer_type().is_some() {
                    parameter.integer_value()?;
                }
                if parameter.is_stateless_reset_token() {
                    parameter.stateless_reset_token_value()?;
                }
                if parameter.is_preferred_address() {
                    parameter.preferred_address_value()?;
                }
                if parameter.is_version_information() {
                    parameter.version_information_value()?;
                }
            }
            offset = end;
        }

        Ok(parameters)
    }

    /// Encode a transport-parameter sequence into a contiguous buffer.
    pub fn encode_sequence(parameters: impl IntoIterator<Item = Self>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for parameter in parameters {
            parameter.encode(&mut out)?;
        }
        Ok(out)
    }

    /// Return the encoded length of a transport-parameter sequence without
    /// concatenating bytes.
    pub fn encoded_sequence_len<'a>(
        parameters: impl IntoIterator<Item = &'a Self>,
    ) -> Result<usize> {
        parameters.into_iter().try_fold(0usize, |total, parameter| {
            Ok(total + parameter.encoded_len()?)
        })
    }

    /// Report duplicate transport-parameter identifiers in input order.
    pub fn duplicate_identifiers<'a>(
        parameters: impl IntoIterator<Item = &'a Self>,
    ) -> Vec<QuicTransportParameterDuplicate> {
        let mut first_indexes = BTreeMap::new();
        let mut duplicates = Vec::new();

        for (index, parameter) in parameters.into_iter().enumerate() {
            let Some(identifier) = parameter.identifier else {
                continue;
            };
            if let Some(first_index) = first_indexes.get(&identifier.value()).copied() {
                duplicates.push(QuicTransportParameterDuplicate::new(
                    identifier,
                    first_index,
                    index,
                ));
            } else {
                first_indexes.insert(identifier.value(), index);
            }
        }

        duplicates
    }

    /// Stable summary for packet inspection.
    pub fn summary(&self) -> String {
        match self.identifier {
            Some(identifier)
                if self.is_stateless_reset_token()
                    && self.value.len() == QUIC_STATELESS_RESET_TOKEN_LEN =>
            {
                format!(
                    "id=0x{:x} kind=stateless_reset_token token={}",
                    identifier.value(),
                    hex_bytes(&self.value)
                )
            }
            Some(identifier) if self.is_preferred_address() => {
                if let Ok(Some(preferred_address)) = self.preferred_address_value() {
                    format!(
                        "id=0x{:x} kind=preferred_address {}",
                        identifier.value(),
                        preferred_address.summary()
                    )
                } else {
                    format!(
                        "id=0x{:x} kind=preferred_address value_len={}",
                        identifier.value(),
                        self.value.len()
                    )
                }
            }
            Some(identifier) if self.is_version_information() => {
                if let Ok(Some(version_information)) = self.version_information_value() {
                    format!(
                        "id=0x{:x} kind=version_information {}",
                        identifier.value(),
                        version_information.summary()
                    )
                } else {
                    format!(
                        "id=0x{:x} kind=version_information value_len={}",
                        identifier.value(),
                        self.value.len()
                    )
                }
            }
            Some(identifier) => {
                format!(
                    "id=0x{:x} kind={} value_len={}",
                    identifier.value(),
                    self.kind().label(),
                    self.value.len()
                )
            }
            None => format!("id=<unset> kind=unset value_len={}", self.value.len()),
        }
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "identifier",
                self.identifier
                    .map(|identifier| format!("0x{:x}", identifier.value()))
                    .unwrap_or_else(|| "<unset>".to_string()),
            ),
            ("kind", self.kind().label().to_string()),
            (
                "identifier_encoded_len",
                self.identifier_encoded_len
                    .map(|len| len.to_string())
                    .unwrap_or_else(|| "canonical".to_string()),
            ),
            (
                "declared_value_len",
                self.declared_value_len
                    .map(|len| len.value().to_string())
                    .unwrap_or_else(|| self.value.len().to_string()),
            ),
            (
                "length_encoded_len",
                self.length_encoded_len
                    .map(|len| len.to_string())
                    .unwrap_or_else(|| "canonical".to_string()),
            ),
            ("value_len", self.value.len().to_string()),
            ("value", hex_bytes(&self.value)),
        ];
        if let Ok(Some(token)) = self.stateless_reset_token_value() {
            fields.push(("stateless_reset_token", token.to_spaced_hex()));
        }
        if let Ok(Some(preferred_address)) = self.preferred_address_value() {
            fields.extend(preferred_address.inspection_fields());
        }
        if let Ok(Some(version_information)) = self.version_information_value() {
            fields.extend(version_information.inspection_fields());
        }
        fields
    }
}

fn value_len_varint(len: usize) -> Result<QuicVarInt> {
    let len = u64::try_from(len).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.transport_parameter.length",
            "length exceeds 62-bit QUIC varint space",
        )
    })?;
    QuicVarInt::new(len).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.transport_parameter.length",
            "length exceeds 62-bit QUIC varint space",
        )
    })
}

fn encoded_varint_width(value: QuicVarInt, encoded_len: Option<usize>) -> Result<usize> {
    match encoded_len {
        Some(len) => {
            let mut scratch = Vec::new();
            value.encode_with_len(len, &mut scratch)?;
            Ok(len)
        }
        None => value.encoded_len(),
    }
}

fn encode_varint(value: QuicVarInt, encoded_len: Option<usize>, out: &mut Vec<u8>) -> Result<()> {
    match encoded_len {
        Some(len) => value.encode_with_len(len, out),
        None => value.encode(out).map(|_| ()),
    }
}

fn decode_parameter_varint(
    bytes: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<(QuicVarInt, usize)> {
    let Some(first) = bytes.get(offset).copied() else {
        return Err(CrafterError::buffer_too_short(context, 1, 0));
    };
    let len = encoded_len_from_prefix(first);
    let available = bytes.len().saturating_sub(offset);
    if available < len {
        return Err(CrafterError::buffer_too_short(context, len, available));
    }

    let (value, consumed) = QuicVarInt::decode(&bytes[offset..])?;
    Ok((value, offset + consumed))
}

fn decode_integer_transport_parameter_value(bytes: &[u8]) -> Result<QuicVarInt> {
    let (value, consumed) =
        decode_parameter_varint(bytes, 0, "quic.transport_parameter.integer.value")?;
    if consumed != bytes.len() {
        return Err(CrafterError::invalid_field_value(
            "quic.transport_parameter.integer.value",
            "integer transport parameter value has surplus bytes",
        ));
    }
    Ok(value)
}

fn decode_stateless_reset_token_value(bytes: &[u8]) -> Result<QuicStatelessResetToken> {
    if bytes.len() != QUIC_STATELESS_RESET_TOKEN_LEN {
        return Err(CrafterError::invalid_field_value(
            "quic.transport_parameter.stateless_reset_token",
            "stateless_reset_token transport parameter value must be exactly 16 bytes",
        ));
    }

    let mut token = [0u8; QUIC_STATELESS_RESET_TOKEN_LEN];
    token.copy_from_slice(bytes);
    Ok(QuicStatelessResetToken::new(token))
}

fn decode_preferred_address_value(bytes: &[u8]) -> Result<QuicPreferredAddress> {
    let mut offset = 0;

    let ipv4_bytes = read_preferred_address_field(
        bytes,
        &mut offset,
        4,
        "quic.transport_parameter.preferred_address.ipv4_address",
    )?;
    let ipv4_address = Ipv4Addr::new(ipv4_bytes[0], ipv4_bytes[1], ipv4_bytes[2], ipv4_bytes[3]);

    let ipv4_port = read_preferred_address_u16(
        bytes,
        &mut offset,
        "quic.transport_parameter.preferred_address.ipv4_port",
    )?;

    let ipv6_bytes = read_preferred_address_field(
        bytes,
        &mut offset,
        16,
        "quic.transport_parameter.preferred_address.ipv6_address",
    )?;
    let mut ipv6_octets = [0u8; 16];
    ipv6_octets.copy_from_slice(ipv6_bytes);
    let ipv6_address = Ipv6Addr::from(ipv6_octets);

    let ipv6_port = read_preferred_address_u16(
        bytes,
        &mut offset,
        "quic.transport_parameter.preferred_address.ipv6_port",
    )?;

    let connection_id_length = read_preferred_address_field(
        bytes,
        &mut offset,
        1,
        "quic.transport_parameter.preferred_address.connection_id_length",
    )?[0];

    let connection_id_bytes = read_preferred_address_field(
        bytes,
        &mut offset,
        usize::from(connection_id_length),
        "quic.transport_parameter.preferred_address.connection_id",
    )?;
    let connection_id = QuicConnectionId::from_bytes(connection_id_bytes);

    let token_bytes = read_preferred_address_field(
        bytes,
        &mut offset,
        QUIC_STATELESS_RESET_TOKEN_LEN,
        "quic.transport_parameter.preferred_address.stateless_reset_token",
    )?;
    let stateless_reset_token = decode_stateless_reset_token_value(token_bytes)?;

    if offset != bytes.len() {
        return Err(CrafterError::invalid_field_value(
            "quic.transport_parameter.preferred_address",
            "preferred_address transport parameter has trailing bytes",
        ));
    }

    Ok(QuicPreferredAddress::new(
        ipv4_address,
        ipv4_port,
        ipv6_address,
        ipv6_port,
        connection_id,
        stateless_reset_token,
    )
    .with_connection_id_length(connection_id_length))
}

fn read_preferred_address_u16(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<u16> {
    let field = read_preferred_address_field(bytes, offset, 2, context)?;
    Ok(u16::from_be_bytes([field[0], field[1]]))
}

fn read_preferred_address_field<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    len: usize,
    context: &'static str,
) -> Result<&'a [u8]> {
    let available = bytes.len().saturating_sub(*offset);
    if available < len {
        return Err(CrafterError::buffer_too_short(context, len, available));
    }
    let start = *offset;
    let end = start + len;
    *offset = end;
    Ok(&bytes[start..end])
}

fn decode_version_information_value(bytes: &[u8]) -> Result<QuicVersionInformation> {
    if bytes.len() < 4 {
        return Err(CrafterError::buffer_too_short(
            "quic.transport_parameter.version_information.chosen_version",
            4,
            bytes.len(),
        ));
    }
    if bytes.len() % 4 != 0 {
        return Err(CrafterError::invalid_field_value(
            "quic.transport_parameter.version_information",
            "version_information value length must be divisible by 4",
        ));
    }

    let chosen_version = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut available_versions = Vec::new();
    for chunk in bytes[4..].chunks_exact(4) {
        available_versions.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }

    Ok(QuicVersionInformation::new(
        chosen_version,
        available_versions,
    ))
}

fn format_quic_version_hex(version: u32) -> String {
    format!("0x{version:08x}")
}

fn format_quic_version_list(versions: &[u32]) -> String {
    if versions.is_empty() {
        return "<empty>".to_string();
    }
    versions
        .iter()
        .copied()
        .map(format_quic_version_hex)
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::quic::constants::{QUIC_VERSION_1, QUIC_VERSION_2};
    use crate::protocols::quic::varint::is_shortest_encoding;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn quic_summary_inspection_transport_parameter_summary_preserves_unknown_codepoint() {
        let parameter = QuicTransportParameter::raw(QuicVarInt::new(0xdeac).unwrap(), [0xaa, 0xbb]);

        assert_eq!(parameter.summary(), "id=0xdeac kind=unknown value_len=2");
        let fields = parameter.inspection_fields();
        assert!(fields.contains(&("identifier", "0xdeac".to_string())));
        assert!(fields.contains(&("kind", "unknown".to_string())));
        assert!(fields.contains(&("value", "aa bb".to_string())));
    }

    #[test]
    fn quic_transport_parameter_skeleton_maps_selected_registry_codepoints() {
        assert_eq!(
            QuicKnownTransportParameter::from_id(QuicVarInt::from_u64_unchecked(0x00)),
            Some(QuicKnownTransportParameter::OriginalDestinationConnectionId)
        );
        assert_eq!(
            QuicKnownTransportParameter::VersionInformation.id().value(),
            0x11
        );
        assert_eq!(
            QuicKnownTransportParameter::MaxDatagramFrameSize.name(),
            "max_datagram_frame_size"
        );
        assert_eq!(
            QuicKnownTransportParameter::GreaseQuicBit.id().value(),
            0x2ab2
        );
        assert!(is_grease_transport_parameter_id(
            QuicVarInt::from_u64_unchecked(27)
        ));
        assert!(!is_grease_transport_parameter_id(
            QuicKnownTransportParameter::GreaseQuicBit.id()
        ));
    }

    #[test]
    fn quic_transport_parameter_skeleton_decodes_sequence_and_preserves_unknowns() -> Result<()> {
        let bytes = [
            0x01, 0x01, 0x03, // max_idle_timeout, one-byte value
            0x40, 0xaf, 0x02, 0xde, 0xad, // unknown two-byte ID with raw value
            0x01, 0x01, 0x00, // duplicate max_idle_timeout with zero value
        ];

        let parameters = QuicTransportParameter::decode_sequence(bytes)?;

        assert_eq!(parameters.len(), 3);
        assert_eq!(
            parameters[0].known_type(),
            Some(QuicKnownTransportParameter::MaxIdleTimeout)
        );
        assert_eq!(parameters[0].value(), &[0x03]);
        assert_eq!(parameters[1].kind(), QuicTransportParameterKind::Unknown);
        assert_eq!(parameters[1].identifier().unwrap().value(), 0xaf);
        assert_eq!(parameters[1].identifier_encoded_len(), Some(2));
        assert_eq!(parameters[1].value(), &[0xde, 0xad]);
        assert_eq!(
            QuicTransportParameter::duplicate_identifiers(parameters.iter()),
            vec![QuicTransportParameterDuplicate::new(
                QuicKnownTransportParameter::MaxIdleTimeout.id(),
                0,
                2,
            )]
        );
        assert_eq!(QuicTransportParameter::encode_sequence(parameters)?, bytes);
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_skeleton_encodes_sequences_and_lengths() -> Result<()> {
        let parameters = vec![
            QuicTransportParameter::known(
                QuicKnownTransportParameter::InitialSourceConnectionId,
                [0x83, 0x94, 0xc8, 0xf0],
            ),
            QuicTransportParameter::raw(QuicVarInt::from_u64_unchecked(0xaf), [0xde, 0xad])
                .with_identifier_encoded_len(2)
                .with_length_encoded_len(2),
        ];

        assert_eq!(
            QuicTransportParameter::encoded_sequence_len(&parameters)?,
            12
        );
        assert_eq!(
            QuicTransportParameter::encode_sequence(parameters)?,
            [0x0f, 0x04, 0x83, 0x94, 0xc8, 0xf0, 0x40, 0xaf, 0x40, 0x02, 0xde, 0xad]
        );
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_skeleton_preserves_non_shortest_tuple_varints() -> Result<()> {
        let bytes = [0x40, 0x21, 0x40, 0x00];

        let parameters = QuicTransportParameter::decode_sequence(bytes)?;

        assert_eq!(parameters[0].identifier().unwrap().value(), 0x21);
        assert_eq!(parameters[0].identifier_encoded_len(), Some(2));
        assert_eq!(parameters[0].length_encoded_len(), Some(2));
        assert!(!is_shortest_encoding(
            parameters[0].identifier().unwrap().value(),
            parameters[0].identifier_encoded_len().unwrap()
        ));
        assert_eq!(QuicTransportParameter::encode_sequence(parameters)?, bytes);
        Ok(())
    }

    #[test]
    fn quic_transport_parameters_integer_builds_and_decodes_registered_values() -> Result<()> {
        let parameters = vec![
            QuicTransportParameter::max_idle_timeout(QuicVarInt::from_u64_unchecked(30))?,
            QuicTransportParameter::initial_max_data(QuicVarInt::from_u64_unchecked(16_384))?,
            QuicTransportParameter::max_datagram_frame_size(QuicVarInt::from_u64_unchecked(1200))?,
        ];

        let bytes = QuicTransportParameter::encode_sequence(parameters)?;

        assert_eq!(
            bytes,
            [0x01, 0x01, 0x1e, 0x04, 0x04, 0x80, 0x00, 0x40, 0x00, 0x20, 0x02, 0x44, 0xb0,]
        );
        let decoded = QuicTransportParameter::decode_sequence(bytes)?;
        assert_eq!(
            decoded[0].integer_type(),
            Some(QuicIntegerTransportParameter::MaxIdleTimeout)
        );
        assert_eq!(decoded[0].integer_value()?.unwrap().value(), 30);
        assert_eq!(
            decoded[1].integer_type(),
            Some(QuicIntegerTransportParameter::InitialMaxData)
        );
        assert_eq!(decoded[1].integer_value()?.unwrap().value(), 16_384);
        assert_eq!(
            decoded[2].integer_type(),
            Some(QuicIntegerTransportParameter::MaxDatagramFrameSize)
        );
        assert_eq!(decoded[2].integer_value()?.unwrap().value(), 1200);
        Ok(())
    }

    #[test]
    fn quic_transport_parameters_integer_reports_validation_findings() -> Result<()> {
        assert_eq!(
            QuicIntegerTransportParameter::MaxUdpPayloadSize
                .default_value()
                .unwrap()
                .value(),
            65_527
        );
        assert_eq!(
            QuicIntegerTransportParameter::InitialMaxData.default_value(),
            None
        );
        assert_eq!(
            QuicTransportParameter::max_udp_payload_size(QuicVarInt::from_u64_unchecked(1199))?
                .integer_validation_finding()?,
            Some(QuicIntegerTransportParameterValidation::MaxUdpPayloadSizeBelowMinimum)
        );
        assert_eq!(
            QuicTransportParameter::ack_delay_exponent(QuicVarInt::from_u64_unchecked(21))?
                .integer_validation_finding()?
                .unwrap()
                .label(),
            "ack_delay_exponent_above_20"
        );
        assert_eq!(
            QuicTransportParameter::max_ack_delay(QuicVarInt::from_u64_unchecked(1 << 14))?
                .integer_validation_finding()?,
            Some(QuicIntegerTransportParameterValidation::MaxAckDelayExceedsLimit)
        );
        assert_eq!(
            QuicTransportParameter::active_connection_id_limit(QuicVarInt::from_u64_unchecked(1))?
                .integer_validation_finding()?,
            Some(QuicIntegerTransportParameterValidation::ActiveConnectionIdLimitBelowMinimum)
        );
        assert_eq!(
            QuicTransportParameter::initial_max_streams_bidi(QuicVarInt::from_u64_unchecked(
                (1u64 << 60) + 1,
            ))?
            .integer_validation_finding()?,
            Some(QuicIntegerTransportParameterValidation::InitialMaxStreamsExceedsLimit)
        );
        Ok(())
    }

    #[test]
    fn quic_transport_parameters_integer_leaves_unknown_integer_looking_values_raw() -> Result<()> {
        let parameter = QuicTransportParameter::raw(QuicVarInt::from_u64_unchecked(0x26ab), [0x01]);

        assert_eq!(parameter.kind(), QuicTransportParameterKind::Unknown);
        assert_eq!(parameter.integer_type(), None);
        assert_eq!(parameter.integer_value()?, None);
        assert_eq!(parameter.integer_validation_finding()?, None);
        assert_eq!(parameter.value(), &[0x01]);
        Ok(())
    }

    #[test]
    fn quic_transport_parameters_integer_reports_structured_value_errors() {
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("quic.transport_parameter.integer.value", 1, 0)
        );
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x01, 0x01, 0x40]).unwrap_err(),
            CrafterError::buffer_too_short("quic.transport_parameter.integer.value", 2, 1)
        );
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x01, 0x02, 0x01, 0x02]).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.integer.value",
                "integer transport parameter value has surplus bytes",
            )
        );
    }

    #[test]
    fn quic_transport_parameters_connection_id_builds_decodes_and_roundtrips() -> Result<()> {
        let oversized = QuicConnectionId::from_bytes([0xab; 21]);
        let parameters = vec![
            QuicTransportParameter::original_destination_connection_id(
                QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]),
            ),
            QuicTransportParameter::initial_source_connection_id(QuicConnectionId::new()),
            QuicTransportParameter::retry_source_connection_id(oversized.clone()),
        ];

        let mut expected = vec![
            0x00, 0x04, 0x83, 0x94, 0xc8, 0xf0, // original DCID
            0x0f, 0x00, // zero-length initial SCID
            0x10, 0x15, // retry SCID with 21 raw bytes
        ];
        expected.extend_from_slice(&[0xab; 21]);

        let encoded = QuicTransportParameter::encode_sequence(parameters)?;
        assert_eq!(encoded, expected);

        let decoded = QuicTransportParameter::decode_sequence(&encoded)?;
        assert_eq!(
            decoded[0].connection_id_type(),
            Some(QuicConnectionIdTransportParameter::OriginalDestinationConnectionId)
        );
        assert_eq!(
            decoded[0].connection_id_value().unwrap().as_bytes(),
            &[0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(
            decoded[1].connection_id_type(),
            Some(QuicConnectionIdTransportParameter::InitialSourceConnectionId)
        );
        assert!(decoded[1].connection_id_value().unwrap().is_empty());
        assert_eq!(
            decoded[2].connection_id_type(),
            Some(QuicConnectionIdTransportParameter::RetrySourceConnectionId)
        );
        assert_eq!(
            decoded[2].connection_id_value().unwrap().as_bytes(),
            [0xab; 21]
        );
        assert_eq!(
            decoded[2]
                .connection_id_value()
                .unwrap()
                .validate_v1_v2_len()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.connection_id.length",
                "QUIC v1/v2 connection IDs must be at most 20 bytes",
            )
        );
        Ok(())
    }

    #[test]
    fn quic_transport_parameters_connection_id_leaves_unknown_values_raw() {
        let parameter = QuicTransportParameter::raw(QuicVarInt::from_u64_unchecked(0x26ab), [0xaa]);

        assert_eq!(parameter.kind(), QuicTransportParameterKind::Unknown);
        assert_eq!(parameter.connection_id_type(), None);
        assert_eq!(parameter.connection_id_value(), None);
        assert_eq!(parameter.value(), &[0xaa]);
    }

    #[test]
    fn quic_transport_parameters_connection_id_reports_tuple_length_errors() {
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x0f, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("quic.transport_parameter.value", 2, 1)
        );
    }

    #[test]
    fn quic_transport_parameter_reset_token_builds_decodes_and_summarizes() -> Result<()> {
        let token = QuicStatelessResetToken::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        let parameter = QuicTransportParameter::stateless_reset_token(token);

        assert_eq!(
            parameter.identifier(),
            Some(QuicKnownTransportParameter::StatelessResetToken.id())
        );
        assert_eq!(parameter.value(), token.as_bytes());
        assert!(parameter.is_stateless_reset_token());
        assert_eq!(parameter.stateless_reset_token_value()?, Some(token));
        assert_eq!(token.to_hex(), "00112233445566778899aabbccddeeff");

        let encoded = parameter.encode_to_vec()?;
        assert_eq!(
            encoded,
            [
                0x02, 0x10, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                0xcc, 0xdd, 0xee, 0xff,
            ]
        );

        let decoded = QuicTransportParameter::decode_sequence(&encoded)?;
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].stateless_reset_token_value()?, Some(token));
        assert_eq!(
            decoded[0].summary(),
            "id=0x2 kind=stateless_reset_token token=00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
        );
        assert_eq!(QuicTransportParameter::encode_sequence(decoded)?, encoded);
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_reset_token_reports_malformed_lengths() {
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x02, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.stateless_reset_token",
                "stateless_reset_token transport parameter value must be exactly 16 bytes",
            )
        );

        let mut short = vec![0x02, 0x0f];
        short.extend_from_slice(&[0xab; QUIC_STATELESS_RESET_TOKEN_LEN - 1]);
        assert_eq!(
            QuicTransportParameter::decode_sequence(short).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.stateless_reset_token",
                "stateless_reset_token transport parameter value must be exactly 16 bytes",
            )
        );

        let mut long = vec![0x02, 0x11];
        long.extend_from_slice(&[0xcd; QUIC_STATELESS_RESET_TOKEN_LEN + 1]);
        assert_eq!(
            QuicTransportParameter::decode_sequence(long).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.stateless_reset_token",
                "stateless_reset_token transport parameter value must be exactly 16 bytes",
            )
        );
    }

    #[test]
    fn quic_transport_parameter_reset_token_raw_build_preserves_malformed_value() -> Result<()> {
        let parameter = QuicTransportParameter::raw(
            QuicKnownTransportParameter::StatelessResetToken.id(),
            [0xab; QUIC_STATELESS_RESET_TOKEN_LEN - 1],
        );

        let encoded = parameter.encode_to_vec()?;

        assert_eq!(
            parameter.value(),
            [0xab; QUIC_STATELESS_RESET_TOKEN_LEN - 1]
        );
        assert_eq!(
            parameter.stateless_reset_token_value().unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.stateless_reset_token",
                "stateless_reset_token transport parameter value must be exactly 16 bytes",
            )
        );
        assert_eq!(encoded[0], 0x02);
        assert_eq!(encoded[1], 0x0f);
        assert_eq!(encoded.len(), 2 + QUIC_STATELESS_RESET_TOKEN_LEN - 1);
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_reset_token_ignores_unknown_values() -> Result<()> {
        let parameter = QuicTransportParameter::raw(QuicVarInt::from_u64_unchecked(0x26ab), [0xaa]);

        assert!(!parameter.is_stateless_reset_token());
        assert_eq!(parameter.stateless_reset_token_value()?, None);
        assert_eq!(parameter.value(), &[0xaa]);
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_preferred_address_builds_decodes_and_inspects() -> Result<()> {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 10);
        let ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010);
        let token = QuicStatelessResetToken::new([0xab; QUIC_STATELESS_RESET_TOKEN_LEN]);
        let preferred_address = QuicPreferredAddress::new(
            ipv4,
            4433,
            ipv6,
            4434,
            QuicConnectionId::from_bytes([0x83, 0x94, 0xc8, 0xf0]),
            token,
        );
        let parameter = QuicTransportParameter::preferred_address(preferred_address)?;

        let mut expected_value = vec![0xc0, 0x00, 0x02, 0x0a, 0x11, 0x51];
        expected_value.extend_from_slice(&ipv6.octets());
        expected_value.extend_from_slice(&[0x11, 0x52, 0x04, 0x83, 0x94, 0xc8, 0xf0]);
        expected_value.extend_from_slice(token.as_bytes());

        let mut expected = vec![0x0d, 0x2d];
        expected.extend_from_slice(&expected_value);
        let encoded = parameter.encode_to_vec()?;
        assert_eq!(encoded, expected);

        let decoded = QuicTransportParameter::decode_sequence(&encoded)?;
        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].is_preferred_address());
        let decoded_preferred = decoded[0].preferred_address_value()?.unwrap();
        assert_eq!(decoded_preferred.ipv4_address(), ipv4);
        assert_eq!(decoded_preferred.ipv4_port(), 4433);
        assert_eq!(decoded_preferred.ipv6_address(), ipv6);
        assert_eq!(decoded_preferred.ipv6_port(), 4434);
        assert_eq!(decoded_preferred.connection_id_length_override(), Some(4));
        assert_eq!(decoded_preferred.connection_id_length()?, 4);
        assert_eq!(
            decoded_preferred.connection_id().as_bytes(),
            &[0x83, 0x94, 0xc8, 0xf0]
        );
        assert_eq!(decoded_preferred.stateless_reset_token(), &token);
        assert!(decoded_preferred.validation_findings().is_empty());
        assert_eq!(
            decoded[0].summary(),
            "id=0xd kind=preferred_address ipv4=192.0.2.10:4433 ipv6=[2001:db8::10]:4434 connection_id_len=4 connection_id=8394c8f0"
        );

        let fields = decoded[0].inspection_fields();
        assert!(fields.contains(&("preferred_ipv4_address", "192.0.2.10".to_string())));
        assert!(fields.contains(&("preferred_ipv4_port", "4433".to_string())));
        assert!(fields.contains(&("preferred_ipv6_address", "2001:db8::10".to_string())));
        assert!(fields.contains(&("preferred_connection_id", "8394c8f0".to_string())));
        assert!(fields.contains(&(
            "preferred_stateless_reset_token",
            "ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab".to_string(),
        )));
        assert_eq!(QuicTransportParameter::encode_sequence(decoded)?, expected);
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_preferred_address_reports_validation_findings() {
        let token = QuicStatelessResetToken::new([0xcd; QUIC_STATELESS_RESET_TOKEN_LEN]);
        let omitted = QuicPreferredAddress::new(
            Ipv4Addr::new(0, 0, 0, 0),
            0,
            Ipv6Addr::UNSPECIFIED,
            0,
            QuicConnectionId::new(),
            token,
        );
        assert_eq!(
            omitted.validation_findings(),
            vec![
                QuicPreferredAddressValidation::ZeroLengthConnectionId,
                QuicPreferredAddressValidation::Ipv4AddressFamilyOmitted,
                QuicPreferredAddressValidation::Ipv6AddressFamilyOmitted,
            ]
        );

        let oversized = QuicPreferredAddress::new(
            Ipv4Addr::new(192, 0, 2, 10),
            4433,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010),
            4434,
            QuicConnectionId::from_bytes([0xab; 21]),
            token,
        );
        assert_eq!(
            oversized.validation_findings(),
            vec![QuicPreferredAddressValidation::ConnectionIdExceedsV1V2Limit]
        );
        assert_eq!(
            QuicPreferredAddressValidation::ConnectionIdExceedsV1V2Limit.label(),
            "preferred_address_connection_id_above_20"
        );
    }

    #[test]
    fn quic_transport_parameter_preferred_address_preserves_bad_cid_len() -> Result<()> {
        let token = QuicStatelessResetToken::new([0xef; QUIC_STATELESS_RESET_TOKEN_LEN]);
        let preferred_address = QuicPreferredAddress::new(
            Ipv4Addr::new(192, 0, 2, 10),
            4433,
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010),
            4434,
            QuicConnectionId::from_bytes([0xaa, 0xbb, 0xcc]),
            token,
        )
        .with_connection_id_length(1);
        let parameter = QuicTransportParameter::preferred_address(preferred_address)?;
        let encoded = parameter.encode_to_vec()?;

        assert_eq!(parameter.value()[24], 1);
        assert_eq!(
            QuicTransportParameter::decode_sequence(encoded).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.preferred_address",
                "preferred_address transport parameter has trailing bytes",
            )
        );
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_preferred_address_reports_structured_truncation() {
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x0d, 0x03, 0xc0, 0x00, 0x02]).unwrap_err(),
            CrafterError::buffer_too_short(
                "quic.transport_parameter.preferred_address.ipv4_address",
                4,
                3,
            )
        );

        let mut truncated_cid = preferred_address_fixed_prefix();
        truncated_cid.push(4);
        truncated_cid.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            QuicTransportParameter::decode_sequence(preferred_address_tuple(truncated_cid))
                .unwrap_err(),
            CrafterError::buffer_too_short(
                "quic.transport_parameter.preferred_address.connection_id",
                4,
                2,
            )
        );

        let mut truncated_token = preferred_address_fixed_prefix();
        truncated_token.extend_from_slice(&[4, 0x83, 0x94, 0xc8, 0xf0]);
        truncated_token.extend_from_slice(&[0xab; QUIC_STATELESS_RESET_TOKEN_LEN - 1]);
        assert_eq!(
            QuicTransportParameter::decode_sequence(preferred_address_tuple(truncated_token))
                .unwrap_err(),
            CrafterError::buffer_too_short(
                "quic.transport_parameter.preferred_address.stateless_reset_token",
                QUIC_STATELESS_RESET_TOKEN_LEN,
                QUIC_STATELESS_RESET_TOKEN_LEN - 1,
            )
        );

        let mut trailing = preferred_address_fixed_prefix();
        trailing.extend_from_slice(&[1, 0xaa]);
        trailing.extend_from_slice(&[0xbb; QUIC_STATELESS_RESET_TOKEN_LEN]);
        trailing.push(0xcc);
        assert_eq!(
            QuicTransportParameter::decode_sequence(preferred_address_tuple(trailing)).unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.preferred_address",
                "preferred_address transport parameter has trailing bytes",
            )
        );
    }

    #[test]
    fn quic_transport_parameter_version_information_builds_decodes_and_inspects() -> Result<()> {
        let version_information = QuicVersionInformation::new(
            QUIC_VERSION_1,
            [QUIC_VERSION_2, QUIC_VERSION_1, 0x0a0a_0a0a, 0xface_feed],
        );
        let parameter = QuicTransportParameter::version_information(version_information.clone());

        assert_eq!(
            parameter.identifier(),
            Some(QuicKnownTransportParameter::VersionInformation.id())
        );
        assert!(parameter.is_version_information());
        assert_eq!(
            parameter.version_information_value()?,
            Some(version_information.clone())
        );

        let encoded = parameter.encode_to_vec()?;
        assert_eq!(
            encoded,
            [
                0x11, 0x14, // ID + 20-byte value length
                0x00, 0x00, 0x00, 0x01, // chosen QUIC v1
                0x6b, 0x33, 0x43, 0xcf, // available QUIC v2
                0x00, 0x00, 0x00, 0x01, // available QUIC v1
                0x0a, 0x0a, 0x0a, 0x0a, // reserved grease version
                0xfa, 0xce, 0xfe, 0xed, // unknown version
            ]
        );

        let decoded = QuicTransportParameter::decode_sequence(&encoded)?;
        let decoded_value = decoded[0].version_information_value()?.unwrap();
        assert_eq!(decoded_value.chosen_version(), QUIC_VERSION_1);
        assert_eq!(
            decoded_value.available_versions(),
            &[QUIC_VERSION_2, QUIC_VERSION_1, 0x0a0a_0a0a, 0xface_feed]
        );
        assert!(decoded_value.validation_findings().is_empty());
        assert_eq!(
            decoded[0].summary(),
            "id=0x11 kind=version_information chosen_version=0x00000001 available_versions=0x6b3343cf,0x00000001,0x0a0a0a0a,0xfacefeed"
        );

        let fields = decoded[0].inspection_fields();
        assert!(fields.contains(&(
            "version_information_chosen_version",
            "0x00000001".to_string(),
        )));
        assert!(fields.contains(&(
            "version_information_chosen_version_label",
            "QUIC v1".to_string(),
        )));
        assert!(fields.contains(&(
            "version_information_available_versions",
            "0x6b3343cf,0x00000001,0x0a0a0a0a,0xfacefeed".to_string(),
        )));
        assert_eq!(QuicTransportParameter::encode_sequence(decoded)?, encoded);
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_version_information_allows_empty_available() -> Result<()> {
        let parameter = QuicTransportParameter::version_information(QuicVersionInformation::new(
            QUIC_VERSION_2,
            [],
        ));

        assert_eq!(
            parameter.encode_to_vec()?,
            [0x11, 0x04, 0x6b, 0x33, 0x43, 0xcf]
        );
        assert_eq!(
            parameter.summary(),
            "id=0x11 kind=version_information chosen_version=0x6b3343cf available_versions=<empty>"
        );
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_version_information_reports_validation_findings() -> Result<()> {
        let version_information = QuicVersionInformation::new(0, [QUIC_VERSION_1, 0]);
        assert_eq!(
            version_information.validation_findings(),
            vec![
                QuicVersionInformationValidation::ChosenVersionZero,
                QuicVersionInformationValidation::AvailableVersionZero { index: 1 },
            ]
        );
        let parameter = QuicTransportParameter::version_information(version_information);
        assert_eq!(
            parameter
                .version_information_value()?
                .unwrap()
                .validation_findings()[1]
                .label(),
            "version_information_available_version_zero"
        );
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_version_information_reports_malformed_lengths() {
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x11, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "quic.transport_parameter.version_information.chosen_version",
                4,
                0,
            )
        );

        assert_eq!(
            QuicTransportParameter::decode_sequence([0x11, 0x05, 0x00, 0x00, 0x00, 0x01, 0xff])
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "quic.transport_parameter.version_information",
                "version_information value length must be divisible by 4",
            )
        );
    }

    #[test]
    fn quic_transport_parameter_version_information_raw_build_preserves_bad_value() -> Result<()> {
        let parameter = QuicTransportParameter::raw(
            QuicKnownTransportParameter::VersionInformation.id(),
            [0xaa],
        );

        assert_eq!(parameter.encode_to_vec()?, [0x11, 0x01, 0xaa]);
        assert_eq!(
            parameter.version_information_value().unwrap_err(),
            CrafterError::buffer_too_short(
                "quic.transport_parameter.version_information.chosen_version",
                4,
                1,
            )
        );
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_version_information_ignores_unknown_values() -> Result<()> {
        let parameter =
            QuicTransportParameter::raw(QuicVarInt::from_u64_unchecked(0x26ab), [0, 0, 0, 1]);

        assert!(!parameter.is_version_information());
        assert_eq!(parameter.version_information_value()?, None);
        assert_eq!(parameter.value(), &[0, 0, 0, 1]);
        Ok(())
    }

    #[test]
    fn quic_transport_parameter_skeleton_reports_structured_truncation() {
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x40]).unwrap_err(),
            CrafterError::buffer_too_short("quic.transport_parameter.id", 2, 1)
        );
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x01, 0x40]).unwrap_err(),
            CrafterError::buffer_too_short("quic.transport_parameter.length", 2, 1)
        );
        assert_eq!(
            QuicTransportParameter::decode_sequence([0x01, 0x03, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("quic.transport_parameter.value", 3, 1)
        );
    }

    fn preferred_address_fixed_prefix() -> Vec<u8> {
        let mut bytes = vec![0xc0, 0x00, 0x02, 0x0a, 0x11, 0x51];
        bytes.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010).octets());
        bytes.extend_from_slice(&[0x11, 0x52]);
        bytes
    }

    fn preferred_address_tuple(value: Vec<u8>) -> Vec<u8> {
        let mut bytes = vec![0x0d, u8::try_from(value.len()).unwrap()];
        bytes.extend_from_slice(&value);
        bytes
    }
}
