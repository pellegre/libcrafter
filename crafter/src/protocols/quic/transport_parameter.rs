//! QUIC transport-parameter tuple helpers.
//!
//! RFC 9000 carries QUIC transport parameters as a sequence of
//! `(Parameter ID, Length, Value)` tuples where the first two fields are QUIC
//! variable-length integers. This module keeps that tuple layer
//! byte-preserving: value-specific interpretation and endpoint negotiation
//! policy are added by later steps.

use std::collections::BTreeMap;

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
        vec![
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
        ]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::quic::varint::is_shortest_encoding;

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
}
