//! QUIC transport-parameter tuple helpers.
//!
//! RFC 9000 carries QUIC transport parameters as a sequence of
//! `(Parameter ID, Length, Value)` tuples where the first two fields are QUIC
//! variable-length integers. This module keeps that tuple layer
//! byte-preserving: value-specific interpretation and endpoint negotiation
//! policy are added by later steps.

use std::collections::BTreeMap;

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
            0x01, 0x00, // duplicate max_idle_timeout with empty value
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
        let bytes = [0x40, 0x01, 0x40, 0x00];

        let parameters = QuicTransportParameter::decode_sequence(bytes)?;

        assert_eq!(parameters[0].identifier().unwrap().value(), 1);
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
