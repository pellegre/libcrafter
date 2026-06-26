//! QUIC frame helpers.
//!
//! This module starts with a raw-preserving frame scaffold. Later steps add
//! source-backed typed bodies for individual frame grammars.

use crate::protocols::transport::common::hex_bytes;
use crate::{CrafterError, Result};

use super::QuicVarInt;

/// Core QUIC frame type families selected for packet-layer parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicKnownFrameType {
    /// PADDING frame (`0x00`).
    Padding,
    /// PING frame (`0x01`).
    Ping,
    /// ACK frame without ECN counts (`0x02`).
    Ack,
    /// ACK frame with ECN counts (`0x03`).
    AckEcn,
    /// RESET_STREAM frame (`0x04`).
    ResetStream,
    /// STOP_SENDING frame (`0x05`).
    StopSending,
    /// CRYPTO frame (`0x06`).
    Crypto,
    /// NEW_TOKEN frame (`0x07`).
    NewToken,
    /// STREAM frame (`0x08..=0x0f`).
    Stream,
    /// MAX_DATA frame (`0x10`).
    MaxData,
    /// MAX_STREAM_DATA frame (`0x11`).
    MaxStreamData,
    /// MAX_STREAMS frame (`0x12..=0x13`).
    MaxStreams,
    /// DATA_BLOCKED frame (`0x14`).
    DataBlocked,
    /// STREAM_DATA_BLOCKED frame (`0x15`).
    StreamDataBlocked,
    /// STREAMS_BLOCKED frame (`0x16..=0x17`).
    StreamsBlocked,
    /// NEW_CONNECTION_ID frame (`0x18`).
    NewConnectionId,
    /// RETIRE_CONNECTION_ID frame (`0x19`).
    RetireConnectionId,
    /// PATH_CHALLENGE frame (`0x1a`).
    PathChallenge,
    /// PATH_RESPONSE frame (`0x1b`).
    PathResponse,
    /// CONNECTION_CLOSE transport frame (`0x1c`).
    ConnectionCloseTransport,
    /// CONNECTION_CLOSE application frame (`0x1d`).
    ConnectionCloseApplication,
    /// HANDSHAKE_DONE frame (`0x1e`).
    HandshakeDone,
    /// DATAGRAM frame without Length (`0x30`).
    Datagram,
    /// DATAGRAM frame with Length (`0x31`).
    DatagramLen,
}

impl QuicKnownFrameType {
    /// Stable frame name for summaries and inspection.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Padding => "PADDING",
            Self::Ping => "PING",
            Self::Ack => "ACK",
            Self::AckEcn => "ACK_ECN",
            Self::ResetStream => "RESET_STREAM",
            Self::StopSending => "STOP_SENDING",
            Self::Crypto => "CRYPTO",
            Self::NewToken => "NEW_TOKEN",
            Self::Stream => "STREAM",
            Self::MaxData => "MAX_DATA",
            Self::MaxStreamData => "MAX_STREAM_DATA",
            Self::MaxStreams => "MAX_STREAMS",
            Self::DataBlocked => "DATA_BLOCKED",
            Self::StreamDataBlocked => "STREAM_DATA_BLOCKED",
            Self::StreamsBlocked => "STREAMS_BLOCKED",
            Self::NewConnectionId => "NEW_CONNECTION_ID",
            Self::RetireConnectionId => "RETIRE_CONNECTION_ID",
            Self::PathChallenge => "PATH_CHALLENGE",
            Self::PathResponse => "PATH_RESPONSE",
            Self::ConnectionCloseTransport => "CONNECTION_CLOSE_TRANSPORT",
            Self::ConnectionCloseApplication => "CONNECTION_CLOSE_APPLICATION",
            Self::HandshakeDone => "HANDSHAKE_DONE",
            Self::Datagram => "DATAGRAM",
            Self::DatagramLen => "DATAGRAM_LEN",
        }
    }
}

/// Raw-preserving QUIC frame classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicFrameKind {
    /// A selected frame type whose body parser is or will be source-backed.
    Known(QuicKnownFrameType),
    /// A byte-complete but unsupported frame type.
    Unknown,
    /// Empty frame placeholder.
    Empty,
    /// Frame bytes whose type varint is incomplete.
    Truncated,
}

impl QuicFrameKind {
    /// Stable frame kind label for summaries and inspection.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Known(kind) => kind.name(),
            Self::Unknown => "UNKNOWN",
            Self::Empty => "EMPTY",
            Self::Truncated => "TRUNCATED",
        }
    }
}

/// One ACK Gap / ACK Range Length pair following the first ACK range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicAckRange {
    gap: QuicVarInt,
    ack_range_length: QuicVarInt,
}

impl QuicAckRange {
    /// Construct an ACK range pair from caller-supplied QUIC varints.
    pub const fn new(gap: QuicVarInt, ack_range_length: QuicVarInt) -> Self {
        Self {
            gap,
            ack_range_length,
        }
    }

    /// Construct an ACK range pair from validated integer values.
    pub fn from_values(gap: u64, ack_range_length: u64) -> Result<Self> {
        Ok(Self {
            gap: QuicVarInt::new(gap)?,
            ack_range_length: QuicVarInt::new(ack_range_length)?,
        })
    }

    /// Return the encoded Gap field.
    pub const fn gap(self) -> QuicVarInt {
        self.gap
    }

    /// Return the encoded ACK Range Length field.
    pub const fn ack_range_length(self) -> QuicVarInt {
        self.ack_range_length
    }
}

/// ACK_ECN ECN counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicAckEcnCounts {
    ect0_count: QuicVarInt,
    ect1_count: QuicVarInt,
    ce_count: QuicVarInt,
}

impl QuicAckEcnCounts {
    /// Construct ACK_ECN counters from caller-supplied QUIC varints.
    pub const fn new(ect0_count: QuicVarInt, ect1_count: QuicVarInt, ce_count: QuicVarInt) -> Self {
        Self {
            ect0_count,
            ect1_count,
            ce_count,
        }
    }

    /// Construct ACK_ECN counters from validated integer values.
    pub fn from_values(ect0_count: u64, ect1_count: u64, ce_count: u64) -> Result<Self> {
        Ok(Self {
            ect0_count: QuicVarInt::new(ect0_count)?,
            ect1_count: QuicVarInt::new(ect1_count)?,
            ce_count: QuicVarInt::new(ce_count)?,
        })
    }

    /// Return the ECT(0) count.
    pub const fn ect0_count(self) -> QuicVarInt {
        self.ect0_count
    }

    /// Return the ECT(1) count.
    pub const fn ect1_count(self) -> QuicVarInt {
        self.ect1_count
    }

    /// Return the ECN-CE count.
    pub const fn ce_count(self) -> QuicVarInt {
        self.ce_count
    }
}

/// Parsed ACK or ACK_ECN frame fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicAckFrame {
    largest_acknowledged: QuicVarInt,
    ack_delay: QuicVarInt,
    first_ack_range: QuicVarInt,
    ack_ranges: Vec<QuicAckRange>,
    ecn_counts: Option<QuicAckEcnCounts>,
}

impl QuicAckFrame {
    /// Construct an ACK frame from caller-supplied fields.
    pub fn new(
        largest_acknowledged: QuicVarInt,
        ack_delay: QuicVarInt,
        first_ack_range: QuicVarInt,
        ack_ranges: impl IntoIterator<Item = QuicAckRange>,
    ) -> Self {
        Self {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ack_ranges: ack_ranges.into_iter().collect(),
            ecn_counts: None,
        }
    }

    /// Construct an ACK frame from validated integer values.
    pub fn from_values(
        largest_acknowledged: u64,
        ack_delay: u64,
        first_ack_range: u64,
        ack_ranges: impl IntoIterator<Item = QuicAckRange>,
    ) -> Result<Self> {
        Ok(Self::new(
            QuicVarInt::new(largest_acknowledged)?,
            QuicVarInt::new(ack_delay)?,
            QuicVarInt::new(first_ack_range)?,
            ack_ranges,
        ))
    }

    /// Add ACK_ECN counters, selecting frame type `0x03` during encoding.
    pub fn with_ecn_counts(mut self, ecn_counts: QuicAckEcnCounts) -> Self {
        self.ecn_counts = Some(ecn_counts);
        self
    }

    /// Return true when this frame encodes ACK_ECN counters.
    pub const fn is_ecn(&self) -> bool {
        self.ecn_counts.is_some()
    }

    /// Return the frame type selected by the parsed fields.
    pub const fn frame_type(&self) -> QuicKnownFrameType {
        if self.is_ecn() {
            QuicKnownFrameType::AckEcn
        } else {
            QuicKnownFrameType::Ack
        }
    }

    /// Return the largest acknowledged packet number value.
    pub const fn largest_acknowledged(&self) -> QuicVarInt {
        self.largest_acknowledged
    }

    /// Return the raw ACK Delay value.
    pub const fn ack_delay(&self) -> QuicVarInt {
        self.ack_delay
    }

    /// Return the first ACK Range value.
    pub const fn first_ack_range(&self) -> QuicVarInt {
        self.first_ack_range
    }

    /// Return the additional ACK ranges.
    pub fn ack_ranges(&self) -> &[QuicAckRange] {
        &self.ack_ranges
    }

    /// Return the encoded ACK Range Count value.
    pub fn ack_range_count(&self) -> Result<QuicVarInt> {
        QuicVarInt::new(u64::try_from(self.ack_ranges.len()).map_err(|_| {
            CrafterError::invalid_field_value("quic.frame.ack.range_count", "too many ACK ranges")
        })?)
    }

    /// Return optional ACK_ECN counters.
    pub const fn ecn_counts(&self) -> Option<QuicAckEcnCounts> {
        self.ecn_counts
    }

    /// Decode one ACK or ACK_ECN frame from bytes that include the Frame Type.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let (frame, consumed) = decode_ack_frame(bytes)?;
        if consumed != bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "quic.frame.ack",
                "ACK frame has trailing bytes",
            ));
        }
        Ok(frame)
    }

    /// Append the canonical ACK or ACK_ECN frame encoding.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let frame_type = if self.is_ecn() { 0x03 } else { 0x02 };
        QuicVarInt::from_u64_unchecked(frame_type).encode(out)?;
        self.largest_acknowledged.encode(out)?;
        self.ack_delay.encode(out)?;
        self.ack_range_count()?.encode(out)?;
        self.first_ack_range.encode(out)?;
        for range in &self.ack_ranges {
            range.gap.encode(out)?;
            range.ack_range_length.encode(out)?;
        }
        if let Some(ecn_counts) = self.ecn_counts {
            ecn_counts.ect0_count.encode(out)?;
            ecn_counts.ect1_count.encode(out)?;
            ecn_counts.ce_count.encode(out)?;
        }
        Ok(())
    }

    /// Return the canonical ACK or ACK_ECN frame encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Stable ACK summary for packet inspection.
    pub fn summary(&self) -> String {
        let mut summary = format!(
            "kind={} largest_acknowledged={} ack_delay={} first_ack_range={} ranges={}",
            self.frame_type().name(),
            self.largest_acknowledged.value(),
            self.ack_delay.value(),
            self.first_ack_range.value(),
            self.ack_ranges.len()
        );
        if let Some(ecn_counts) = self.ecn_counts {
            summary.push_str(&format!(
                " ect0={} ect1={} ce={}",
                ecn_counts.ect0_count.value(),
                ecn_counts.ect1_count.value(),
                ecn_counts.ce_count.value()
            ));
        }
        summary
    }

    /// Stable field/value pairs for ACK inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "ack_largest_acknowledged",
                self.largest_acknowledged.value().to_string(),
            ),
            ("ack_delay", self.ack_delay.value().to_string()),
            ("ack_range_count", self.ack_ranges.len().to_string()),
            ("ack_first_range", self.first_ack_range.value().to_string()),
        ];
        for range in &self.ack_ranges {
            fields.push((
                "ack_range",
                format!(
                    "gap={} length={}",
                    range.gap.value(),
                    range.ack_range_length.value()
                ),
            ));
        }
        if let Some(ecn_counts) = self.ecn_counts {
            fields.extend([
                ("ack_ecn_ect0", ecn_counts.ect0_count.value().to_string()),
                ("ack_ecn_ect1", ecn_counts.ect1_count.value().to_string()),
                ("ack_ecn_ce", ecn_counts.ce_count.value().to_string()),
            ]);
        }
        fields
    }
}

/// Parsed RESET_STREAM frame fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicResetStreamFrame {
    stream_id: QuicVarInt,
    application_error_code: QuicVarInt,
    final_size: QuicVarInt,
}

impl QuicResetStreamFrame {
    /// Construct a RESET_STREAM frame from caller-supplied fields.
    pub const fn new(
        stream_id: QuicVarInt,
        application_error_code: QuicVarInt,
        final_size: QuicVarInt,
    ) -> Self {
        Self {
            stream_id,
            application_error_code,
            final_size,
        }
    }

    /// Construct a RESET_STREAM frame from validated integer values.
    pub fn from_values(
        stream_id: u64,
        application_error_code: u64,
        final_size: u64,
    ) -> Result<Self> {
        Ok(Self::new(
            QuicVarInt::new(stream_id)?,
            QuicVarInt::new(application_error_code)?,
            QuicVarInt::new(final_size)?,
        ))
    }

    /// Return the Stream ID field.
    pub const fn stream_id(self) -> QuicVarInt {
        self.stream_id
    }

    /// Return the application protocol error code as a raw numeric value.
    pub const fn application_error_code(self) -> QuicVarInt {
        self.application_error_code
    }

    /// Return the Final Size field.
    pub const fn final_size(self) -> QuicVarInt {
        self.final_size
    }

    /// Decode one RESET_STREAM frame from bytes that include the Frame Type.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let (frame, consumed) = decode_reset_stream_frame(bytes)?;
        if consumed != bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "quic.frame.reset_stream",
                "RESET_STREAM frame has trailing bytes",
            ));
        }
        Ok(frame)
    }

    /// Append the canonical RESET_STREAM frame encoding.
    pub fn encode(self, out: &mut Vec<u8>) -> Result<()> {
        QuicVarInt::from_u64_unchecked(0x04).encode(out)?;
        self.stream_id.encode(out)?;
        self.application_error_code.encode(out)?;
        self.final_size.encode(out)?;
        Ok(())
    }

    /// Return the canonical RESET_STREAM frame encoding.
    pub fn encode_to_vec(self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Stable RESET_STREAM summary for packet inspection.
    pub fn summary(self) -> String {
        format!(
            "kind=RESET_STREAM stream_id={} application_error_code={} final_size={}",
            self.stream_id.value(),
            self.application_error_code.value(),
            self.final_size.value()
        )
    }

    /// Stable field/value pairs for RESET_STREAM inspection.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("reset_stream_id", self.stream_id.value().to_string()),
            (
                "reset_stream_application_error_code",
                self.application_error_code.value().to_string(),
            ),
            (
                "reset_stream_final_size",
                self.final_size.value().to_string(),
            ),
        ]
    }
}

/// Parsed STOP_SENDING frame fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicStopSendingFrame {
    stream_id: QuicVarInt,
    application_error_code: QuicVarInt,
}

impl QuicStopSendingFrame {
    /// Construct a STOP_SENDING frame from caller-supplied fields.
    pub const fn new(stream_id: QuicVarInt, application_error_code: QuicVarInt) -> Self {
        Self {
            stream_id,
            application_error_code,
        }
    }

    /// Construct a STOP_SENDING frame from validated integer values.
    pub fn from_values(stream_id: u64, application_error_code: u64) -> Result<Self> {
        Ok(Self::new(
            QuicVarInt::new(stream_id)?,
            QuicVarInt::new(application_error_code)?,
        ))
    }

    /// Return the Stream ID field.
    pub const fn stream_id(self) -> QuicVarInt {
        self.stream_id
    }

    /// Return the application protocol error code as a raw numeric value.
    pub const fn application_error_code(self) -> QuicVarInt {
        self.application_error_code
    }

    /// Decode one STOP_SENDING frame from bytes that include the Frame Type.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let (frame, consumed) = decode_stop_sending_frame(bytes)?;
        if consumed != bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "quic.frame.stop_sending",
                "STOP_SENDING frame has trailing bytes",
            ));
        }
        Ok(frame)
    }

    /// Append the canonical STOP_SENDING frame encoding.
    pub fn encode(self, out: &mut Vec<u8>) -> Result<()> {
        QuicVarInt::from_u64_unchecked(0x05).encode(out)?;
        self.stream_id.encode(out)?;
        self.application_error_code.encode(out)?;
        Ok(())
    }

    /// Return the canonical STOP_SENDING frame encoding.
    pub fn encode_to_vec(self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Stable STOP_SENDING summary for packet inspection.
    pub fn summary(self) -> String {
        format!(
            "kind=STOP_SENDING stream_id={} application_error_code={}",
            self.stream_id.value(),
            self.application_error_code.value()
        )
    }

    /// Stable field/value pairs for STOP_SENDING inspection.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("stop_sending_stream_id", self.stream_id.value().to_string()),
            (
                "stop_sending_application_error_code",
                self.application_error_code.value().to_string(),
            ),
        ]
    }
}

/// Parsed or buildable CRYPTO frame fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicCryptoFrame {
    offset: QuicVarInt,
    length: Option<QuicVarInt>,
    data: Vec<u8>,
}

impl QuicCryptoFrame {
    /// Construct a CRYPTO frame with an auto-filled data length.
    pub fn new(offset: QuicVarInt, data: impl AsRef<[u8]>) -> Self {
        Self {
            offset,
            length: None,
            data: data.as_ref().to_vec(),
        }
    }

    /// Construct a CRYPTO frame from validated integer fields.
    pub fn from_values(offset: u64, data: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::new(QuicVarInt::new(offset)?, data))
    }

    /// Preserve an explicit Length field, even when it does not match data.
    pub fn with_length(mut self, length: QuicVarInt) -> Self {
        self.length = Some(length);
        self
    }

    /// Return the Offset field.
    pub const fn offset(&self) -> QuicVarInt {
        self.offset
    }

    /// Return the advertised Length field, auto-filled from data when unset.
    pub fn length(&self) -> Result<QuicVarInt> {
        match self.length {
            Some(length) => Ok(length),
            None => QuicVarInt::new(u64::try_from(self.data.len()).map_err(|_| {
                CrafterError::invalid_field_value(
                    "quic.frame.crypto.length",
                    "data length exceeds u64",
                )
            })?),
        }
    }

    /// Return a caller-pinned Length field when present.
    pub const fn length_override(&self) -> Option<QuicVarInt> {
        self.length
    }

    /// Borrow the opaque CRYPTO data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Decode one CRYPTO frame from bytes that include the Frame Type.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let (frame, consumed) = decode_crypto_frame(bytes)?;
        if consumed != bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "quic.frame.crypto",
                "CRYPTO frame has trailing bytes",
            ));
        }
        Ok(frame)
    }

    /// Append the canonical CRYPTO frame encoding, preserving explicit Length.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        QuicVarInt::from_u64_unchecked(0x06).encode(out)?;
        self.offset.encode(out)?;
        self.length()?.encode(out)?;
        out.extend_from_slice(&self.data);
        Ok(())
    }

    /// Return the canonical CRYPTO frame encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Stable CRYPTO summary for packet inspection.
    pub fn summary(&self) -> String {
        format!(
            "kind=CRYPTO offset={} length={} data_len={}",
            self.offset.value(),
            self.length().map(|length| length.value()).unwrap_or(0),
            self.data.len()
        )
    }

    /// Stable field/value pairs for CRYPTO inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("crypto_offset", self.offset.value().to_string()),
            (
                "crypto_length",
                self.length()
                    .map(|length| length.value().to_string())
                    .unwrap_or_else(|_| "<invalid>".to_string()),
            ),
            ("crypto_data_len", self.data.len().to_string()),
            ("crypto_data", hex_bytes(&self.data)),
        ]
    }
}

/// Parsed or buildable NEW_TOKEN frame fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicNewTokenFrame {
    token_length: Option<QuicVarInt>,
    token: Vec<u8>,
}

impl QuicNewTokenFrame {
    /// Construct a NEW_TOKEN frame with an auto-filled token length.
    pub fn new(token: impl AsRef<[u8]>) -> Self {
        Self {
            token_length: None,
            token: token.as_ref().to_vec(),
        }
    }

    /// Preserve an explicit Token Length field, even when it does not match.
    pub fn with_token_length(mut self, token_length: QuicVarInt) -> Self {
        self.token_length = Some(token_length);
        self
    }

    /// Return the advertised Token Length field, auto-filled from token bytes.
    pub fn token_length(&self) -> Result<QuicVarInt> {
        match self.token_length {
            Some(token_length) => Ok(token_length),
            None => QuicVarInt::new(u64::try_from(self.token.len()).map_err(|_| {
                CrafterError::invalid_field_value(
                    "quic.frame.new_token.token_length",
                    "token length exceeds u64",
                )
            })?),
        }
    }

    /// Return a caller-pinned Token Length field when present.
    pub const fn token_length_override(&self) -> Option<QuicVarInt> {
        self.token_length
    }

    /// Borrow the opaque token bytes.
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Decode one NEW_TOKEN frame from bytes that include the Frame Type.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let (frame, consumed) = decode_new_token_frame(bytes)?;
        if consumed != bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "quic.frame.new_token",
                "NEW_TOKEN frame has trailing bytes",
            ));
        }
        Ok(frame)
    }

    /// Append the canonical NEW_TOKEN frame encoding, preserving explicit Length.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        QuicVarInt::from_u64_unchecked(0x07).encode(out)?;
        self.token_length()?.encode(out)?;
        out.extend_from_slice(&self.token);
        Ok(())
    }

    /// Return the canonical NEW_TOKEN frame encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Stable NEW_TOKEN summary for packet inspection.
    pub fn summary(&self) -> String {
        format!(
            "kind=NEW_TOKEN token_length={} token_len={}",
            self.token_length()
                .map(|length| length.value())
                .unwrap_or(0),
            self.token.len()
        )
    }

    /// Stable field/value pairs for NEW_TOKEN inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "new_token_length",
                self.token_length()
                    .map(|length| length.value().to_string())
                    .unwrap_or_else(|_| "<invalid>".to_string()),
            ),
            ("new_token_len", self.token.len().to_string()),
            ("new_token", hex_bytes(&self.token)),
        ]
    }
}

/// Parsed or buildable STREAM frame fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicStreamFrame {
    stream_id: QuicVarInt,
    offset: Option<QuicVarInt>,
    include_length: bool,
    length: Option<QuicVarInt>,
    fin: bool,
    data: Vec<u8>,
}

impl QuicStreamFrame {
    /// Construct a STREAM frame with an auto-filled Length field.
    pub fn new(stream_id: QuicVarInt, data: impl AsRef<[u8]>) -> Self {
        Self {
            stream_id,
            offset: None,
            include_length: true,
            length: None,
            fin: false,
            data: data.as_ref().to_vec(),
        }
    }

    /// Construct a STREAM frame from validated integer fields.
    pub fn from_values(stream_id: u64, data: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::new(QuicVarInt::new(stream_id)?, data))
    }

    /// Include an Offset field.
    pub fn with_offset(mut self, offset: QuicVarInt) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Preserve an explicit Length field and set the LEN bit.
    pub fn with_length(mut self, length: QuicVarInt) -> Self {
        self.include_length = true;
        self.length = Some(length);
        self
    }

    /// Omit the Length field so data extends to the containing packet end.
    pub fn without_length(mut self) -> Self {
        self.include_length = false;
        self.length = None;
        self
    }

    /// Set or clear the FIN bit.
    pub fn with_fin(mut self, fin: bool) -> Self {
        self.fin = fin;
        self
    }

    /// Return the Stream ID field.
    pub const fn stream_id(&self) -> QuicVarInt {
        self.stream_id
    }

    /// Return the Offset field when present.
    pub const fn offset(&self) -> Option<QuicVarInt> {
        self.offset
    }

    /// Return true when the LEN bit is present.
    pub const fn has_length(&self) -> bool {
        self.include_length
    }

    /// Return the advertised Length field when the LEN bit is present.
    pub fn length(&self) -> Result<Option<QuicVarInt>> {
        if !self.include_length {
            return Ok(None);
        }
        match self.length {
            Some(length) => Ok(Some(length)),
            None => Ok(Some(QuicVarInt::new(
                u64::try_from(self.data.len()).map_err(|_| {
                    CrafterError::invalid_field_value(
                        "quic.frame.stream.length",
                        "data length exceeds u64",
                    )
                })?,
            )?)),
        }
    }

    /// Return a caller-pinned Length field when present.
    pub const fn length_override(&self) -> Option<QuicVarInt> {
        self.length
    }

    /// Return true when the FIN bit is set.
    pub const fn fin(&self) -> bool {
        self.fin
    }

    /// Borrow the stream data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Decode one STREAM frame from bytes that include the Frame Type.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let (frame, consumed) = decode_stream_frame(bytes)?;
        if consumed != bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "quic.frame.stream",
                "STREAM frame has trailing bytes",
            ));
        }
        Ok(frame)
    }

    /// Append the canonical STREAM frame encoding, preserving explicit Length.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut frame_type = 0x08;
        if self.offset.is_some() {
            frame_type |= 0x04;
        }
        if self.include_length {
            frame_type |= 0x02;
        }
        if self.fin {
            frame_type |= 0x01;
        }

        QuicVarInt::from_u64_unchecked(frame_type).encode(out)?;
        self.stream_id.encode(out)?;
        if let Some(offset) = self.offset {
            offset.encode(out)?;
        }
        if let Some(length) = self.length()? {
            length.encode(out)?;
        }
        out.extend_from_slice(&self.data);
        Ok(())
    }

    /// Return the canonical STREAM frame encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Stable STREAM summary for packet inspection.
    pub fn summary(&self) -> String {
        let offset = self
            .offset
            .map(|offset| offset.value().to_string())
            .unwrap_or_else(|| "<none>".to_string());
        let length = self
            .length()
            .ok()
            .flatten()
            .map(|length| length.value().to_string())
            .unwrap_or_else(|| "<packet-end>".to_string());
        format!(
            "kind=STREAM stream_id={} offset={} length={} fin={} data_len={}",
            self.stream_id.value(),
            offset,
            length,
            self.fin,
            self.data.len()
        )
    }

    /// Stable field/value pairs for STREAM inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("stream_id", self.stream_id.value().to_string()),
            (
                "stream_offset",
                self.offset
                    .map(|offset| offset.value().to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
            ),
            (
                "stream_length",
                self.length()
                    .ok()
                    .flatten()
                    .map(|length| length.value().to_string())
                    .unwrap_or_else(|| "<packet-end>".to_string()),
            ),
            ("stream_fin", self.fin.to_string()),
            ("stream_data_len", self.data.len().to_string()),
            ("stream_data", hex_bytes(&self.data)),
        ]
    }
}

/// Raw-preserving QUIC frame.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicFrame {
    bytes: Vec<u8>,
    kind: QuicFrameKind,
}

impl QuicFrame {
    /// Preserve raw frame bytes without attempting to classify them.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref();
        Self {
            bytes: bytes.to_vec(),
            kind: classify_frame_kind(bytes),
        }
    }

    /// Construct a PADDING run that emits `count` zero bytes.
    pub fn padding(count: usize) -> Self {
        let bytes = vec![0x00; count];
        Self {
            kind: classify_frame_kind(&bytes),
            bytes,
        }
    }

    /// Construct a PING frame.
    pub fn ping() -> Self {
        Self {
            bytes: vec![0x01],
            kind: QuicFrameKind::Known(QuicKnownFrameType::Ping),
        }
    }

    /// Construct an ACK or ACK_ECN frame from typed fields.
    pub fn from_ack_frame(ack: QuicAckFrame) -> Result<Self> {
        Ok(Self::from_bytes(ack.encode_to_vec()?))
    }

    /// Construct an ACK frame from caller-supplied fields.
    pub fn ack(
        largest_acknowledged: QuicVarInt,
        ack_delay: QuicVarInt,
        first_ack_range: QuicVarInt,
        ack_ranges: impl IntoIterator<Item = QuicAckRange>,
    ) -> Result<Self> {
        Self::from_ack_frame(QuicAckFrame::new(
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ack_ranges,
        ))
    }

    /// Construct an ACK_ECN frame from caller-supplied fields.
    pub fn ack_ecn(
        largest_acknowledged: QuicVarInt,
        ack_delay: QuicVarInt,
        first_ack_range: QuicVarInt,
        ack_ranges: impl IntoIterator<Item = QuicAckRange>,
        ecn_counts: QuicAckEcnCounts,
    ) -> Result<Self> {
        Self::from_ack_frame(
            QuicAckFrame::new(largest_acknowledged, ack_delay, first_ack_range, ack_ranges)
                .with_ecn_counts(ecn_counts),
        )
    }

    /// Construct a RESET_STREAM frame from typed fields.
    pub fn from_reset_stream_frame(reset_stream: QuicResetStreamFrame) -> Result<Self> {
        Ok(Self::from_bytes(reset_stream.encode_to_vec()?))
    }

    /// Construct a RESET_STREAM frame from caller-supplied fields.
    pub fn reset_stream(
        stream_id: QuicVarInt,
        application_error_code: QuicVarInt,
        final_size: QuicVarInt,
    ) -> Result<Self> {
        Self::from_reset_stream_frame(QuicResetStreamFrame::new(
            stream_id,
            application_error_code,
            final_size,
        ))
    }

    /// Construct a STOP_SENDING frame from typed fields.
    pub fn from_stop_sending_frame(stop_sending: QuicStopSendingFrame) -> Result<Self> {
        Ok(Self::from_bytes(stop_sending.encode_to_vec()?))
    }

    /// Construct a STOP_SENDING frame from caller-supplied fields.
    pub fn stop_sending(stream_id: QuicVarInt, application_error_code: QuicVarInt) -> Result<Self> {
        Self::from_stop_sending_frame(QuicStopSendingFrame::new(stream_id, application_error_code))
    }

    /// Construct a CRYPTO frame from typed fields.
    pub fn from_crypto_frame(crypto: QuicCryptoFrame) -> Result<Self> {
        Ok(Self::from_bytes(crypto.encode_to_vec()?))
    }

    /// Construct a CRYPTO frame with an auto-filled data length.
    pub fn crypto(offset: QuicVarInt, data: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_crypto_frame(QuicCryptoFrame::new(offset, data))
    }

    /// Construct a NEW_TOKEN frame from typed fields.
    pub fn from_new_token_frame(new_token: QuicNewTokenFrame) -> Result<Self> {
        Ok(Self::from_bytes(new_token.encode_to_vec()?))
    }

    /// Construct a NEW_TOKEN frame with an auto-filled token length.
    pub fn new_token(token: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_new_token_frame(QuicNewTokenFrame::new(token))
    }

    /// Construct a STREAM frame from typed fields.
    pub fn from_stream_frame(stream: QuicStreamFrame) -> Result<Self> {
        Ok(Self::from_bytes(stream.encode_to_vec()?))
    }

    /// Construct a STREAM frame with an auto-filled Length field.
    pub fn stream(stream_id: QuicVarInt, data: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_stream_frame(QuicStreamFrame::new(stream_id, data))
    }

    /// Decode a frame sequence within the caller-provided packet boundary.
    ///
    /// Supported fixed-boundary frames are split out first. The remaining
    /// unsupported tail is preserved as one raw frame because QUIC frame types
    /// are not self-describing without type-specific grammar.
    pub fn decode_sequence(bytes: impl AsRef<[u8]>) -> Result<Vec<Self>> {
        let bytes = bytes.as_ref();
        let mut frames = Vec::new();
        let mut offset = 0;

        while offset < bytes.len() {
            let (frame_type, consumed) = QuicVarInt::decode(&bytes[offset..])?;
            match frame_type.value() {
                0x00 if bytes[offset] == 0x00 => {
                    let start = offset;
                    offset += 1;
                    while offset < bytes.len() && bytes[offset] == 0x00 {
                        offset += 1;
                    }
                    frames.push(Self::from_bytes(&bytes[start..offset]));
                }
                0x01 => {
                    let end = offset + consumed;
                    frames.push(Self::from_bytes(&bytes[offset..end]));
                    offset = end;
                }
                0x02 | 0x03 => {
                    let (_, ack_len) = decode_ack_frame(&bytes[offset..])?;
                    let end = offset + ack_len;
                    frames.push(Self::from_bytes(&bytes[offset..end]));
                    offset = end;
                }
                0x04 => {
                    let (_, reset_stream_len) = decode_reset_stream_frame(&bytes[offset..])?;
                    let end = offset + reset_stream_len;
                    frames.push(Self::from_bytes(&bytes[offset..end]));
                    offset = end;
                }
                0x05 => {
                    let (_, stop_sending_len) = decode_stop_sending_frame(&bytes[offset..])?;
                    let end = offset + stop_sending_len;
                    frames.push(Self::from_bytes(&bytes[offset..end]));
                    offset = end;
                }
                0x06 => {
                    let (_, crypto_len) = decode_crypto_frame(&bytes[offset..])?;
                    let end = offset + crypto_len;
                    frames.push(Self::from_bytes(&bytes[offset..end]));
                    offset = end;
                }
                0x07 => {
                    let (_, new_token_len) = decode_new_token_frame(&bytes[offset..])?;
                    let end = offset + new_token_len;
                    frames.push(Self::from_bytes(&bytes[offset..end]));
                    offset = end;
                }
                0x08..=0x0f => {
                    let (_, stream_len) = decode_stream_frame(&bytes[offset..])?;
                    let end = offset + stream_len;
                    frames.push(Self::from_bytes(&bytes[offset..end]));
                    offset = end;
                }
                _ => {
                    frames.push(Self::from_bytes(&bytes[offset..]));
                    break;
                }
            }
        }

        Ok(frames)
    }

    /// Encode a frame sequence into a contiguous payload buffer.
    pub fn encode_sequence(frames: impl IntoIterator<Item = Self>) -> Vec<u8> {
        let mut out = Vec::new();
        for frame in frames {
            frame.encode(&mut out);
        }
        out
    }

    /// Return the frame classification.
    pub const fn kind(&self) -> QuicFrameKind {
        self.kind
    }

    /// Return true when this frame is a byte-complete PADDING run.
    pub fn is_padding(&self) -> bool {
        matches!(self.kind, QuicFrameKind::Known(QuicKnownFrameType::Padding))
            && self.bytes.iter().all(|byte| *byte == 0x00)
    }

    /// Return the number of zero bytes represented by this PADDING run.
    pub fn padding_len(&self) -> Option<usize> {
        self.is_padding().then_some(self.bytes.len())
    }

    /// Return true when this frame is a byte-complete PING frame.
    pub fn is_ping(&self) -> bool {
        matches!(self.kind, QuicFrameKind::Known(QuicKnownFrameType::Ping))
            && self.frame_type_value() == Some(0x01)
            && self.frame_type_encoded_len() == Some(self.bytes.len())
    }

    /// Decode this frame as ACK or ACK_ECN when applicable.
    pub fn ack_frame(&self) -> Result<Option<QuicAckFrame>> {
        match self.frame_type_value() {
            Some(0x02 | 0x03) => Ok(Some(QuicAckFrame::decode(&self.bytes)?)),
            _ => Ok(None),
        }
    }

    /// Decode this frame as RESET_STREAM when applicable.
    pub fn reset_stream_frame(&self) -> Result<Option<QuicResetStreamFrame>> {
        match self.frame_type_value() {
            Some(0x04) => Ok(Some(QuicResetStreamFrame::decode(&self.bytes)?)),
            _ => Ok(None),
        }
    }

    /// Decode this frame as STOP_SENDING when applicable.
    pub fn stop_sending_frame(&self) -> Result<Option<QuicStopSendingFrame>> {
        match self.frame_type_value() {
            Some(0x05) => Ok(Some(QuicStopSendingFrame::decode(&self.bytes)?)),
            _ => Ok(None),
        }
    }

    /// Decode this frame as CRYPTO when applicable.
    pub fn crypto_frame(&self) -> Result<Option<QuicCryptoFrame>> {
        match self.frame_type_value() {
            Some(0x06) => Ok(Some(QuicCryptoFrame::decode(&self.bytes)?)),
            _ => Ok(None),
        }
    }

    /// Decode this frame as NEW_TOKEN when applicable.
    pub fn new_token_frame(&self) -> Result<Option<QuicNewTokenFrame>> {
        match self.frame_type_value() {
            Some(0x07) => Ok(Some(QuicNewTokenFrame::decode(&self.bytes)?)),
            _ => Ok(None),
        }
    }

    /// Decode this frame as STREAM when applicable.
    pub fn stream_frame(&self) -> Result<Option<QuicStreamFrame>> {
        match self.frame_type_value() {
            Some(0x08..=0x0f) => Ok(Some(QuicStreamFrame::decode(&self.bytes)?)),
            _ => Ok(None),
        }
    }

    /// Borrow the preserved frame bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the preserved frame bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Encoded frame length in bytes.
    pub fn encoded_len(&self) -> usize {
        self.len()
    }

    /// Return true when no frame bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return the raw frame type varint when a byte-complete type is available.
    pub fn frame_type(&self) -> Option<QuicVarInt> {
        QuicVarInt::decode(&self.bytes)
            .ok()
            .map(|(frame_type, _)| frame_type)
    }

    /// Return the raw frame type value when available.
    pub fn frame_type_value(&self) -> Option<u64> {
        self.frame_type().map(QuicVarInt::value)
    }

    /// Return the encoded width of the frame type varint when available.
    pub fn frame_type_encoded_len(&self) -> Option<usize> {
        QuicVarInt::decode(&self.bytes)
            .ok()
            .map(|(_, consumed)| consumed)
    }

    /// Append the frame bytes to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    /// Return this frame's encoded bytes as a vector.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Stable summary for packet inspection.
    pub fn summary(&self) -> String {
        if let Some(padding_len) = self.padding_len() {
            return format!("kind=PADDING padding_len={padding_len}");
        }
        if let Ok(Some(ack)) = self.ack_frame() {
            return ack.summary();
        }
        if let Ok(Some(reset_stream)) = self.reset_stream_frame() {
            return reset_stream.summary();
        }
        if let Ok(Some(stop_sending)) = self.stop_sending_frame() {
            return stop_sending.summary();
        }
        if let Ok(Some(crypto)) = self.crypto_frame() {
            return crypto.summary();
        }
        if let Ok(Some(new_token)) = self.new_token_frame() {
            return new_token.summary();
        }
        if let Ok(Some(stream)) = self.stream_frame() {
            return stream.summary();
        }
        match self.frame_type() {
            Some(frame_type) => format!(
                "kind={} type=0x{:x} raw_len={}",
                self.kind.label(),
                frame_type.value(),
                self.bytes.len()
            ),
            None if self.bytes.is_empty() => "kind=EMPTY type=<empty> raw_len=0".to_string(),
            None => format!(
                "kind=TRUNCATED type=<truncated> raw_len={}",
                self.bytes.len()
            ),
        }
    }

    /// Stable field/value pairs for packet inspection.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("frame_kind", self.kind.label().to_string()),
            (
                "frame_type",
                self.frame_type()
                    .map(|frame_type| format!("0x{:x}", frame_type.value()))
                    .unwrap_or_else(|| "<unavailable>".to_string()),
            ),
            (
                "frame_type_encoded_len",
                self.frame_type_encoded_len()
                    .map(|len| len.to_string())
                    .unwrap_or_else(|| "<unavailable>".to_string()),
            ),
            ("raw_len", self.bytes.len().to_string()),
            ("raw_bytes", hex_bytes(&self.bytes)),
        ];
        if let Some(padding_len) = self.padding_len() {
            fields.push(("padding_len", padding_len.to_string()));
        }
        if let Ok(Some(ack)) = self.ack_frame() {
            fields.extend(ack.inspection_fields());
        }
        if let Ok(Some(reset_stream)) = self.reset_stream_frame() {
            fields.extend(reset_stream.inspection_fields());
        }
        if let Ok(Some(stop_sending)) = self.stop_sending_frame() {
            fields.extend(stop_sending.inspection_fields());
        }
        if let Ok(Some(crypto)) = self.crypto_frame() {
            fields.extend(crypto.inspection_fields());
        }
        if let Ok(Some(new_token)) = self.new_token_frame() {
            fields.extend(new_token.inspection_fields());
        }
        if let Ok(Some(stream)) = self.stream_frame() {
            fields.extend(stream.inspection_fields());
        }
        fields
    }
}

impl Default for QuicFrameKind {
    fn default() -> Self {
        Self::Empty
    }
}

fn decode_ack_frame(bytes: &[u8]) -> Result<(QuicAckFrame, usize)> {
    let (frame_type, mut offset) = decode_frame_varint(bytes, 0, "quic.frame.type")?;
    let is_ecn = match frame_type.value() {
        0x02 => false,
        0x03 => true,
        _ => {
            return Err(CrafterError::invalid_field_value(
                "quic.frame.ack.type",
                "ACK frame type must be 0x02 or 0x03",
            ))
        }
    };

    let (largest_acknowledged, next) =
        decode_frame_varint(bytes, offset, "quic.frame.ack.largest_acknowledged")?;
    offset = next;
    let (ack_delay, next) = decode_frame_varint(bytes, offset, "quic.frame.ack.ack_delay")?;
    offset = next;
    let (range_count, next) = decode_frame_varint(bytes, offset, "quic.frame.ack.range_count")?;
    offset = next;
    let (first_ack_range, next) = decode_frame_varint(bytes, offset, "quic.frame.ack.first_range")?;
    offset = next;

    let mut ack_ranges = Vec::new();
    for _ in 0..range_count.value() {
        let (gap, next) = decode_frame_varint(bytes, offset, "quic.frame.ack.range.gap")?;
        offset = next;
        let (ack_range_length, next) =
            decode_frame_varint(bytes, offset, "quic.frame.ack.range.length")?;
        offset = next;
        ack_ranges.push(QuicAckRange::new(gap, ack_range_length));
    }

    let ecn_counts = if is_ecn {
        let (ect0_count, next) = decode_frame_varint(bytes, offset, "quic.frame.ack.ecn.ect0")?;
        offset = next;
        let (ect1_count, next) = decode_frame_varint(bytes, offset, "quic.frame.ack.ecn.ect1")?;
        offset = next;
        let (ce_count, next) = decode_frame_varint(bytes, offset, "quic.frame.ack.ecn.ce")?;
        offset = next;
        Some(QuicAckEcnCounts::new(ect0_count, ect1_count, ce_count))
    } else {
        None
    };

    Ok((
        QuicAckFrame {
            largest_acknowledged,
            ack_delay,
            first_ack_range,
            ack_ranges,
            ecn_counts,
        },
        offset,
    ))
}

fn decode_reset_stream_frame(bytes: &[u8]) -> Result<(QuicResetStreamFrame, usize)> {
    let (frame_type, mut offset) = decode_frame_varint(bytes, 0, "quic.frame.type")?;
    if frame_type.value() != 0x04 {
        return Err(CrafterError::invalid_field_value(
            "quic.frame.reset_stream.type",
            "RESET_STREAM frame type must be 0x04",
        ));
    }
    let (stream_id, next) =
        decode_frame_varint(bytes, offset, "quic.frame.reset_stream.stream_id")?;
    offset = next;
    let (application_error_code, next) = decode_frame_varint(
        bytes,
        offset,
        "quic.frame.reset_stream.application_error_code",
    )?;
    offset = next;
    let (final_size, next) =
        decode_frame_varint(bytes, offset, "quic.frame.reset_stream.final_size")?;
    offset = next;

    Ok((
        QuicResetStreamFrame::new(stream_id, application_error_code, final_size),
        offset,
    ))
}

fn decode_stop_sending_frame(bytes: &[u8]) -> Result<(QuicStopSendingFrame, usize)> {
    let (frame_type, mut offset) = decode_frame_varint(bytes, 0, "quic.frame.type")?;
    if frame_type.value() != 0x05 {
        return Err(CrafterError::invalid_field_value(
            "quic.frame.stop_sending.type",
            "STOP_SENDING frame type must be 0x05",
        ));
    }
    let (stream_id, next) =
        decode_frame_varint(bytes, offset, "quic.frame.stop_sending.stream_id")?;
    offset = next;
    let (application_error_code, next) = decode_frame_varint(
        bytes,
        offset,
        "quic.frame.stop_sending.application_error_code",
    )?;
    offset = next;

    Ok((
        QuicStopSendingFrame::new(stream_id, application_error_code),
        offset,
    ))
}

fn decode_crypto_frame(bytes: &[u8]) -> Result<(QuicCryptoFrame, usize)> {
    let (frame_type, mut offset) = decode_frame_varint(bytes, 0, "quic.frame.type")?;
    if frame_type.value() != 0x06 {
        return Err(CrafterError::invalid_field_value(
            "quic.frame.crypto.type",
            "CRYPTO frame type must be 0x06",
        ));
    }
    let (crypto_offset, next) = decode_frame_varint(bytes, offset, "quic.frame.crypto.offset")?;
    offset = next;
    let (length, next) = decode_frame_varint(bytes, offset, "quic.frame.crypto.length")?;
    offset = next;

    let data_len = usize::try_from(length.value()).map_err(|_| {
        CrafterError::invalid_field_value("quic.frame.crypto.length", "length exceeds usize")
    })?;
    let available = bytes.len().saturating_sub(offset);
    if available < data_len {
        return Err(CrafterError::buffer_too_short(
            "quic.frame.crypto.data",
            data_len,
            available,
        ));
    }
    let end = offset + data_len;
    Ok((
        QuicCryptoFrame::new(crypto_offset, &bytes[offset..end]).with_length(length),
        end,
    ))
}

fn decode_new_token_frame(bytes: &[u8]) -> Result<(QuicNewTokenFrame, usize)> {
    let (frame_type, mut offset) = decode_frame_varint(bytes, 0, "quic.frame.type")?;
    if frame_type.value() != 0x07 {
        return Err(CrafterError::invalid_field_value(
            "quic.frame.new_token.type",
            "NEW_TOKEN frame type must be 0x07",
        ));
    }
    let (token_length, next) =
        decode_frame_varint(bytes, offset, "quic.frame.new_token.token_length")?;
    offset = next;

    let token_len = usize::try_from(token_length.value()).map_err(|_| {
        CrafterError::invalid_field_value(
            "quic.frame.new_token.token_length",
            "length exceeds usize",
        )
    })?;
    let available = bytes.len().saturating_sub(offset);
    if available < token_len {
        return Err(CrafterError::buffer_too_short(
            "quic.frame.new_token.token",
            token_len,
            available,
        ));
    }
    let end = offset + token_len;
    Ok((
        QuicNewTokenFrame::new(&bytes[offset..end]).with_token_length(token_length),
        end,
    ))
}

fn decode_stream_frame(bytes: &[u8]) -> Result<(QuicStreamFrame, usize)> {
    let (frame_type, mut offset) = decode_frame_varint(bytes, 0, "quic.frame.type")?;
    let frame_type_value = frame_type.value();
    if !(0x08..=0x0f).contains(&frame_type_value) {
        return Err(CrafterError::invalid_field_value(
            "quic.frame.stream.type",
            "STREAM frame type must be 0x08..0x0f",
        ));
    }

    let has_offset = frame_type_value & 0x04 != 0;
    let has_length = frame_type_value & 0x02 != 0;
    let fin = frame_type_value & 0x01 != 0;

    let (stream_id, next) = decode_frame_varint(bytes, offset, "quic.frame.stream.stream_id")?;
    offset = next;

    let stream_offset = if has_offset {
        let (stream_offset, next) = decode_frame_varint(bytes, offset, "quic.frame.stream.offset")?;
        offset = next;
        Some(stream_offset)
    } else {
        None
    };

    let (length, data_len) = if has_length {
        let (length, next) = decode_frame_varint(bytes, offset, "quic.frame.stream.length")?;
        offset = next;
        let data_len = usize::try_from(length.value()).map_err(|_| {
            CrafterError::invalid_field_value("quic.frame.stream.length", "length exceeds usize")
        })?;
        (Some(length), data_len)
    } else {
        (None, bytes.len().saturating_sub(offset))
    };

    let available = bytes.len().saturating_sub(offset);
    if available < data_len {
        return Err(CrafterError::buffer_too_short(
            "quic.frame.stream.data",
            data_len,
            available,
        ));
    }
    let end = offset + data_len;
    let mut stream = QuicStreamFrame::new(stream_id, &bytes[offset..end]).with_fin(fin);
    if let Some(stream_offset) = stream_offset {
        stream = stream.with_offset(stream_offset);
    }
    stream = match length {
        Some(length) => stream.with_length(length),
        None => stream.without_length(),
    };

    Ok((stream, end))
}

fn decode_frame_varint(
    bytes: &[u8],
    offset: usize,
    context: &'static str,
) -> Result<(QuicVarInt, usize)> {
    match QuicVarInt::decode(&bytes[offset..]) {
        Ok((value, consumed)) => Ok((value, offset + consumed)),
        Err(CrafterError::BufferTooShort {
            required,
            available,
            ..
        }) => Err(CrafterError::buffer_too_short(context, required, available)),
        Err(error) => Err(error),
    }
}

fn classify_frame_kind(bytes: &[u8]) -> QuicFrameKind {
    if bytes.is_empty() {
        return QuicFrameKind::Empty;
    }
    let Ok((frame_type, consumed)) = QuicVarInt::decode(bytes) else {
        return QuicFrameKind::Truncated;
    };
    if frame_type.value() == 0x00 {
        return if bytes.iter().all(|byte| *byte == 0x00) {
            QuicFrameKind::Known(QuicKnownFrameType::Padding)
        } else {
            QuicFrameKind::Unknown
        };
    }
    if frame_type.value() == 0x01 && consumed != bytes.len() {
        return QuicFrameKind::Unknown;
    }
    match known_frame_type(frame_type.value()) {
        Some(kind) => QuicFrameKind::Known(kind),
        None => QuicFrameKind::Unknown,
    }
}

fn known_frame_type(frame_type: u64) -> Option<QuicKnownFrameType> {
    match frame_type {
        0x00 => Some(QuicKnownFrameType::Padding),
        0x01 => Some(QuicKnownFrameType::Ping),
        0x02 => Some(QuicKnownFrameType::Ack),
        0x03 => Some(QuicKnownFrameType::AckEcn),
        0x04 => Some(QuicKnownFrameType::ResetStream),
        0x05 => Some(QuicKnownFrameType::StopSending),
        0x06 => Some(QuicKnownFrameType::Crypto),
        0x07 => Some(QuicKnownFrameType::NewToken),
        0x08..=0x0f => Some(QuicKnownFrameType::Stream),
        0x10 => Some(QuicKnownFrameType::MaxData),
        0x11 => Some(QuicKnownFrameType::MaxStreamData),
        0x12 | 0x13 => Some(QuicKnownFrameType::MaxStreams),
        0x14 => Some(QuicKnownFrameType::DataBlocked),
        0x15 => Some(QuicKnownFrameType::StreamDataBlocked),
        0x16 | 0x17 => Some(QuicKnownFrameType::StreamsBlocked),
        0x18 => Some(QuicKnownFrameType::NewConnectionId),
        0x19 => Some(QuicKnownFrameType::RetireConnectionId),
        0x1a => Some(QuicKnownFrameType::PathChallenge),
        0x1b => Some(QuicKnownFrameType::PathResponse),
        0x1c => Some(QuicKnownFrameType::ConnectionCloseTransport),
        0x1d => Some(QuicKnownFrameType::ConnectionCloseApplication),
        0x1e => Some(QuicKnownFrameType::HandshakeDone),
        0x30 => Some(QuicKnownFrameType::Datagram),
        0x31 => Some(QuicKnownFrameType::DatagramLen),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::CrafterError;

    use super::*;

    fn v(value: u64) -> QuicVarInt {
        QuicVarInt::new(value).unwrap()
    }

    #[test]
    fn quic_summary_inspection_frame_summary_preserves_unknown_codepoint() {
        let frame = QuicFrame::from_bytes([0x40, 0xaf, 0xaa]);

        assert_eq!(frame.summary(), "kind=UNKNOWN type=0xaf raw_len=3");
        let fields = frame.inspection_fields();
        assert!(fields.contains(&("frame_kind", "UNKNOWN".to_string())));
        assert!(fields.contains(&("frame_type", "0xaf".to_string())));
        assert!(fields.contains(&("frame_type_encoded_len", "2".to_string())));
        assert!(fields.contains(&("raw_bytes", "40 af aa".to_string())));
    }

    #[test]
    fn quic_frame_skeleton_empty_sequence_roundtrips() -> crate::Result<()> {
        let frames = QuicFrame::decode_sequence([])?;

        assert!(frames.is_empty());
        assert_eq!(QuicFrame::encode_sequence(frames), Vec::<u8>::new());
        Ok(())
    }

    #[test]
    fn quic_frame_skeleton_unknown_frame_roundtrips() -> crate::Result<()> {
        let bytes = [0x40, 0xaf, 0xaa];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 1);
        let frame = &frames[0];
        assert_eq!(frame.kind(), QuicFrameKind::Unknown);
        assert_eq!(frame.frame_type_value(), Some(0xaf));
        assert_eq!(frame.frame_type_encoded_len(), Some(2));
        assert_eq!(frame.encoded_len(), bytes.len());
        assert_eq!(frame.encode_to_vec(), bytes);
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_skeleton_truncated_type_reports_structured_error() {
        assert_eq!(
            QuicFrame::decode_sequence([0x40]).unwrap_err(),
            CrafterError::buffer_too_short("quic.varint", 2, 1)
        );

        let frame = QuicFrame::from_bytes([0x40]);
        assert_eq!(frame.kind(), QuicFrameKind::Truncated);
        assert_eq!(frame.summary(), "kind=TRUNCATED type=<truncated> raw_len=1");
    }

    #[test]
    fn quic_frame_padding_ping_sequence_roundtrips() -> crate::Result<()> {
        let bytes = [0x00, 0x00, 0x00, 0x01, 0x00];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 3);
        assert_eq!(
            frames[0].kind(),
            QuicFrameKind::Known(QuicKnownFrameType::Padding)
        );
        assert_eq!(frames[0].padding_len(), Some(3));
        assert!(frames[1].is_ping());
        assert_eq!(frames[2].padding_len(), Some(1));
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_padding_ping_builders_emit_selected_bytes() {
        let frames = [QuicFrame::padding(4), QuicFrame::ping()];

        assert_eq!(
            QuicFrame::encode_sequence(frames),
            [0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn quic_frame_padding_ping_summary_reports_names() {
        let padding = QuicFrame::padding(2);
        let ping = QuicFrame::ping();

        assert_eq!(padding.summary(), "kind=PADDING padding_len=2");
        assert_eq!(ping.summary(), "kind=PING type=0x1 raw_len=1");
        assert!(padding
            .inspection_fields()
            .contains(&("padding_len", "2".to_string())));
    }

    #[test]
    fn quic_frame_ack_decodes_ranges_and_continues_sequence() -> crate::Result<()> {
        let bytes = [0x02, 10, 1, 1, 2, 0, 3, 0x01];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].kind(),
            QuicFrameKind::Known(QuicKnownFrameType::Ack)
        );
        let ack = frames[0].ack_frame()?.unwrap();
        assert!(!ack.is_ecn());
        assert_eq!(ack.largest_acknowledged().value(), 10);
        assert_eq!(ack.ack_delay().value(), 1);
        assert_eq!(ack.ack_range_count()?.value(), 1);
        assert_eq!(ack.first_ack_range().value(), 2);
        assert_eq!(ack.ack_ranges(), &[QuicAckRange::from_values(0, 3)?]);
        assert!(frames[1].is_ping());
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_ack_ecn_serializes_counts() -> crate::Result<()> {
        let frame = QuicFrame::ack_ecn(
            v(10),
            v(0),
            v(2),
            [QuicAckRange::from_values(1, 4)?],
            QuicAckEcnCounts::from_values(5, 6, 7)?,
        )?;

        assert_eq!(frame.as_bytes(), &[0x03, 10, 0, 1, 2, 1, 4, 5, 6, 7]);
        let ack = frame.ack_frame()?.unwrap();
        assert!(ack.is_ecn());
        assert_eq!(ack.ecn_counts().unwrap().ect0_count().value(), 5);
        assert_eq!(ack.ecn_counts().unwrap().ect1_count().value(), 6);
        assert_eq!(ack.ecn_counts().unwrap().ce_count().value(), 7);
        Ok(())
    }

    #[test]
    fn quic_frame_ack_malformed_range_varint_reports_structured_error() {
        assert_eq!(
            QuicFrame::decode_sequence([0x02, 10, 1, 1, 2, 0]).unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.ack.range.length", 1, 0)
        );
    }

    #[test]
    fn quic_frame_ack_summary_reports_ack_fields() -> crate::Result<()> {
        let frame = QuicFrame::ack(v(9), v(3), v(2), [QuicAckRange::from_values(0, 1)?])?;

        assert_eq!(
            frame.summary(),
            "kind=ACK largest_acknowledged=9 ack_delay=3 first_ack_range=2 ranges=1"
        );
        let fields = frame.inspection_fields();
        assert!(fields.contains(&("ack_largest_acknowledged", "9".to_string())));
        assert!(fields.contains(&("ack_range", "gap=0 length=1".to_string())));
        Ok(())
    }

    #[test]
    fn quic_frame_reset_stream_decodes_and_continues_sequence() -> crate::Result<()> {
        let bytes = [0x04, 4, 0x12, 9, 0x01];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].kind(),
            QuicFrameKind::Known(QuicKnownFrameType::ResetStream)
        );
        let reset_stream = frames[0].reset_stream_frame()?.unwrap();
        assert_eq!(reset_stream.stream_id().value(), 4);
        assert_eq!(reset_stream.application_error_code().value(), 0x12);
        assert_eq!(reset_stream.final_size().value(), 9);
        assert!(frames[1].is_ping());
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_reset_stream_serializes_unknown_error_codes() -> crate::Result<()> {
        let reset_stream = QuicResetStreamFrame::from_values(1, 0x1234, 63)?;
        let frame = QuicFrame::from_reset_stream_frame(reset_stream)?;

        assert_eq!(frame.as_bytes(), &[0x04, 0x01, 0x52, 0x34, 0x3f]);
        assert_eq!(
            frame.summary(),
            "kind=RESET_STREAM stream_id=1 application_error_code=4660 final_size=63"
        );
        Ok(())
    }

    #[test]
    fn quic_frame_reset_stream_malformed_varint_reports_structured_error() {
        assert_eq!(
            QuicFrame::decode_sequence([0x04, 1, 2, 0x40]).unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.reset_stream.final_size", 2, 1)
        );
    }

    #[test]
    fn quic_frame_stop_sending_decodes_and_continues_sequence() -> crate::Result<()> {
        let bytes = [0x05, 4, 0x12, 0x01];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].kind(),
            QuicFrameKind::Known(QuicKnownFrameType::StopSending)
        );
        let stop_sending = frames[0].stop_sending_frame()?.unwrap();
        assert_eq!(stop_sending.stream_id().value(), 4);
        assert_eq!(stop_sending.application_error_code().value(), 0x12);
        assert!(frames[1].is_ping());
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_stop_sending_serializes_unknown_error_codes() -> crate::Result<()> {
        let stop_sending = QuicStopSendingFrame::from_values(1, 0x1234)?;
        let frame = QuicFrame::from_stop_sending_frame(stop_sending)?;

        assert_eq!(frame.as_bytes(), &[0x05, 0x01, 0x52, 0x34]);
        assert_eq!(
            frame.summary(),
            "kind=STOP_SENDING stream_id=1 application_error_code=4660"
        );
        Ok(())
    }

    #[test]
    fn quic_frame_stop_sending_malformed_varint_reports_structured_error() {
        assert_eq!(
            QuicFrame::decode_sequence([0x05, 1, 0x40]).unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.stop_sending.application_error_code", 2, 1)
        );
    }

    #[test]
    fn quic_frame_crypto_decodes_data_and_continues_sequence() -> crate::Result<()> {
        let bytes = [0x06, 2, 3, 0xaa, 0xbb, 0xcc, 0x01];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].kind(),
            QuicFrameKind::Known(QuicKnownFrameType::Crypto)
        );
        let crypto = frames[0].crypto_frame()?.unwrap();
        assert_eq!(crypto.offset().value(), 2);
        assert_eq!(crypto.length()?.value(), 3);
        assert_eq!(crypto.data(), &[0xaa, 0xbb, 0xcc]);
        assert!(frames[1].is_ping());
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_crypto_auto_fills_length() -> crate::Result<()> {
        let frame = QuicFrame::crypto(v(0), [0x16, 0x03, 0x03])?;

        assert_eq!(frame.as_bytes(), &[0x06, 0x00, 0x03, 0x16, 0x03, 0x03]);
        assert_eq!(frame.summary(), "kind=CRYPTO offset=0 length=3 data_len=3");
        Ok(())
    }

    #[test]
    fn quic_frame_crypto_preserves_explicit_malformed_length() -> crate::Result<()> {
        let crypto = QuicCryptoFrame::new(v(0), [0xaa]).with_length(v(3));
        let frame = QuicFrame::from_crypto_frame(crypto)?;

        assert_eq!(frame.as_bytes(), &[0x06, 0x00, 0x03, 0xaa]);
        assert_eq!(
            frame.crypto_frame().unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.crypto.data", 3, 1)
        );
        Ok(())
    }

    #[test]
    fn quic_frame_crypto_truncated_data_reports_structured_error() {
        assert_eq!(
            QuicFrame::decode_sequence([0x06, 0, 3, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.crypto.data", 3, 1)
        );
    }

    #[test]
    fn quic_frame_new_token_decodes_token_and_continues_sequence() -> crate::Result<()> {
        let bytes = [0x07, 3, 0xde, 0xad, 0xbe, 0x01];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].kind(),
            QuicFrameKind::Known(QuicKnownFrameType::NewToken)
        );
        let new_token = frames[0].new_token_frame()?.unwrap();
        assert_eq!(new_token.token_length()?.value(), 3);
        assert_eq!(new_token.token(), &[0xde, 0xad, 0xbe]);
        assert!(frames[1].is_ping());
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_new_token_builder_auto_fills_length() -> crate::Result<()> {
        let frame = QuicFrame::new_token([0xde, 0xad])?;

        assert_eq!(frame.as_bytes(), &[0x07, 0x02, 0xde, 0xad]);
        assert_eq!(frame.summary(), "kind=NEW_TOKEN token_length=2 token_len=2");
        Ok(())
    }

    #[test]
    fn quic_frame_new_token_empty_token_is_byte_complete() -> crate::Result<()> {
        let frame = QuicFrame::new_token([])?;
        let decoded = frame.new_token_frame()?.unwrap();

        assert_eq!(frame.as_bytes(), &[0x07, 0x00]);
        assert_eq!(decoded.token(), &[]);
        assert_eq!(decoded.token_length()?.value(), 0);
        Ok(())
    }

    #[test]
    fn quic_frame_new_token_preserves_explicit_malformed_length() -> crate::Result<()> {
        let new_token = QuicNewTokenFrame::new([0xaa]).with_token_length(v(3));
        let frame = QuicFrame::from_new_token_frame(new_token)?;

        assert_eq!(frame.as_bytes(), &[0x07, 0x03, 0xaa]);
        assert_eq!(
            frame.new_token_frame().unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.new_token.token", 3, 1)
        );
        Ok(())
    }

    #[test]
    fn quic_frame_new_token_truncated_token_reports_structured_error() {
        assert_eq!(
            QuicFrame::decode_sequence([0x07, 3, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.new_token.token", 3, 1)
        );
    }

    #[test]
    fn quic_frame_stream_decodes_offset_length_fin_and_continues_sequence() -> crate::Result<()> {
        let bytes = [0x0f, 4, 2, 3, 0xaa, 0xbb, 0xcc, 0x01];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].kind(),
            QuicFrameKind::Known(QuicKnownFrameType::Stream)
        );
        let stream = frames[0].stream_frame()?.unwrap();
        assert_eq!(stream.stream_id().value(), 4);
        assert_eq!(stream.offset().unwrap().value(), 2);
        assert_eq!(stream.length()?.unwrap().value(), 3);
        assert!(stream.fin());
        assert_eq!(stream.data(), &[0xaa, 0xbb, 0xcc]);
        assert!(frames[1].is_ping());
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_stream_builder_auto_fills_length() -> crate::Result<()> {
        let stream = QuicStreamFrame::new(v(1), [0xaa, 0xbb])
            .with_offset(v(10))
            .with_fin(true);
        let frame = QuicFrame::from_stream_frame(stream)?;

        assert_eq!(frame.as_bytes(), &[0x0f, 0x01, 0x0a, 0x02, 0xaa, 0xbb]);
        assert_eq!(
            frame.summary(),
            "kind=STREAM stream_id=1 offset=10 length=2 fin=true data_len=2"
        );
        Ok(())
    }

    #[test]
    fn quic_frame_stream_without_length_consumes_packet_remainder() -> crate::Result<()> {
        let bytes = [0x08, 1, 0xaa, 0x01];

        let frames = QuicFrame::decode_sequence(bytes)?;

        assert_eq!(frames.len(), 1);
        let stream = frames[0].stream_frame()?.unwrap();
        assert!(!stream.has_length());
        assert_eq!(stream.length()?, None);
        assert_eq!(stream.data(), &[0xaa, 0x01]);
        assert_eq!(QuicFrame::encode_sequence(frames), bytes);
        Ok(())
    }

    #[test]
    fn quic_frame_stream_preserves_explicit_malformed_length() -> crate::Result<()> {
        let stream = QuicStreamFrame::new(v(1), [0xaa]).with_length(v(3));
        let frame = QuicFrame::from_stream_frame(stream)?;

        assert_eq!(frame.as_bytes(), &[0x0a, 0x01, 0x03, 0xaa]);
        assert_eq!(
            frame.stream_frame().unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.stream.data", 3, 1)
        );
        Ok(())
    }

    #[test]
    fn quic_frame_stream_truncated_data_reports_structured_error() {
        assert_eq!(
            QuicFrame::decode_sequence([0x0a, 1, 3, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("quic.frame.stream.data", 3, 1)
        );
    }
}
