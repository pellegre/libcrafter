//! QUIC frame helpers.
//!
//! This module starts with a raw-preserving frame scaffold. Later steps add
//! source-backed typed bodies for individual frame grammars.

use crate::protocols::transport::common::hex_bytes;
use crate::Result;

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
        fields
    }
}

impl Default for QuicFrameKind {
    fn default() -> Self {
        Self::Empty
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
}
