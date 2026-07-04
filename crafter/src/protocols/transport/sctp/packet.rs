//! SCTP common-header layer model.
//!
//! RFC 9260 section 3.1 defines the fixed 12-octet common header: source port,
//! destination port, verification tag, and CRC32c checksum. This module only
//! models those fields; decode loops, chunks, checksum status, and packet
//! storage integration are introduced by later SCTP steps.

#![allow(dead_code)]

use crate::error::Result;
use crate::field::Field;
use crate::packet::{Layer, LayerContext};

use super::super::common::{impl_layer_div, impl_layer_object, value_or_copy};
use super::checksum::{sctp_packet_crc32c, SctpChecksumStatus};
use super::chunk::{
    encode_chunks, SctpChunk, SctpDataChunk, SctpHeartbeatChunk, SctpInitChunk, SctpSackChunk,
    SctpSackGapAckBlock, SctpShutdownChunk,
};
use super::constants::{SCTP_CHECKSUM_LEN, SCTP_CHECKSUM_OFFSET, SCTP_COMMON_HEADER_LEN};

const SCTP_DEFAULT_SOURCE_PORT: u16 = 5_000;
const SCTP_DEFAULT_DESTINATION_PORT: u16 = 5_001;
const SCTP_SUMMARY_CHUNK_LIMIT: usize = 4;

/// Stream Control Transmission Protocol common-header layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sctp {
    source_port: Field<u16>,
    destination_port: Field<u16>,
    verification_tag: Field<u32>,
    checksum: Field<u32>,
    checksum_status: SctpChecksumStatus,
    chunks: Vec<SctpChunk>,
}

impl Sctp {
    /// Create an SCTP common header with deterministic packet-builder defaults.
    pub fn new() -> Self {
        Self {
            source_port: Field::defaulted(SCTP_DEFAULT_SOURCE_PORT),
            destination_port: Field::defaulted(SCTP_DEFAULT_DESTINATION_PORT),
            verification_tag: Field::defaulted(0),
            checksum: Field::unset(),
            checksum_status: SctpChecksumStatus::NotChecked,
            chunks: Vec::new(),
        }
    }

    /// Build an SCTP packet containing one INIT chunk.
    pub fn init(
        initiate_tag: u32,
        advertised_receiver_window_credit: u32,
        outbound_streams: u16,
        inbound_streams: u16,
        initial_tsn: u32,
    ) -> Self {
        Self::new().chunk(SctpInitChunk::from_init(
            initiate_tag,
            advertised_receiver_window_credit,
            outbound_streams,
            inbound_streams,
            initial_tsn,
        ))
    }

    /// Build an SCTP packet containing one DATA chunk.
    pub fn data(
        tsn: u32,
        stream_id: u16,
        stream_sequence_number: u16,
        payload_protocol_identifier: u32,
        user_data: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new().chunk(SctpDataChunk::from_data(
            tsn,
            stream_id,
            stream_sequence_number,
            payload_protocol_identifier,
            user_data,
        ))
    }

    /// Build an SCTP packet containing one HEARTBEAT chunk.
    pub fn heartbeat(heartbeat_info: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self::new().chunk(SctpHeartbeatChunk::try_from_heartbeat_info(heartbeat_info)?))
    }

    /// Build an SCTP packet containing one SACK chunk.
    pub fn sack(
        cumulative_tsn_ack: u32,
        advertised_receiver_window_credit: u32,
        gap_ack_blocks: impl IntoIterator<Item = SctpSackGapAckBlock>,
        duplicate_tsns: impl IntoIterator<Item = u32>,
    ) -> Result<Self> {
        Ok(Self::new().chunk(SctpSackChunk::try_from_sack(
            cumulative_tsn_ack,
            advertised_receiver_window_credit,
            gap_ack_blocks,
            duplicate_tsns,
        )?))
    }

    /// Build an SCTP packet containing one SHUTDOWN chunk.
    pub fn shutdown(cumulative_tsn_ack: u32) -> Self {
        Self::new().chunk(SctpShutdownChunk::from_shutdown(cumulative_tsn_ack))
    }

    /// Construct an SCTP common header from decoded wire fields.
    pub(super) fn from_decoded_parts(
        source_port: u16,
        destination_port: u16,
        verification_tag: u32,
        checksum: u32,
    ) -> Self {
        Self::from_decoded_parts_with_chunks(
            source_port,
            destination_port,
            verification_tag,
            checksum,
            Vec::new(),
        )
    }

    /// Construct an SCTP common header from decoded wire fields and checksum status.
    pub(super) fn from_decoded_parts_with_checksum_status(
        source_port: u16,
        destination_port: u16,
        verification_tag: u32,
        checksum: u32,
        checksum_status: SctpChecksumStatus,
    ) -> Self {
        Self::from_decoded_parts_with_chunks_and_checksum_status(
            source_port,
            destination_port,
            verification_tag,
            checksum,
            Vec::new(),
            checksum_status,
        )
    }

    /// Construct an SCTP packet from decoded wire fields and preserved chunks.
    pub(super) fn from_decoded_parts_with_chunks(
        source_port: u16,
        destination_port: u16,
        verification_tag: u32,
        checksum: u32,
        chunks: Vec<SctpChunk>,
    ) -> Self {
        Self::from_decoded_parts_with_chunks_and_checksum_status(
            source_port,
            destination_port,
            verification_tag,
            checksum,
            chunks,
            SctpChecksumStatus::NotChecked,
        )
    }

    /// Construct an SCTP packet from decoded wire fields, preserved chunks, and checksum status.
    pub(super) fn from_decoded_parts_with_chunks_and_checksum_status(
        source_port: u16,
        destination_port: u16,
        verification_tag: u32,
        checksum: u32,
        chunks: Vec<SctpChunk>,
        checksum_status: SctpChecksumStatus,
    ) -> Self {
        Self {
            source_port: Field::user(source_port),
            destination_port: Field::user(destination_port),
            verification_tag: Field::user(verification_tag),
            checksum: Field::user(checksum),
            checksum_status,
            chunks,
        }
    }

    /// Fixed SCTP common-header length in octets.
    pub const fn header_len(&self) -> usize {
        SCTP_COMMON_HEADER_LEN
    }

    /// Set the source port.
    pub fn source_port(mut self, source_port: u16) -> Self {
        self.source_port.set_user(source_port);
        self
    }

    /// Compatibility alias for source port.
    pub fn sport(self, source_port: u16) -> Self {
        self.source_port(source_port)
    }

    /// Set the destination port.
    pub fn destination_port(mut self, destination_port: u16) -> Self {
        self.destination_port.set_user(destination_port);
        self
    }

    /// Compatibility alias for destination port.
    pub fn dport(self, destination_port: u16) -> Self {
        self.destination_port(destination_port)
    }

    /// Set the SCTP verification tag.
    pub fn verification_tag(mut self, verification_tag: u32) -> Self {
        self.verification_tag.set_user(verification_tag);
        self
    }

    /// Compatibility alias for verification tag.
    pub fn tag(self, verification_tag: u32) -> Self {
        self.verification_tag(verification_tag)
    }

    /// Compatibility alias for verification tag.
    pub fn vtag(self, verification_tag: u32) -> Self {
        self.verification_tag(verification_tag)
    }

    /// Set the SCTP CRC32c checksum field explicitly.
    pub fn checksum(mut self, checksum: u32) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Compatibility alias for checksum.
    pub fn chksum(self, checksum: u32) -> Self {
        self.checksum(checksum)
    }

    /// Append one SCTP chunk to this packet builder.
    pub fn chunk(mut self, chunk: impl Into<SctpChunk>) -> Self {
        self.chunks.push(chunk.into());
        self
    }

    /// Compatibility alias for appending one SCTP chunk.
    pub fn with_chunk(self, chunk: impl Into<SctpChunk>) -> Self {
        self.chunk(chunk)
    }

    /// Append many SCTP chunks to this packet builder.
    pub fn with_chunks<I, C>(mut self, chunks: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: Into<SctpChunk>,
    {
        self.chunks.extend(chunks.into_iter().map(Into::into));
        self
    }

    /// Mutably append one SCTP chunk.
    pub fn push_chunk(&mut self, chunk: impl Into<SctpChunk>) -> &mut Self {
        self.chunks.push(chunk.into());
        self
    }

    /// Mutably append many SCTP chunks.
    pub fn extend_chunks<I, C>(&mut self, chunks: I) -> &mut Self
    where
        I: IntoIterator<Item = C>,
        C: Into<SctpChunk>,
    {
        self.chunks.extend(chunks.into_iter().map(Into::into));
        self
    }

    /// Source port value.
    pub fn source_port_value(&self) -> u16 {
        value_or_copy(&self.source_port, SCTP_DEFAULT_SOURCE_PORT)
    }

    /// Destination port value.
    pub fn destination_port_value(&self) -> u16 {
        value_or_copy(&self.destination_port, SCTP_DEFAULT_DESTINATION_PORT)
    }

    /// SCTP verification tag value.
    pub fn verification_tag_value(&self) -> u32 {
        value_or_copy(&self.verification_tag, 0)
    }

    /// Stored SCTP checksum value, when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u32> {
        self.checksum.value().copied()
    }

    /// Decode-time SCTP checksum inspection status.
    pub const fn checksum_status(&self) -> SctpChecksumStatus {
        self.checksum_status
    }

    /// Borrow stored SCTP chunks.
    pub fn chunks(&self) -> &[SctpChunk] {
        &self.chunks
    }

    /// Mutably borrow stored SCTP chunks.
    pub fn chunks_mut(&mut self) -> &mut Vec<SctpChunk> {
        &mut self.chunks
    }

    /// Consume the layer and return its stored SCTP chunks.
    pub fn into_chunks(self) -> Vec<SctpChunk> {
        self.chunks
    }

    /// Number of stored SCTP chunks.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Return true when no SCTP chunks are stored on this layer.
    pub fn is_chunks_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    fn chunks_encoded_len(&self) -> usize {
        self.chunks.iter().map(SctpChunk::encoded_len).sum()
    }

    fn chunk_presence_summary(&self) -> String {
        match self.chunks.as_slice() {
            [] => "0".to_string(),
            chunks => {
                let mut summary = chunks
                    .iter()
                    .take(SCTP_SUMMARY_CHUNK_LIMIT)
                    .map(sctp_chunk_presence_label)
                    .collect::<Vec<_>>()
                    .join(",");
                if chunks.len() > SCTP_SUMMARY_CHUNK_LIMIT {
                    summary.push_str(&format!(",+{}", chunks.len() - SCTP_SUMMARY_CHUNK_LIMIT));
                }
                format!("{}[{summary}]", chunks.len())
            }
        }
    }

    fn chunk_inspection_summary(&self) -> String {
        if self.chunks.is_empty() {
            return "none".to_string();
        }

        self.chunks
            .iter()
            .map(sctp_chunk_inspection_summary)
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn checksum_status_summary(&self) -> String {
        match self.checksum_status {
            SctpChecksumStatus::NotChecked => String::new(),
            status => format!(", checksum_status={}", status.label()),
        }
    }
}

/// Build an SCTP packet containing one INIT chunk.
pub fn sctp_init(
    initiate_tag: u32,
    advertised_receiver_window_credit: u32,
    outbound_streams: u16,
    inbound_streams: u16,
    initial_tsn: u32,
) -> Sctp {
    Sctp::init(
        initiate_tag,
        advertised_receiver_window_credit,
        outbound_streams,
        inbound_streams,
        initial_tsn,
    )
}

/// Build an SCTP packet containing one DATA chunk.
pub fn sctp_data(
    tsn: u32,
    stream_id: u16,
    stream_sequence_number: u16,
    payload_protocol_identifier: u32,
    user_data: impl Into<Vec<u8>>,
) -> Sctp {
    Sctp::data(
        tsn,
        stream_id,
        stream_sequence_number,
        payload_protocol_identifier,
        user_data,
    )
}

/// Build an SCTP packet containing one HEARTBEAT chunk.
pub fn sctp_heartbeat(heartbeat_info: impl Into<Vec<u8>>) -> Result<Sctp> {
    Sctp::heartbeat(heartbeat_info)
}

/// Build an SCTP packet containing one SACK chunk.
pub fn sctp_sack(
    cumulative_tsn_ack: u32,
    advertised_receiver_window_credit: u32,
    gap_ack_blocks: impl IntoIterator<Item = SctpSackGapAckBlock>,
    duplicate_tsns: impl IntoIterator<Item = u32>,
) -> Result<Sctp> {
    Sctp::sack(
        cumulative_tsn_ack,
        advertised_receiver_window_credit,
        gap_ack_blocks,
        duplicate_tsns,
    )
}

/// Build an SCTP packet containing one SHUTDOWN chunk.
pub fn sctp_shutdown(cumulative_tsn_ack: u32) -> Sctp {
    Sctp::shutdown(cumulative_tsn_ack)
}

impl Default for Sctp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Sctp {
    fn name(&self) -> &'static str {
        "Sctp"
    }

    fn summary(&self) -> String {
        format!(
            "Sctp(sport={}, dport={}, vtag=0x{:08x}, chunks={}, checksum={}{})",
            self.source_port_value(),
            self.destination_port_value(),
            self.verification_tag_value(),
            self.chunk_presence_summary(),
            self.checksum_value()
                .map(|value| format!("0x{value:08x}"))
                .unwrap_or_else(|| "auto".to_string()),
            self.checksum_status_summary()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("sport", self.source_port_value().to_string()),
            ("dport", self.destination_port_value().to_string()),
            (
                "verification_tag",
                format!("0x{:08x}", self.verification_tag_value()),
            ),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:08x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("checksum_status", self.checksum_status.label().to_string()),
            ("header_len", self.header_len().to_string()),
            ("chunk_count", self.chunk_count().to_string()),
            ("chunk_bytes", self.chunks_encoded_len().to_string()),
            ("chunk_summary", self.chunk_inspection_summary()),
        ]
    }

    fn encoded_len(&self) -> usize {
        SCTP_COMMON_HEADER_LEN + self.chunks_encoded_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let mut sctp_packet = Vec::with_capacity(self.encoded_len());
        sctp_packet.extend_from_slice(&self.source_port_value().to_be_bytes());
        sctp_packet.extend_from_slice(&self.destination_port_value().to_be_bytes());
        sctp_packet.extend_from_slice(&self.verification_tag_value().to_be_bytes());
        sctp_packet.extend_from_slice(&self.checksum_value().unwrap_or(0).to_be_bytes());
        encode_chunks(&self.chunks, &mut sctp_packet)?;

        if self.checksum_value().is_none() {
            let mut checksum_packet =
                Vec::with_capacity(sctp_packet.len() + ctx.packet().encoded_len_after(ctx.index()));
            checksum_packet.extend_from_slice(&sctp_packet);
            ctx.packet()
                .compile_layers_after_into(ctx.index(), &mut checksum_packet)?;
            let checksum = sctp_packet_crc32c(&checksum_packet)?;
            let checksum_end = SCTP_CHECKSUM_OFFSET + SCTP_CHECKSUM_LEN;
            sctp_packet[SCTP_CHECKSUM_OFFSET..checksum_end]
                .copy_from_slice(&checksum.to_be_bytes());
        }

        out.extend_from_slice(&sctp_packet);
        Ok(())
    }

    impl_layer_object!(Sctp);
}

impl_layer_div!(Sctp);

fn sctp_chunk_name(chunk: &SctpChunk) -> &'static str {
    match chunk {
        SctpChunk::Data(_) => "DATA",
        SctpChunk::Init(_) => "INIT",
        SctpChunk::InitAck(_) => "INIT ACK",
        SctpChunk::Sack(_) => "SACK",
        SctpChunk::Heartbeat(_) => "HEARTBEAT",
        SctpChunk::HeartbeatAck(_) => "HEARTBEAT ACK",
        SctpChunk::Abort(_) => "ABORT",
        SctpChunk::Shutdown(_) => "SHUTDOWN",
        SctpChunk::ShutdownAck(_) => "SHUTDOWN ACK",
        SctpChunk::Error(_) => "ERROR",
        SctpChunk::CookieEcho(_) => "COOKIE ECHO",
        SctpChunk::CookieAck(_) => "COOKIE ACK",
        SctpChunk::Ecne(_) => "ECNE",
        SctpChunk::Cwr(_) => "CWR",
        SctpChunk::ShutdownComplete(_) => "SHUTDOWN COMPLETE",
        SctpChunk::Auth(_) => "AUTH",
        SctpChunk::IData(_) => "I-DATA",
        SctpChunk::AsconfAck(_) => "ASCONF-ACK",
        SctpChunk::ReConfig(_) => "RE-CONFIG",
        SctpChunk::Pad(_) => "PAD",
        SctpChunk::ForwardTsn(_) => "FORWARD TSN",
        SctpChunk::Asconf(_) => "ASCONF",
        SctpChunk::IForwardTsn(_) => "I-FORWARD-TSN",
        SctpChunk::Unknown(_) => "UNKNOWN",
    }
}

fn sctp_chunk_presence_label(chunk: &SctpChunk) -> String {
    match chunk {
        SctpChunk::Unknown(_) => format!("UNKNOWN({})", chunk.chunk_type_value()),
        _ => sctp_chunk_name(chunk).to_string(),
    }
}

fn sctp_chunk_inspection_summary(chunk: &SctpChunk) -> String {
    format!(
        "{}(type={}, flags=0x{:02x}, len={}, value_bytes={}, padding_bytes={})",
        sctp_chunk_name(chunk),
        chunk.chunk_type_value(),
        chunk.flags(),
        chunk.declared_length(),
        chunk.value_len(),
        chunk.encoded_padding_len()
    )
}

#[cfg(test)]
mod tests {
    use crate::field::FieldState;
    use crate::packet::{Packet, Raw};

    use super::super::checksum::decoded_sctp_checksum_status;
    use super::super::chunk::{
        SctpAsconfAckChunk, SctpAsconfChunk, SctpAuthChunk, SctpChunk, SctpCookieAckChunk,
        SctpCookieEchoChunk, SctpCwrChunk, SctpDataChunk, SctpEcneChunk, SctpErrorChunk,
        SctpForwardTsnChunk, SctpForwardTsnSkippedStreamSequence, SctpHeartbeatAckChunk,
        SctpIForwardTsnChunk, SctpIForwardTsnSkippedStream, SctpPadChunk, SctpReConfigChunk,
        SctpSackGapAckBlock, SctpShutdownAckChunk, SctpShutdownChunk, SctpShutdownCompleteChunk,
    };
    use super::super::constants::{
        SCTP_CHUNK_TYPE_DATA, SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
        SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE,
    };
    use super::*;

    fn read_checksum(bytes: &[u8]) -> u32 {
        u32::from_be_bytes([
            bytes[SCTP_CHECKSUM_OFFSET],
            bytes[SCTP_CHECKSUM_OFFSET + 1],
            bytes[SCTP_CHECKSUM_OFFSET + 2],
            bytes[SCTP_CHECKSUM_OFFSET + 3],
        ])
    }

    fn field<'a>(fields: &'a [(&'static str, String)], name: &str) -> &'a str {
        fields
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("SCTP inspection field {name:?} missing from {fields:?}"))
    }

    #[test]
    fn sctp_common_header_builder_defaults_are_deterministic() {
        let sctp = Sctp::new();

        assert_eq!(sctp.header_len(), SCTP_COMMON_HEADER_LEN);
        assert_eq!(sctp.source_port.state(), FieldState::Defaulted);
        assert_eq!(sctp.destination_port.state(), FieldState::Defaulted);
        assert_eq!(sctp.verification_tag.state(), FieldState::Defaulted);
        assert_eq!(sctp.checksum.state(), FieldState::Unset);
        assert_eq!(sctp.source_port_value(), SCTP_DEFAULT_SOURCE_PORT);
        assert_eq!(sctp.destination_port_value(), SCTP_DEFAULT_DESTINATION_PORT);
        assert_eq!(sctp.verification_tag_value(), 0);
        assert_eq!(sctp.checksum_value(), None);
        assert_eq!(sctp.checksum_status(), SctpChecksumStatus::NotChecked);
    }

    #[test]
    fn sctp_common_header_setters_preserve_explicit_overrides() {
        let sctp = Sctp::new()
            .source_port(0)
            .destination_port(65_535)
            .verification_tag(0x1122_3344)
            .checksum(0);

        assert_eq!(sctp.source_port.state(), FieldState::User);
        assert_eq!(sctp.destination_port.state(), FieldState::User);
        assert_eq!(sctp.verification_tag.state(), FieldState::User);
        assert_eq!(sctp.checksum.state(), FieldState::User);
        assert_eq!(sctp.source_port_value(), 0);
        assert_eq!(sctp.destination_port_value(), 65_535);
        assert_eq!(sctp.verification_tag_value(), 0x1122_3344);
        assert_eq!(sctp.checksum_value(), Some(0));
    }

    #[test]
    fn sctp_common_header_aliases_preserve_explicit_overrides() {
        let sctp = Sctp::new()
            .sport(5_000)
            .dport(5_001)
            .tag(0xaabb_ccdd)
            .chksum(0x0102_0304);

        assert_eq!(sctp.source_port.state(), FieldState::User);
        assert_eq!(sctp.destination_port.state(), FieldState::User);
        assert_eq!(sctp.verification_tag.state(), FieldState::User);
        assert_eq!(sctp.checksum.state(), FieldState::User);
        assert_eq!(sctp.source_port_value(), 5_000);
        assert_eq!(sctp.destination_port_value(), 5_001);
        assert_eq!(sctp.verification_tag_value(), 0xaabb_ccdd);
        assert_eq!(sctp.checksum_value(), Some(0x0102_0304));
    }

    #[test]
    fn sctp_builder_aliases_preserve_explicit_overrides() {
        let sctp = Sctp::new()
            .sport(0)
            .dport(65_535)
            .vtag(0x1122_3344)
            .chksum(0);

        assert_eq!(sctp.source_port.state(), FieldState::User);
        assert_eq!(sctp.destination_port.state(), FieldState::User);
        assert_eq!(sctp.verification_tag.state(), FieldState::User);
        assert_eq!(sctp.checksum.state(), FieldState::User);
        assert_eq!(sctp.source_port_value(), 0);
        assert_eq!(sctp.destination_port_value(), 65_535);
        assert_eq!(sctp.verification_tag_value(), 0x1122_3344);
        assert_eq!(sctp.checksum_value(), Some(0));
    }

    #[test]
    fn sctp_builder_aliases_keep_tag_and_checksum_aliases() {
        let sctp = Sctp::new().tag(0xaabb_ccdd).checksum(0x0102_0304);
        let aliased = Sctp::new().vtag(0xaabb_ccdd).chksum(0x0102_0304);

        assert_eq!(sctp.verification_tag.state(), FieldState::User);
        assert_eq!(sctp.checksum.state(), FieldState::User);
        assert_eq!(
            sctp.verification_tag_value(),
            aliased.verification_tag_value()
        );
        assert_eq!(sctp.checksum_value(), aliased.checksum_value());
    }

    #[test]
    fn sctp_packet_helpers_build_common_typed_chunks() -> Result<()> {
        let init = Sctp::init(0x0102_0304, 65_535, 10, 20, 0x1122_3344);
        assert_eq!(init.chunk_count(), 1);
        let SctpChunk::Init(init_chunk) = &init.chunks()[0] else {
            panic!("expected INIT chunk");
        };
        assert_eq!(init_chunk.initiate_tag()?, 0x0102_0304);
        assert_eq!(init_chunk.a_rwnd()?, 65_535);
        assert_eq!(init_chunk.outbound_streams()?, 10);
        assert_eq!(init_chunk.inbound_streams()?, 20);
        assert_eq!(init_chunk.initial_tsn()?, 0x1122_3344);

        let data = sctp_data(0x2233_4455, 7, 9, 3, b"message".to_vec());
        let SctpChunk::Data(data_chunk) = &data.chunks()[0] else {
            panic!("expected DATA chunk");
        };
        assert_eq!(data_chunk.tsn()?, 0x2233_4455);
        assert_eq!(data_chunk.stream_id()?, 7);
        assert_eq!(data_chunk.stream_sequence_number()?, 9);
        assert_eq!(data_chunk.ppid()?, 3);
        assert_eq!(data_chunk.user_data()?, b"message");

        let heartbeat = sctp_heartbeat([0xde, 0xad, 0xbe, 0xef])?;
        let SctpChunk::Heartbeat(heartbeat_chunk) = &heartbeat.chunks()[0] else {
            panic!("expected HEARTBEAT chunk");
        };
        assert_eq!(heartbeat_chunk.heartbeat_info()?, [0xde, 0xad, 0xbe, 0xef]);

        let sack = Sctp::sack(
            0x1000_0000,
            4_096,
            [SctpSackGapAckBlock::new(1, 3)],
            [0x1000_0004],
        )?;
        let SctpChunk::Sack(sack_chunk) = &sack.chunks()[0] else {
            panic!("expected SACK chunk");
        };
        assert_eq!(sack_chunk.cumulative_tsn_ack()?, 0x1000_0000);
        assert_eq!(sack_chunk.a_rwnd()?, 4_096);
        assert_eq!(
            sack_chunk.gap_ack_blocks()?,
            [SctpSackGapAckBlock::new(1, 3)]
        );
        assert_eq!(sack_chunk.duplicate_tsns()?, [0x1000_0004]);

        let shutdown = sctp_shutdown(0x5566_7788);
        let SctpChunk::Shutdown(shutdown_chunk) = &shutdown.chunks()[0] else {
            panic!("expected SHUTDOWN chunk");
        };
        assert_eq!(shutdown_chunk.cumulative_tsn_ack()?, 0x5566_7788);

        let packet = Packet::from_layer(data);
        assert_eq!(
            packet.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[DATA], checksum=auto)"
        );
        assert!(packet.compile()?.as_bytes().len() > SCTP_COMMON_HEADER_LEN);
        Ok(())
    }

    #[test]
    fn sctp_compile_header_autofills_crc32c() -> Result<()> {
        let compiled = Packet::from_layer(Sctp::new()).compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(bytes.len(), SCTP_COMMON_HEADER_LEN);
        assert_eq!(&bytes[0..2], &SCTP_DEFAULT_SOURCE_PORT.to_be_bytes());
        assert_eq!(&bytes[2..4], &SCTP_DEFAULT_DESTINATION_PORT.to_be_bytes());
        assert_eq!(&bytes[4..8], &0u32.to_be_bytes());
        assert_eq!(read_checksum(bytes), sctp_packet_crc32c(bytes)?);
        Ok(())
    }

    #[test]
    fn sctp_compile_header_preserves_explicit_checksum_override() -> Result<()> {
        let compiled = Packet::from_layer(
            Sctp::new()
                .sport(0)
                .dport(65_535)
                .vtag(0x1122_3344)
                .checksum(0),
        )
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(bytes.len(), SCTP_COMMON_HEADER_LEN);
        assert_eq!(&bytes[0..2], &0u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &65_535u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &0x1122_3344u32.to_be_bytes());
        assert_eq!(read_checksum(bytes), 0);
        assert_ne!(sctp_packet_crc32c(bytes)?, 0);
        Ok(())
    }

    #[test]
    fn sctp_compile_header_exposes_summary_show_and_inspection() {
        let sctp = Sctp::new().sport(12_000).dport(12_001).vtag(0xaabb_ccdd);
        let packet = Packet::from_layer(sctp.clone());
        let fields = sctp.inspection_fields();

        assert_eq!(sctp.name(), "Sctp");
        assert_eq!(sctp.encoded_len(), SCTP_COMMON_HEADER_LEN);
        assert!(sctp.summary().contains("Sctp(sport=12000, dport=12001"));
        assert!(sctp.summary().contains("vtag=0xaabbccdd"));
        assert!(sctp.summary().contains("checksum=auto"));
        assert!(fields.contains(&("verification_tag", "0xaabbccdd".to_string())));
        assert!(fields.contains(&("checksum", "auto".to_string())));
        assert!(packet.show().contains("[0] Sctp"));
        assert!(packet.show().contains("verification_tag: 0xaabbccdd"));
    }

    #[test]
    fn sctp_summary_includes_common_header_and_chunk_presence() {
        let sctp = Sctp::new()
            .sport(12_000)
            .dport(12_001)
            .vtag(0xaabb_ccdd)
            .checksum(0x0102_0304)
            .chunk(SctpDataChunk::new([0xaa]).with_flags(0x03))
            .chunk(SctpChunk::unknown(
                SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
                0x80,
                [0xbb, 0xcc],
            ));

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=12000, dport=12001, vtag=0xaabbccdd, chunks=2[DATA,UNKNOWN(255)], checksum=0x01020304)"
        );
    }

    #[test]
    fn sctp_heartbeat_ack_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpHeartbeatAckChunk::from_heartbeat_info_parameter_bytes(
            [0x00, 0x01, 0x00, 0x04],
        ));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[HEARTBEAT ACK], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "HEARTBEAT ACK(type=5, flags=0x00, len=8, value_bytes=4, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_shutdown_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpShutdownChunk::from_shutdown(0x1122_3344));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[SHUTDOWN], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "SHUTDOWN(type=7, flags=0x00, len=8, value_bytes=4, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_shutdown_ack_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpShutdownAckChunk::from_shutdown_ack_parts(0xa0));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[SHUTDOWN ACK], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "SHUTDOWN ACK(type=8, flags=0xa0, len=4, value_bytes=0, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_shutdown_complete_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpShutdownCompleteChunk::from_shutdown_complete_parts(
            0x01,
        ));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[SHUTDOWN COMPLETE], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "SHUTDOWN COMPLETE(type=14, flags=0x01, len=4, value_bytes=0, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_error_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpErrorChunk::from_error_cause_bytes([
            0x00, 0x0d, 0x00, 0x04,
        ]));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[ERROR], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "ERROR(type=9, flags=0x00, len=8, value_bytes=4, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_cookie_echo_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpCookieEchoChunk::from_cookie([0xde, 0xad, 0xbe]));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[COOKIE ECHO], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "COOKIE ECHO(type=10, flags=0x00, len=7, value_bytes=3, padding_bytes=1)"
        );
    }

    #[test]
    fn sctp_cookie_ack_chunk_summary_show_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpCookieAckChunk::from_cookie_ack_parts(0xa0));
        let fields = sctp.inspection_fields();
        let packet = Packet::from_layer(sctp.clone());
        let expected_chunk_summary =
            "COOKIE ACK(type=11, flags=0xa0, len=4, value_bytes=0, padding_bytes=0)";

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[COOKIE ACK], checksum=auto)"
        );
        assert_eq!(field(&fields, "chunk_summary"), expected_chunk_summary);
        assert!(packet
            .show()
            .contains(&format!("chunk_summary: {expected_chunk_summary}")));
    }

    #[test]
    fn sctp_ecne_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpEcneChunk::from_lowest_tsn(0x1122_3344));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[ECNE], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "ECNE(type=12, flags=0x00, len=8, value_bytes=4, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_cwr_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpCwrChunk::from_lowest_tsn(0x1122_3344));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[CWR], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "CWR(type=13, flags=0x00, len=8, value_bytes=4, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_auth_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpAuthChunk::from_auth(
            0x0102u16,
            0x0003u16,
            [0xaa, 0xbb, 0xcc],
        ));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[AUTH], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "AUTH(type=15, flags=0x00, len=11, value_bytes=7, padding_bytes=1)"
        );
    }

    #[test]
    fn sctp_forward_tsn_chunk_summary_output_uses_stable_label() {
        let skipped = [SctpForwardTsnSkippedStreamSequence::new(1, 2)];
        let sctp = Sctp::new().chunk(SctpForwardTsnChunk::from_forward_tsn(0x1122_3344, &skipped));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[FORWARD TSN], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "FORWARD TSN(type=192, flags=0x00, len=12, value_bytes=8, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_iforward_tsn_chunk_summary_output_uses_stable_label() {
        let skipped = [SctpIForwardTsnSkippedStream::unordered(1, 2)];
        let sctp = Sctp::new().chunk(SctpIForwardTsnChunk::from_iforward_tsn(
            0x1122_3344,
            &skipped,
        ));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[I-FORWARD-TSN], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "I-FORWARD-TSN(type=194, flags=0x00, len=16, value_bytes=12, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_asconf_chunk_summary_output_uses_stable_label() {
        let value = [
            0x11, 0x22, 0x33, 0x44, 0x00, 0x05, 0x00, 0x08, 192, 0, 2, 1, 0xc0, 0x01, 0x00, 0x10,
            0x01, 0x02, 0x03, 0x04, 0x00, 0x05, 0x00, 0x08, 198, 51, 100, 1,
        ];
        let sctp = Sctp::new().chunk(SctpAsconfChunk::new(value));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[ASCONF], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "ASCONF(type=193, flags=0x00, len=32, value_bytes=28, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_asconf_ack_chunk_summary_output_uses_stable_label() {
        let sctp =
            Sctp::new().chunk(SctpAsconfAckChunk::try_from_asconf_ack(0x1122_3344, &[]).unwrap());
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[ASCONF-ACK], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "ASCONF-ACK(type=128, flags=0x00, len=8, value_bytes=4, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_reconfig_chunk_summary_output_uses_stable_label() {
        let value = [
            0x00, 0x10, 0x00, 0x0c, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01,
        ];
        let sctp = Sctp::new().chunk(SctpReConfigChunk::new(value));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[RE-CONFIG], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "RE-CONFIG(type=130, flags=0x00, len=16, value_bytes=12, padding_bytes=0)"
        );
    }

    #[test]
    fn sctp_pad_chunk_summary_output_uses_stable_label() {
        let sctp = Sctp::new().chunk(SctpPadChunk::from_padding_data([0xaa, 0xbb, 0xcc]));
        let fields = sctp.inspection_fields();

        assert_eq!(
            sctp.summary(),
            "Sctp(sport=5000, dport=5001, vtag=0x00000000, chunks=1[PAD], checksum=auto)"
        );
        assert_eq!(
            field(&fields, "chunk_summary"),
            "PAD(type=132, flags=0x00, len=7, value_bytes=3, padding_bytes=1)"
        );
    }

    #[test]
    fn sctp_show_exposes_stable_common_header_and_chunk_fields() {
        let sctp = Sctp::new()
            .sport(12_000)
            .dport(12_001)
            .vtag(0xaabb_ccdd)
            .chunk(SctpDataChunk::new([0xaa]).with_flags(0x03))
            .chunk(SctpChunk::unknown(
                SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
                0x80,
                [0xbb, 0xcc],
            ));
        let fields = sctp.inspection_fields();
        let packet = Packet::from_layer(sctp);
        let show = packet.show();
        let expected_chunk_summary = "DATA(type=0, flags=0x03, len=5, value_bytes=1, padding_bytes=3), UNKNOWN(type=255, flags=0x80, len=6, value_bytes=2, padding_bytes=2)";

        assert_eq!(field(&fields, "sport"), "12000");
        assert_eq!(field(&fields, "dport"), "12001");
        assert_eq!(field(&fields, "verification_tag"), "0xaabbccdd");
        assert_eq!(field(&fields, "checksum"), "auto");
        assert_eq!(field(&fields, "header_len"), "12");
        assert_eq!(field(&fields, "chunk_count"), "2");
        assert_eq!(field(&fields, "chunk_bytes"), "16");
        assert_eq!(field(&fields, "chunk_summary"), expected_chunk_summary);

        assert!(show.contains("[0] Sctp"));
        assert!(show.contains("sport: 12000"));
        assert!(show.contains("dport: 12001"));
        assert!(show.contains("verification_tag: 0xaabbccdd"));
        assert!(show.contains("chunk_count: 2"));
        assert!(show.contains("chunk_bytes: 16"));
        assert!(show.contains(&format!("chunk_summary: {expected_chunk_summary}")));
    }

    #[test]
    fn sctp_compile_header_supports_slash_composition() -> Result<()> {
        let compiled = (Sctp::new().sport(10).dport(20).checksum(0x0102_0304)
            / Raw::from_bytes([0xaa, 0xbb]))
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(bytes.len(), SCTP_COMMON_HEADER_LEN + 2);
        assert_eq!(&bytes[0..2], &10u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &20u16.to_be_bytes());
        assert_eq!(&bytes[8..12], &0x0102_0304u32.to_be_bytes());
        assert_eq!(&bytes[SCTP_COMMON_HEADER_LEN..], &[0xaa, 0xbb]);
        Ok(())
    }

    #[test]
    fn sctp_common_header_decoded_constructor_preserves_wire_values() {
        let sctp = Sctp::from_decoded_parts(0, 65_535, 0xffff_ffff, 0xdead_beef);

        assert_eq!(sctp.source_port.state(), FieldState::User);
        assert_eq!(sctp.destination_port.state(), FieldState::User);
        assert_eq!(sctp.verification_tag.state(), FieldState::User);
        assert_eq!(sctp.checksum.state(), FieldState::User);
        assert_eq!(sctp.source_port_value(), 0);
        assert_eq!(sctp.destination_port_value(), 65_535);
        assert_eq!(sctp.verification_tag_value(), 0xffff_ffff);
        assert_eq!(sctp.checksum_value(), Some(0xdead_beef));
        assert_eq!(sctp.checksum_status(), SctpChecksumStatus::NotChecked);
    }

    #[test]
    fn sctp_checksum_status_reports_decode_time_crc32c_state() -> Result<()> {
        let compiled = Packet::from_layer(Sctp::data(1, 2, 3, 4, b"payload".to_vec())).compile()?;
        let bytes = compiled.as_bytes();
        assert_eq!(
            decoded_sctp_checksum_status(bytes)?,
            SctpChecksumStatus::Valid
        );

        let mut invalid = bytes.to_vec();
        let mut bad_checksum = read_checksum(bytes) ^ 0xffff_ffff;
        if bad_checksum == 0 {
            bad_checksum = 1;
        }
        invalid[SCTP_CHECKSUM_OFFSET..SCTP_CHECKSUM_OFFSET + SCTP_CHECKSUM_LEN]
            .copy_from_slice(&bad_checksum.to_be_bytes());
        assert_ne!(read_checksum(&invalid), 0);
        assert_eq!(
            decoded_sctp_checksum_status(&invalid)?,
            SctpChecksumStatus::Invalid
        );

        let zero = Packet::from_layer(Sctp::data(1, 2, 3, 4, b"payload".to_vec()).checksum(0))
            .compile()?;
        assert_eq!(read_checksum(zero.as_bytes()), 0);
        assert_eq!(
            decoded_sctp_checksum_status(zero.as_bytes())?,
            SctpChecksumStatus::ZeroChecksum
        );

        let decoded = Sctp::from_decoded_parts_with_checksum_status(
            5_000,
            5_001,
            0x1122_3344,
            read_checksum(bytes),
            SctpChecksumStatus::Valid,
        );
        assert_eq!(decoded.checksum_status(), SctpChecksumStatus::Valid);
        assert_eq!(
            decoded.summary(),
            format!(
                "Sctp(sport=5000, dport=5001, vtag=0x11223344, chunks=0, checksum=0x{:08x}, checksum_status=valid)",
                read_checksum(bytes)
            )
        );
        let fields = decoded.inspection_fields();
        assert_eq!(field(&fields, "checksum_status"), "valid");
        assert!(Packet::from_layer(decoded)
            .show()
            .contains("checksum_status: valid"));
        Ok(())
    }

    #[test]
    fn sctp_layer_chunks_append_accessors_and_encoded_len() {
        let mut sctp = Sctp::new()
            .chunk(SctpDataChunk::new([0xaa]).with_flags(0x03))
            .with_chunk(SctpChunk::unknown(
                SCTP_CHUNK_TYPE_IETF_DEFINED_EXTENSION_4,
                0x80,
                [0xbb, 0xcc],
            ));

        assert_eq!(sctp.chunk_count(), 2);
        assert!(!sctp.is_chunks_empty());
        assert_eq!(sctp.chunks().len(), 2);
        assert!(matches!(sctp.chunks()[0], SctpChunk::Data(_)));
        assert!(matches!(sctp.chunks()[1], SctpChunk::Unknown(_)));
        assert_eq!(sctp.chunks_encoded_len(), 16);
        assert_eq!(sctp.encoded_len(), SCTP_COMMON_HEADER_LEN + 16);

        sctp.push_chunk(SctpShutdownCompleteChunk::new([]));
        assert_eq!(sctp.chunk_count(), 3);
        assert_eq!(
            sctp.chunks()[2].chunk_type_value(),
            SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE
        );

        sctp.chunks_mut().push(
            SctpChunk::from_preserved_parts(SCTP_CHUNK_TYPE_DATA, 0x01, 5, [0xdd], [0xee]).into(),
        );
        assert_eq!(sctp.into_chunks().len(), 4);
    }

    #[test]
    fn sctp_layer_chunks_with_chunks_builder_preserves_order() {
        let chunks = [
            SctpChunk::from(SctpDataChunk::new([0x01])),
            SctpChunk::from(SctpShutdownCompleteChunk::new([])),
        ];
        let sctp = Sctp::new().with_chunks(chunks.clone());

        assert_eq!(sctp.chunk_count(), 2);
        assert_eq!(sctp.chunks()[0].chunk_type_value(), SCTP_CHUNK_TYPE_DATA);
        assert_eq!(
            sctp.chunks()[1].chunk_type_value(),
            SCTP_CHUNK_TYPE_SHUTDOWN_COMPLETE
        );
    }

    #[test]
    fn sctp_layer_chunks_compile_before_trailing_raw_and_crc_covers_raw() -> Result<()> {
        let compiled = (Sctp::new()
            .sport(10)
            .dport(20)
            .vtag(0x1122_3344)
            .chunk(SctpDataChunk::new([0xaa]).with_flags(0x03))
            / Raw::from_bytes([0xde, 0xad]))
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(bytes.len(), SCTP_COMMON_HEADER_LEN + 8 + 2);
        assert_eq!(&bytes[0..2], &10u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &20u16.to_be_bytes());
        assert_eq!(&bytes[4..8], &0x1122_3344u32.to_be_bytes());
        assert_eq!(
            &bytes[SCTP_COMMON_HEADER_LEN..SCTP_COMMON_HEADER_LEN + 8],
            &[
                SCTP_CHUNK_TYPE_DATA,
                0x03,
                0x00,
                0x05,
                0xaa,
                0x00,
                0x00,
                0x00
            ]
        );
        assert_eq!(&bytes[SCTP_COMMON_HEADER_LEN + 8..], &[0xde, 0xad]);
        assert_eq!(read_checksum(bytes), sctp_packet_crc32c(bytes)?);
        Ok(())
    }

    #[test]
    fn sctp_layer_chunks_explicit_checksum_survives_chunks_and_raw_tail() -> Result<()> {
        let compiled = (Sctp::new().checksum(0).chunk(SctpDataChunk::new([0xaa]))
            / Raw::from_bytes([0xde]))
        .compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(read_checksum(bytes), 0);
        assert_ne!(sctp_packet_crc32c(bytes)?, 0);
        assert_eq!(&bytes[SCTP_COMMON_HEADER_LEN + 8..], &[0xde]);
        Ok(())
    }

    #[test]
    fn sctp_layer_chunks_decoded_constructor_preserves_explicit_chunks() -> Result<()> {
        let chunk = SctpChunk::from_preserved_parts(
            SCTP_CHUNK_TYPE_DATA,
            0x01,
            5,
            [0xaa],
            [0xbb, 0xcc, 0xdd],
        );
        let sctp =
            Sctp::from_decoded_parts_with_chunks(1, 2, 0x0102_0304, 0x1122_3344, vec![chunk]);
        let compiled = Packet::from_layer(sctp.clone()).compile()?;
        let bytes = compiled.as_bytes();

        assert_eq!(sctp.chunk_count(), 1);
        assert_eq!(sctp.chunks()[0].explicit_declared_length(), Some(5));
        assert_eq!(sctp.chunks()[0].padding(), &[0xbb, 0xcc, 0xdd]);
        assert_eq!(read_checksum(bytes), 0x1122_3344);
        assert_eq!(
            &bytes[SCTP_COMMON_HEADER_LEN..],
            &[
                SCTP_CHUNK_TYPE_DATA,
                0x01,
                0x00,
                0x05,
                0xaa,
                0xbb,
                0xcc,
                0xdd
            ]
        );
        Ok(())
    }
}
