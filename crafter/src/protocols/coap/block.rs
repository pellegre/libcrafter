//! Lossless Block1, Block2, Q-Block, and BERT option metadata.
//!
//! The `NUM | M | SZX` layout comes from RFC 7959 Section 2.2 and is reused
//! by RFC 9177 Section 4.2 for Q-Block. RFC 8323 Section 6 assigns SZX 7 to
//! BERT only for Block1 and Block2 over reliable transports. Transfer
//! assembly, scheduling, retransmission, and congestion control belong to
//! callers.

use crate::error::{CrafterError, Result};

use super::constants::{
    COAP_OPTION_BLOCK1, COAP_OPTION_BLOCK2, COAP_OPTION_Q_BLOCK1, COAP_OPTION_Q_BLOCK2,
};
use super::option::CoapOption;

const COAP_BLOCK_MAX_NUMBER: u64 = 0x0f_ffff;
const COAP_BLOCK_MAX_WIRE_LEN: usize = 3;
const COAP_BLOCK_BERT_SZX: u8 = 7;
const COAP_BLOCK_BERT_UNIT: u64 = 1024;
const COAP_QBLOCK_DEFAULT_MAX_PAYLOADS: u64 = 10;

/// The CoAP option whose shared block-value grammar is being interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoapBlockKind {
    /// RFC 7959 Block1 request-body metadata (option 27).
    Block1,
    /// RFC 7959 Block2 response-body metadata (option 23).
    Block2,
    /// RFC 9177 Q-Block1 request-body metadata (option 19).
    QBlock1,
    /// RFC 9177 Q-Block2 response-body metadata (option 31).
    QBlock2,
}

impl CoapBlockKind {
    /// Return the assigned CoAP option number for this block kind.
    pub const fn option_number(self) -> u16 {
        match self {
            Self::Block1 => COAP_OPTION_BLOCK1,
            Self::Block2 => COAP_OPTION_BLOCK2,
            Self::QBlock1 => COAP_OPTION_Q_BLOCK1,
            Self::QBlock2 => COAP_OPTION_Q_BLOCK2,
        }
    }

    /// Return whether this kind belongs to RFC 9177 Q-Block.
    pub const fn is_qblock(self) -> bool {
        matches!(self, Self::QBlock1 | Self::QBlock2)
    }

    fn from_option_number(number: u16) -> Option<Self> {
        match number {
            COAP_OPTION_BLOCK1 => Some(Self::Block1),
            COAP_OPTION_BLOCK2 => Some(Self::Block2),
            COAP_OPTION_Q_BLOCK1 => Some(Self::QBlock1),
            COAP_OPTION_Q_BLOCK2 => Some(Self::QBlock2),
            _ => None,
        }
    }
}

/// Transport context used for source-backed Block and BERT validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoapBlockTransport {
    /// CoAP over a datagram transport such as UDP.
    Datagram,
    /// CoAP over an RFC 8323 reliable transport.
    Reliable,
}

/// Stateless semantic findings for one block option and payload context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoapBlockValidation {
    issues: Vec<CrafterError>,
}

impl CoapBlockValidation {
    /// Return whether no semantic inconsistency was found.
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    /// Borrow deterministic validation findings in check order.
    pub fn issues(&self) -> &[CrafterError] {
        &self.issues
    }

    /// Consume the report and return its deterministic findings.
    pub fn into_issues(self) -> Vec<CrafterError> {
        self.issues
    }

    fn push(&mut self, field: &'static str, reason: &'static str) {
        self.issues
            .push(CrafterError::invalid_field_value(field, reason));
    }

    fn extend(&mut self, other: Self) {
        self.issues.extend(other.issues);
    }
}

/// One lossless CoAP Block or Q-Block option value.
///
/// Canonical constructors emit the shortest CoAP `uint` representation.
/// [`Self::from_raw_bytes`] retains zero-prefixed and overlong values up to
/// 64 bits so malformed packets can be inspected and re-emitted exactly.
/// [`Self::validate`] reports source-level constraints without changing those
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoapBlock {
    raw_value: u64,
    wire_value: Vec<u8>,
    option_kind: Option<CoapBlockKind>,
}

impl CoapBlock {
    /// Largest block number representable by a source-conformant 3-byte value.
    pub const MAX_NUMBER: u64 = COAP_BLOCK_MAX_NUMBER;

    /// The SZX value assigned to BERT by RFC 8323 Section 6.
    pub const BERT_SZX: u8 = COAP_BLOCK_BERT_SZX;

    /// The byte unit used by BERT block numbers and payload chunks.
    pub const BERT_UNIT: u64 = COAP_BLOCK_BERT_UNIT;

    /// RFC 9177's default number of payloads in one Q-Block set.
    ///
    /// This is inspectable grouping metadata only. Callers remain responsible
    /// for configuration agreement, congestion control, and transmission.
    pub const QBLOCK_DEFAULT_MAX_PAYLOADS: u64 = COAP_QBLOCK_DEFAULT_MAX_PAYLOADS;

    /// Build a block value using the shortest CoAP `uint` representation.
    ///
    /// SZX 7 is retained for contextual BERT validation. Values above 7 have
    /// no three-bit wire representation and are rejected. Numbers wider than
    /// the RFC 7959 20-bit field may be deliberately constructed when they
    /// still fit the lossless 64-bit model; [`Self::validate`] reports them.
    pub fn new(number: u64, more: bool, szx: u8) -> Result<Self> {
        if szx > COAP_BLOCK_BERT_SZX {
            return Err(CrafterError::invalid_field_value(
                "coap.block.szx",
                "SZX must fit in three bits",
            ));
        }
        if number > (u64::MAX >> 4) {
            return Err(CrafterError::invalid_field_value(
                "coap.block.number",
                "block number cannot be encoded without overflow",
            ));
        }

        let raw_value = (number << 4) | (u64::from(more) << 3) | u64::from(szx);
        Ok(Self {
            raw_value,
            wire_value: encode_coap_uint(raw_value),
            option_kind: None,
        })
    }

    /// Build a canonical block value carrying explicit option-kind context.
    pub fn new_for(kind: CoapBlockKind, number: u64, more: bool, szx: u8) -> Result<Self> {
        Ok(Self::new(number, more, szx)?.with_option_kind(kind))
    }

    /// Build a canonical RFC 7959 Block1 value.
    ///
    /// This convenience constructor attaches request-body option context but
    /// does not infer a request method, payload, transfer state, or Size1.
    pub fn block1(number: u64, more: bool, szx: u8) -> Result<Self> {
        Self::new_for(CoapBlockKind::Block1, number, more, szx)
    }

    /// Build a canonical RFC 7959 Block2 value.
    ///
    /// This constructor attaches response-body option context but does not
    /// infer whether the value is request control metadata or a descriptive
    /// response fragment.
    pub fn block2(number: u64, more: bool, szx: u8) -> Result<Self> {
        Self::new_for(CoapBlockKind::Block2, number, more, szx)
    }

    /// Build a canonical RFC 9177 Q-Block1 value.
    ///
    /// This convenience constructor attaches request-body option context but
    /// does not allocate a Request-Tag, infer Size1, or retain transfer state.
    pub fn qblock1(number: u64, more: bool, szx: u8) -> Result<Self> {
        Self::new_for(CoapBlockKind::QBlock1, number, more, szx)
    }

    /// Build a canonical RFC 9177 Q-Block2 value.
    ///
    /// The M bit remains caller-controlled because it distinguishes a single
    /// requested block from an entire-body, continuation, or set-tail request.
    pub fn qblock2(number: u64, more: bool, szx: u8) -> Result<Self> {
        Self::new_for(CoapBlockKind::QBlock2, number, more, szx)
    }

    /// Decode exact CoAP `uint` bytes while retaining their original form.
    ///
    /// Empty bytes decode to zero. Up to eight bytes are retained, including
    /// noncanonical leading zeroes and malformed values wider than the
    /// source-conformant three-byte Block option limit.
    pub fn from_raw_bytes(raw_bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let wire_value = raw_bytes.into();
        if wire_value.len() > size_of::<u64>() {
            return Err(CrafterError::invalid_field_value(
                "coap.block.value",
                "block option value exceeds 64 bits",
            ));
        }

        let raw_value = wire_value
            .iter()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
        Ok(Self {
            raw_value,
            wire_value,
            option_kind: None,
        })
    }

    /// Decode exact bytes while attaching explicit option-kind context.
    pub fn from_raw_bytes_for(kind: CoapBlockKind, raw_bytes: impl Into<Vec<u8>>) -> Result<Self> {
        Ok(Self::from_raw_bytes(raw_bytes)?.with_option_kind(kind))
    }

    /// Attach the option kind without changing the encoded block value.
    pub const fn with_option_kind(mut self, kind: CoapBlockKind) -> Self {
        self.option_kind = Some(kind);
        self
    }

    /// Return attached option-kind context, when known.
    pub const fn option_kind(&self) -> Option<CoapBlockKind> {
        self.option_kind
    }

    /// Return the decoded unsigned integer before bit-field interpretation.
    pub const fn raw_value(&self) -> u64 {
        self.raw_value
    }

    /// Borrow the exact canonical or decoded option value bytes.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.wire_value
    }

    /// Return the decoded NUM field.
    pub const fn number(&self) -> u64 {
        self.raw_value >> 4
    }

    /// Return the decoded M (more) bit.
    pub const fn more(&self) -> bool {
        (self.raw_value & 0x08) != 0
    }

    /// Return the decoded three-bit SZX field.
    pub const fn szx(&self) -> u8 {
        (self.raw_value & 0x07) as u8
    }

    /// Return whether this value carries the SZX encoding assigned to BERT.
    ///
    /// BERT is valid only for Block1/Block2 over a reliable transport. Use
    /// [`Self::validate`] when the kind and transport context are available.
    pub const fn is_bert(&self) -> bool {
        self.szx() == COAP_BLOCK_BERT_SZX
    }

    /// Return the block-size unit in bytes.
    ///
    /// SZX 0 through 6 map to 16 through 1024 bytes. SZX 7 uses the 1024-byte
    /// BERT unit rather than the reserved RFC 7959 value of 2048 bytes.
    pub const fn block_size(&self) -> u64 {
        if self.szx() >= 6 {
            COAP_BLOCK_BERT_UNIT
        } else {
            1u64 << (self.szx() + 4)
        }
    }

    /// Return the checked byte offset `NUM * block_size`.
    pub fn offset(&self) -> Result<u64> {
        self.number().checked_mul(self.block_size()).ok_or_else(|| {
            CrafterError::invalid_field_value("coap.block.offset", "block byte offset overflow")
        })
    }

    /// Return the zero-based RFC 9177 MAX_PAYLOADS_SET index.
    ///
    /// This is a pure grouping calculation; it does not schedule or pace a
    /// burst. `max_payloads` must be nonzero and NUM must fit the 20-bit field.
    pub fn qblock_set_index(&self, max_payloads: u64) -> Result<u64> {
        self.validate_qblock_grouping(max_payloads)?;
        Ok(self.number() / max_payloads)
    }

    /// Return NUM's zero-based position within its MAX_PAYLOADS_SET.
    pub fn qblock_set_position(&self, max_payloads: u64) -> Result<u64> {
        self.validate_qblock_grouping(max_payloads)?;
        Ok(self.number() % max_payloads)
    }

    /// Return the first block number in NUM's MAX_PAYLOADS_SET.
    pub fn qblock_set_start_number(&self, max_payloads: u64) -> Result<u64> {
        self.qblock_set_index(max_payloads)?
            .checked_mul(max_payloads)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "coap.qblock.max-payloads",
                    "Q-Block set start overflow",
                )
            })
    }

    /// Return the last representable block number in NUM's MAX_PAYLOADS_SET.
    pub fn qblock_set_end_number(&self, max_payloads: u64) -> Result<u64> {
        let start = self.qblock_set_start_number(max_payloads)?;
        let end = start.checked_add(max_payloads - 1).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.qblock.max-payloads",
                "Q-Block set end overflow",
            )
        })?;
        Ok(end.min(Self::MAX_NUMBER))
    }

    /// Return the next NUM in strictly increasing Q-Block order.
    pub fn qblock_next_number(&self) -> Result<u64> {
        let next = self.number().checked_add(1).ok_or_else(|| {
            CrafterError::invalid_field_value("coap.block.number", "next Q-Block number overflow")
        })?;
        if next > Self::MAX_NUMBER {
            return Err(CrafterError::invalid_field_value(
                "coap.block.number",
                "next Q-Block number exceeds the 20-bit NUM field",
            ));
        }
        Ok(next)
    }

    /// Return whether `next` follows this value in strict NUM order.
    ///
    /// This helper intentionally accepts gaps, as recovery requests list only
    /// missing block numbers, but rejects duplicates and descending values.
    pub const fn qblock_precedes(&self, next: &Self) -> bool {
        self.number() < next.number()
    }

    /// Return the inclusive block-number range selected by a Q-Block2 request.
    ///
    /// RFC 9177 Section 4.4 assigns these request meanings: an unset M bit
    /// selects only NUM; `NUM=0, M=1` selects the entire body; any other set M
    /// bit selects NUM through the end of its MAX_PAYLOADS_SET. A set-boundary
    /// NUM therefore describes the stateless `Continue` range for that set.
    pub fn qblock2_request_range(&self, max_payloads: u64) -> Result<(u64, u64)> {
        self.validate_qblock_grouping(max_payloads)?;
        if !self.more() {
            return Ok((self.number(), self.number()));
        }
        if self.number() == 0 {
            return Ok((0, Self::MAX_NUMBER));
        }
        Ok((self.number(), self.qblock_set_end_number(max_payloads)?))
    }

    /// Return whether this Q-Block2 request selects `block_number`.
    pub fn qblock2_request_covers(&self, block_number: u64, max_payloads: u64) -> Result<bool> {
        if block_number > Self::MAX_NUMBER {
            return Err(CrafterError::invalid_field_value(
                "coap.block.number",
                "requested Q-Block number must fit in the 20-bit NUM field",
            ));
        }
        let (start, end) = self.qblock2_request_range(max_payloads)?;
        Ok((start..=end).contains(&block_number))
    }

    /// Return whether this is the RFC 9177 `Continue` Q-Block2 request shape.
    pub fn is_qblock2_continue(&self, max_payloads: u64) -> Result<bool> {
        Ok(self.more() && self.number() != 0 && self.qblock_set_position(max_payloads)? == 0)
    }

    /// Return how many 1024-byte BERT blocks `payload_len` represents.
    ///
    /// A final reliable-message payload may end with a partial block, so a
    /// nonempty partial unit counts as one represented block. This helper is
    /// stateless and does not decide whether another message should be sent.
    pub fn bert_block_count(&self, payload_len: usize) -> Result<u64> {
        self.require_bert()?;

        let payload_len = u64::try_from(payload_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "coap.block.payload-length",
                "BERT payload length exceeds the supported integer range",
            )
        })?;
        let complete = payload_len / Self::BERT_UNIT;
        if payload_len % Self::BERT_UNIT == 0 {
            Ok(complete)
        } else {
            complete.checked_add(1).ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "coap.block.payload-length",
                    "BERT payload block count overflow",
                )
            })
        }
    }

    /// Return the checked byte offset immediately after `payload_len` bytes.
    ///
    /// Unlike [`Self::bert_next_offset`], this is the exact payload boundary
    /// and therefore does not round a final partial BERT block up to 1024
    /// bytes.
    pub fn bert_payload_end_offset(&self, payload_len: usize) -> Result<u64> {
        self.require_bert()?;
        let payload_len = u64::try_from(payload_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "coap.block.payload-length",
                "BERT payload length exceeds the supported integer range",
            )
        })?;
        self.offset()?.checked_add(payload_len).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.block.offset",
                "BERT payload end offset overflow",
            )
        })
    }

    /// Return the next BERT NUM after the represented reliable payload.
    ///
    /// The result advances by [`Self::bert_block_count`] and must still fit
    /// the 20-bit NUM field so that it can be encoded in a following Block1
    /// or Block2 option.
    pub fn bert_next_number(&self, payload_len: usize) -> Result<u64> {
        let next = self
            .number()
            .checked_add(self.bert_block_count(payload_len)?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "coap.block.number",
                    "next BERT block number overflow",
                )
            })?;
        if next > Self::MAX_NUMBER {
            return Err(CrafterError::invalid_field_value(
                "coap.block.number",
                "next BERT block number exceeds the 20-bit NUM field",
            ));
        }
        Ok(next)
    }

    /// Return the 1024-byte boundary selected by the next BERT NUM.
    pub fn bert_next_offset(&self, payload_len: usize) -> Result<u64> {
        self.bert_next_number(payload_len)?
            .checked_mul(Self::BERT_UNIT)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "coap.block.offset",
                    "next BERT block byte offset overflow",
                )
            })
    }

    /// Convert this value to an exact CoAP option occurrence of `kind`.
    pub fn into_option(self, kind: CoapBlockKind) -> CoapOption {
        CoapOption::new(kind.option_number(), self.wire_value)
    }

    /// Convert this value to an exact RFC 7959 Block1 option occurrence.
    ///
    /// Exact decoded bytes remain authoritative, including a server-selected
    /// size and noncanonical uint encodings used for malformed packet work.
    pub fn into_block1_option(self) -> CoapOption {
        self.into_option(CoapBlockKind::Block1)
    }

    /// Convert this value to an exact RFC 7959 Block2 option occurrence.
    ///
    /// Exact decoded bytes remain authoritative, including noncanonical uint
    /// encodings used for malformed packet work.
    pub fn into_block2_option(self) -> CoapOption {
        self.into_option(CoapBlockKind::Block2)
    }

    /// Convert this value to an exact RFC 9177 Q-Block1 option occurrence.
    pub fn into_qblock1_option(self) -> CoapOption {
        self.into_option(CoapBlockKind::QBlock1)
    }

    /// Convert this value to an exact RFC 9177 Q-Block2 option occurrence.
    pub fn into_qblock2_option(self) -> CoapOption {
        self.into_option(CoapBlockKind::QBlock2)
    }

    /// Validate this value as descriptive Block1 request metadata.
    ///
    /// The payload length rule is reported only here (or through the
    /// message-level Block1 report); construction and compilation remain
    /// lossless even when the M bit and payload length disagree.
    pub fn validate_block1(
        &self,
        transport: CoapBlockTransport,
        payload_len: usize,
    ) -> CoapBlockValidation {
        self.validate(CoapBlockKind::Block1, transport, payload_len)
    }

    /// Validate this value as Block2 request selection metadata.
    ///
    /// RFC 7959 Sections 2.3 and 2.4 require the M bit to be zero in a
    /// request. Validation is opt-in and never prevents the exact value from
    /// being compiled.
    pub fn validate_block2_request(&self, transport: CoapBlockTransport) -> CoapBlockValidation {
        let mut validation = self.validate_control(CoapBlockKind::Block2, transport);
        if self.more() {
            validation.push(
                "coap.block2.request.more",
                "Block2 request M bit must be zero",
            );
        }
        validation
    }

    /// Validate a descriptive Block2 response and optional request selection.
    ///
    /// Non-final fragment length follows the selected response SZX. When a
    /// request Block2 is supplied, the response may retain or reduce its size
    /// but must describe the same byte offset. These checks report findings
    /// only; they do not rewrite either exact option value.
    pub fn validate_block2_response(
        &self,
        transport: CoapBlockTransport,
        payload_len: usize,
        requested: Option<&Self>,
    ) -> CoapBlockValidation {
        let mut validation = self.validate(CoapBlockKind::Block2, transport, payload_len);

        if let Some(requested) = requested {
            validation.extend(requested.validate_block2_request(transport));

            if self.block_size() > requested.block_size() {
                validation.push(
                    "coap.block2.response.size",
                    "returned Block2 size must not exceed requested size",
                );
            }

            if let (Ok(requested_offset), Ok(returned_offset)) = (requested.offset(), self.offset())
            {
                if returned_offset != requested_offset {
                    validation.push(
                        "coap.block2.response.offset",
                        "returned Block2 offset must match requested offset",
                    );
                }
            }
        }

        validation
    }

    /// Validate descriptive Q-Block1 request payload metadata.
    ///
    /// Request-Tag and Size1 presence are message-level requirements. This
    /// packet-local report checks the exact Q-Block value and payload length.
    pub fn validate_qblock1_request(
        &self,
        transport: CoapBlockTransport,
        payload_len: usize,
    ) -> CoapBlockValidation {
        self.validate(CoapBlockKind::QBlock1, transport, payload_len)
    }

    /// Validate Q-Block1 response control metadata without a payload rule.
    pub fn validate_qblock1_response(&self, transport: CoapBlockTransport) -> CoapBlockValidation {
        self.validate_control(CoapBlockKind::QBlock1, transport)
    }

    /// Validate one Q-Block2 request selector and its grouping parameter.
    pub fn validate_qblock2_request(
        &self,
        transport: CoapBlockTransport,
        max_payloads: u64,
    ) -> CoapBlockValidation {
        let mut validation = self.validate_control(CoapBlockKind::QBlock2, transport);
        if self.qblock2_request_range(max_payloads).is_err() {
            validation.push(
                "coap.qblock.max-payloads",
                "MAX_PAYLOADS must be nonzero and Q-Block NUM must fit in 20 bits",
            );
        }
        validation
    }

    /// Validate a Q-Block2 response payload against an optional request range.
    ///
    /// The request can select one block, the entire body, or the remaining
    /// blocks in a MAX_PAYLOADS_SET. This helper checks only packet-local
    /// range, size, and payload facts; it retains no response or body state.
    pub fn validate_qblock2_response(
        &self,
        transport: CoapBlockTransport,
        payload_len: usize,
        requested: Option<&Self>,
        max_payloads: u64,
    ) -> CoapBlockValidation {
        let mut validation = self.validate(CoapBlockKind::QBlock2, transport, payload_len);

        if let Some(requested) = requested {
            validation.extend(requested.validate_qblock2_request(transport, max_payloads));

            if self.block_size() > requested.block_size() {
                validation.push(
                    "coap.qblock2.response.size",
                    "returned Q-Block2 size must not exceed requested size",
                );
            }

            match requested.qblock2_request_covers(self.number(), max_payloads) {
                Ok(true) => {}
                Ok(false) => validation.push(
                    "coap.qblock2.response.number",
                    "returned Q-Block2 number is outside the requested range",
                ),
                Err(_) => {}
            }
        }

        validation
    }

    /// Validate source-level Block, Q-Block, BERT, and payload constraints.
    ///
    /// Validation is opt-in and never changes the exact raw representation.
    /// For ordinary descriptive blocks, a non-final payload must equal the
    /// selected block size, and a final ordinary Block1 or Block2 payload must
    /// not exceed it.
    /// For reliable BERT, a non-final payload must be a positive multiple of
    /// 1024 bytes; final BERT payloads may include any number of complete
    /// units plus a final partial unit.
    pub fn validate(
        &self,
        kind: CoapBlockKind,
        transport: CoapBlockTransport,
        payload_len: usize,
    ) -> CoapBlockValidation {
        let mut validation = self.validate_control(kind, transport);

        if self.is_bert() {
            if !kind.is_qblock()
                && transport == CoapBlockTransport::Reliable
                && self.more()
                && (payload_len == 0 || payload_len % COAP_BLOCK_BERT_UNIT as usize != 0)
            {
                validation.push(
                    "coap.block.payload-length",
                    "non-final BERT payload must be a positive multiple of 1024 bytes",
                );
            }

            if !kind.is_qblock() && transport == CoapBlockTransport::Reliable {
                match self.bert_block_count(payload_len) {
                    Ok(0) => {}
                    Ok(block_count) => {
                        let last_delta = block_count - 1;
                        let last_number = self.number().checked_add(last_delta);
                        if !matches!(last_number, Some(number) if number <= Self::MAX_NUMBER) {
                            validation.push(
                                "coap.block.number",
                                "BERT payload exceeds the 20-bit NUM field",
                            );
                        } else if self.more() && self.bert_next_number(payload_len).is_err() {
                            validation.push(
                                "coap.block.number",
                                "next BERT block number exceeds the 20-bit NUM field",
                            );
                        }
                    }
                    Err(_) => validation.push(
                        "coap.block.payload-length",
                        "BERT payload length cannot be represented safely",
                    ),
                }
            }
        } else if self.more() {
            if payload_len as u128 != u128::from(self.block_size()) {
                validation.push(
                    "coap.block.payload-length",
                    "non-final block payload must equal the selected block size",
                );
            }
        } else if payload_len as u128 > u128::from(self.block_size()) {
            let reason = match kind {
                CoapBlockKind::Block1 => {
                    "final Block1 payload must not exceed the selected block size"
                }
                CoapBlockKind::Block2 => {
                    "final Block2 payload must not exceed the selected block size"
                }
                CoapBlockKind::QBlock1 => {
                    "final Q-Block1 payload must not exceed the selected block size"
                }
                CoapBlockKind::QBlock2 => {
                    "final Q-Block2 payload must not exceed the selected block size"
                }
            };
            validation.push("coap.block.payload-length", reason);
        }

        validation
    }

    /// Validate Block1/Block2 control metadata without applying a payload rule.
    ///
    /// Block1 in a response describes acknowledgement, atomicity, and the
    /// server's selected size; it does not describe that response's payload.
    pub(super) fn validate_control(
        &self,
        kind: CoapBlockKind,
        transport: CoapBlockTransport,
    ) -> CoapBlockValidation {
        let mut validation = CoapBlockValidation::default();

        if let Some(option_kind) = self.option_kind {
            if option_kind != kind {
                validation.push(
                    "coap.block.kind",
                    "validation kind differs from decoded option kind",
                );
            }
        }
        if self.wire_value.len() > COAP_BLOCK_MAX_WIRE_LEN {
            validation.push(
                "coap.block.value",
                "Block option value must not exceed 3 bytes",
            );
        }
        if self.wire_value != encode_coap_uint(self.raw_value) {
            validation.push(
                "coap.block.value",
                "Block option uint is not canonically encoded",
            );
        }
        if self.number() > Self::MAX_NUMBER {
            validation.push(
                "coap.block.number",
                "block number must fit in the 20-bit NUM field",
            );
        }
        if self.offset().is_err() {
            validation.push("coap.block.offset", "block byte offset overflow");
        }

        if self.is_bert() {
            if kind.is_qblock() {
                validation.push("coap.block.szx", "Q-Block does not define BERT SZX 7");
            } else if transport != CoapBlockTransport::Reliable {
                validation.push("coap.block.szx", "BERT SZX 7 requires a reliable transport");
            }
        }

        validation
    }

    fn require_bert(&self) -> Result<()> {
        if self.is_bert() {
            Ok(())
        } else {
            Err(CrafterError::invalid_field_value(
                "coap.block.szx",
                "BERT helper requires SZX 7",
            ))
        }
    }

    fn validate_qblock_grouping(&self, max_payloads: u64) -> Result<()> {
        if max_payloads == 0 {
            return Err(CrafterError::invalid_field_value(
                "coap.qblock.max-payloads",
                "MAX_PAYLOADS must be nonzero",
            ));
        }
        if self.number() > Self::MAX_NUMBER {
            return Err(CrafterError::invalid_field_value(
                "coap.block.number",
                "Q-Block number must fit in the 20-bit NUM field",
            ));
        }
        Ok(())
    }
}

impl TryFrom<&CoapOption> for CoapBlock {
    type Error = CrafterError;

    fn try_from(option: &CoapOption) -> Result<Self> {
        let kind = CoapBlockKind::from_option_number(option.number().value()).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "coap.block.kind",
                "option number is not Block1, Block2, Q-Block1, or Q-Block2",
            )
        })?;
        Self::from_raw_bytes_for(kind, option.value())
    }
}

fn encode_coap_uint(value: u64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let encoded = value.to_be_bytes();
    let first = encoded
        .iter()
        .position(|byte| *byte != 0)
        .expect("a nonzero integer contains a nonzero byte");
    encoded[first..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;
    use crate::protocols::coap::{Coap, CoapEtag, CoapRequestTag, CoapSize1, CoapSize2};

    #[test]
    fn canonical_boundaries_cover_every_standard_szx() {
        let expected_sizes = [16, 32, 64, 128, 256, 512, 1024];
        for (szx, expected_size) in expected_sizes.into_iter().enumerate() {
            let block = CoapBlock::new(0, false, szx as u8).unwrap();
            assert_eq!(block.raw_value(), szx as u64);
            assert_eq!(block.number(), 0);
            assert!(!block.more());
            assert_eq!(block.szx(), szx as u8);
            assert_eq!(block.block_size(), expected_size);
            assert_eq!(block.offset().unwrap(), 0);
        }

        let maximum = CoapBlock::new(CoapBlock::MAX_NUMBER, true, 6).unwrap();
        assert_eq!(maximum.raw_bytes(), &[0xff, 0xff, 0xfe]);
        assert_eq!(maximum.offset().unwrap(), 1_073_740_800);
        assert!(maximum
            .validate(CoapBlockKind::Block1, CoapBlockTransport::Datagram, 1024)
            .is_valid());
    }

    #[test]
    fn empty_and_noncanonical_uint_bytes_round_trip_exactly() {
        let empty = CoapBlock::from_raw_bytes_for(CoapBlockKind::Block2, Vec::new()).unwrap();
        assert_eq!(empty.raw_value(), 0);
        assert_eq!(empty.raw_bytes(), b"");
        assert_eq!(empty.block_size(), 16);

        let option = CoapOption::new(COAP_OPTION_Q_BLOCK1, vec![0, 0, 0x10]);
        let decoded = CoapBlock::try_from(&option).unwrap();
        assert_eq!(decoded.option_kind(), Some(CoapBlockKind::QBlock1));
        assert_eq!(decoded.number(), 1);
        assert_eq!(decoded.raw_bytes(), &[0, 0, 0x10]);
        let encoded = decoded.clone().into_option(CoapBlockKind::QBlock1);
        assert_eq!(encoded.value(), &[0, 0, 0x10]);
        assert!(!decoded
            .validate(CoapBlockKind::QBlock1, CoapBlockTransport::Datagram, 0)
            .is_valid());
    }

    #[test]
    fn all_option_kinds_map_and_decode_with_context() {
        for kind in [
            CoapBlockKind::Block1,
            CoapBlockKind::Block2,
            CoapBlockKind::QBlock1,
            CoapBlockKind::QBlock2,
        ] {
            let block = CoapBlock::new_for(kind, 42, true, 5).unwrap();
            let option = block.clone().into_option(kind);
            assert_eq!(option.number().value(), kind.option_number());
            let decoded = CoapBlock::try_from(&option).unwrap();
            assert_eq!(decoded, block);
        }

        let unrelated = CoapOption::new(12u16, Vec::new());
        assert!(CoapBlock::try_from(&unrelated).is_err());
    }

    #[test]
    fn bert_uses_reliable_1024_byte_units() {
        let bert = CoapBlock::new_for(CoapBlockKind::Block1, 3, true, 7).unwrap();
        assert_eq!(bert.raw_value(), 0x3f);
        assert_eq!(bert.raw_bytes(), &[0x3f]);
        assert!(bert.is_bert());
        assert_eq!(CoapBlock::BERT_SZX, 7);
        assert_eq!(CoapBlock::BERT_UNIT, 1024);
        assert_eq!(bert.block_size(), 1024);
        assert_eq!(bert.offset().unwrap(), 3072);
        assert_eq!(bert.bert_block_count(2048).unwrap(), 2);
        assert_eq!(bert.bert_payload_end_offset(2048).unwrap(), 5120);
        assert_eq!(bert.bert_next_number(2048).unwrap(), 5);
        assert_eq!(bert.bert_next_offset(2048).unwrap(), 5120);
        assert!(bert
            .validate(CoapBlockKind::Block1, CoapBlockTransport::Reliable, 2048)
            .is_valid());
        assert!(!bert
            .validate(CoapBlockKind::Block1, CoapBlockTransport::Reliable, 1536)
            .is_valid());
        assert!(!bert
            .validate(CoapBlockKind::Block1, CoapBlockTransport::Datagram, 2048)
            .is_valid());
        assert!(!bert
            .validate(CoapBlockKind::QBlock1, CoapBlockTransport::Reliable, 2048)
            .is_valid());

        let final_bert = CoapBlock::new(8, false, 7).unwrap();
        assert_eq!(final_bert.bert_block_count(4711).unwrap(), 5);
        assert_eq!(final_bert.bert_payload_end_offset(4711).unwrap(), 12_903);
        assert_eq!(final_bert.bert_next_number(4711).unwrap(), 13);
        assert_eq!(final_bert.bert_next_offset(4711).unwrap(), 13_312);
        assert!(final_bert
            .validate(CoapBlockKind::Block2, CoapBlockTransport::Reliable, 4711)
            .is_valid());

        let non_bert = CoapBlock::block1(0, false, 6).unwrap();
        assert!(matches!(
            non_bert.bert_block_count(1024),
            Err(CrafterError::InvalidFieldValue {
                field: "coap.block.szx",
                ..
            })
        ));
    }

    #[test]
    fn bert_validation_covers_partial_oversized_and_wrong_transport_payloads() {
        // RFC 8323 Section 6 permits a partial final BERT block but requires
        // every non-final payload to be a positive multiple of 1024 bytes.
        let partial = CoapBlock::block2(4, false, CoapBlock::BERT_SZX).unwrap();
        assert!(partial
            .validate(CoapBlockKind::Block2, CoapBlockTransport::Reliable, 1537)
            .is_valid());

        let partial_non_final = CoapBlock::block2(4, true, CoapBlock::BERT_SZX).unwrap();
        assert!(matches!(
            partial_non_final
                .validate(CoapBlockKind::Block2, CoapBlockTransport::Reliable, 1537)
                .issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block.payload-length",
                reason: "non-final BERT payload must be a positive multiple of 1024 bytes",
            }]
        ));

        let oversized =
            CoapBlock::block1(CoapBlock::MAX_NUMBER, false, CoapBlock::BERT_SZX).unwrap();
        assert_eq!(oversized.bert_block_count(1025).unwrap(), 2);
        assert!(matches!(
            oversized.bert_next_number(1025),
            Err(CrafterError::InvalidFieldValue {
                field: "coap.block.number",
                reason: "next BERT block number exceeds the 20-bit NUM field",
            })
        ));
        assert!(matches!(
            oversized
                .validate(CoapBlockKind::Block1, CoapBlockTransport::Reliable, 1025)
                .issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block.number",
                reason: "BERT payload exceeds the 20-bit NUM field",
            }]
        ));

        let wrong_transport = CoapBlock::block1(0, true, CoapBlock::BERT_SZX).unwrap();
        assert!(matches!(
            wrong_transport
                .validate(CoapBlockKind::Block1, CoapBlockTransport::Datagram, 1024)
                .issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block.szx",
                reason: "BERT SZX 7 requires a reliable transport",
            }]
        ));
    }

    #[test]
    fn validation_reports_payload_and_raw_value_boundaries() {
        let non_final = CoapBlock::new(1, true, 0).unwrap();
        assert!(non_final
            .validate(CoapBlockKind::Block1, CoapBlockTransport::Datagram, 16)
            .is_valid());
        assert!(!non_final
            .validate(CoapBlockKind::Block1, CoapBlockTransport::Datagram, 15)
            .is_valid());

        let overlong = CoapBlock::from_raw_bytes(vec![0, 0, 0, 0x10]).unwrap();
        assert_eq!(overlong.number(), 1);
        assert_eq!(overlong.raw_bytes(), &[0, 0, 0, 0x10]);
        let findings = overlong
            .validate(CoapBlockKind::Block2, CoapBlockTransport::Datagram, 0)
            .into_issues();
        assert!(findings.len() >= 2);
    }

    #[test]
    fn offset_and_constructor_overflow_are_checked() {
        let overflow = CoapBlock::from_raw_bytes(vec![0xff; 8]).unwrap();
        assert_eq!(overflow.raw_value(), u64::MAX);
        assert_eq!(overflow.number(), u64::MAX >> 4);
        assert!(matches!(
            overflow.offset(),
            Err(CrafterError::InvalidFieldValue {
                field: "coap.block.offset",
                ..
            })
        ));

        assert!(CoapBlock::new((u64::MAX >> 4) + 1, false, 0).is_err());
        assert!(CoapBlock::new(0, false, 8).is_err());
        assert!(CoapBlock::from_raw_bytes(vec![0; 9]).is_err());
    }

    #[test]
    fn block1_request_fragments_match_first_middle_and_final_wire_bytes() {
        // RFC 7959 Sections 2.3 and 3.2: non-final payloads exactly match
        // SZX, while the final payload may be shorter. Size1 describes the
        // complete request body rather than this fragment's payload.
        let first = Coap::put()
            .message_id(0x1234)
            .block1_request_fragment_with_size1(
                CoapBlock::block1(0, true, 0).unwrap(),
                (0xa0..=0xaf).collect::<Vec<_>>(),
                CoapSize1::new(37),
            );
        let middle = Coap::put().message_id(0x1235).block1_request_fragment(
            CoapBlock::block1(1, true, 0).unwrap(),
            (0xb0..=0xbf).collect::<Vec<_>>(),
        );
        let final_fragment = Coap::put().message_id(0x1236).block1_request_fragment(
            CoapBlock::block1(2, false, 0).unwrap(),
            vec![0xc0, 0xc1, 0xc2, 0xc3, 0xc4],
        );

        assert_eq!(
            Packet::from_layer(first.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x40, 0x03, 0x12, 0x34, // CON, PUT, MID
                0xd1, 0x0e, 0x08, // Block1 0/1/16
                0xd1, 0x14, 0x25, // Size1 37
                0xff, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
                0xad, 0xae, 0xaf,
            ]
        );
        assert_eq!(
            Packet::from_layer(middle.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x40, 0x03, 0x12, 0x35, // CON, PUT, MID
                0xd1, 0x0e, 0x18, // Block1 1/1/16
                0xff, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc,
                0xbd, 0xbe, 0xbf,
            ]
        );
        assert_eq!(
            Packet::from_layer(final_fragment.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x40, 0x03, 0x12, 0x36, // CON, PUT, MID
                0xd1, 0x0e, 0x20, // Block1 2/0/16
                0xff, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4,
            ]
        );

        for message in [&first, &middle, &final_fragment] {
            assert!(message
                .block1_validation(CoapBlockTransport::Datagram)
                .expect("Block1 occurrence")
                .unwrap()
                .is_valid());
        }
        assert_eq!(first.size1_value().unwrap().unwrap().value(), 37);

        let short_non_final = Coap::put()
            .block1_request_fragment(CoapBlock::block1(0, true, 0).unwrap(), vec![0; 15]);
        let report = short_non_final
            .block1_validation(CoapBlockTransport::Datagram)
            .unwrap()
            .unwrap();
        assert!(!report.is_valid());
        assert!(matches!(
            report.issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block.payload-length",
                ..
            }]
        ));
        assert!(Packet::from_layer(short_non_final).compile().is_ok());
    }

    #[test]
    fn block1_oversized_final_fragment_is_reported_without_blocking_compile() {
        // RFC 7959 Section 2 defines the final payload as the possibly short
        // remainder of the selected block size, while Section 2.3 keeps
        // semantic checks separate from the wire representation.
        let oversized_final = Coap::put().message_id(0x1237).block1_request_fragment(
            CoapBlock::block1(0, false, 0).unwrap(),
            (0xd0..=0xe0).collect::<Vec<_>>(),
        );

        let report = oversized_final
            .block1_validation(CoapBlockTransport::Datagram)
            .expect("Block1 occurrence")
            .unwrap();
        assert!(matches!(
            report.issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block.payload-length",
                reason: "final Block1 payload must not exceed the selected block size",
            }]
        ));
        assert_eq!(
            Packet::from_layer(oversized_final)
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x40, 0x03, 0x12, 0x37, // CON, PUT, MID
                0xd0, 0x0e, // final Block1 0/0/16 uses canonical empty uint
                0xff, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
                0xdd, 0xde, 0xdf, 0xe0,
            ]
        );
    }

    #[test]
    fn block1_continue_preserves_negotiated_downsize_and_unknown_details() {
        // RFC 7959 Sections 2.3, 2.5, and Figure 9: a response Block1 value
        // can acknowledge the request while selecting a smaller future SZX.
        let selected = CoapBlock::from_raw_bytes_for(CoapBlockKind::Block1, vec![0x09]).unwrap();
        let response = Coap::block1_continue(selected)
            .acknowledgement()
            .message_id(0x1234)
            .option(CoapOption::new(2048u16, vec![0xde, 0xad]));
        let expected = [
            0x60, 0x5f, 0x12, 0x34, // ACK, 2.31 Continue, MID
            0xd1, 0x0e, 0x09, // Block1 0/1/32 selected by server
            0xe2, 0x06, 0xd8, 0xde, 0xad, // unknown option 2048
        ];

        assert_eq!(
            Packet::from_layer(response.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &expected
        );
        assert!(response
            .block1_validation(CoapBlockTransport::Datagram)
            .unwrap()
            .unwrap()
            .is_valid());

        let decoded = Coap::decode(&expected).unwrap();
        let decoded_block = decoded.block1_value().unwrap().unwrap();
        assert_eq!(decoded_block.raw_bytes(), &[0x09]);
        assert_eq!(decoded_block.block_size(), 32);
        assert_eq!(decoded.options_value()[1].number().value(), 2048);
        assert_eq!(decoded.options_value()[1].value(), &[0xde, 0xad]);
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            &expected
        );
    }

    #[test]
    fn block1_error_responses_preserve_raw_control_and_size1_metadata() {
        let raw_ack = CoapBlock::from_raw_bytes_for(CoapBlockKind::Block1, vec![0, 0x10]).unwrap();
        let incomplete = Coap::block1_request_entity_incomplete(raw_ack)
            .acknowledgement()
            .message_id(0x1235);
        assert_eq!(
            Packet::from_layer(incomplete.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[0x60, 0x88, 0x12, 0x35, 0xd2, 0x0e, 0x00, 0x10]
        );
        assert_eq!(
            incomplete.block1_value().unwrap().unwrap().raw_bytes(),
            &[0x00, 0x10]
        );

        // RFC 7959 Section 2.9.3 permits both a smaller Block1 SZX hint and
        // Size1 carrying the maximum request-body size accepted by the server.
        let too_large = Coap::block1_request_entity_too_large(
            CoapBlock::block1(0, false, 1).unwrap(),
            CoapSize1::new(32),
        )
        .acknowledgement()
        .message_id(0x1236);
        assert_eq!(
            Packet::from_layer(too_large.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x60, 0x8d, 0x12, 0x36, // ACK, 4.13, MID
                0xd1, 0x0e, 0x01, // Block1 0/0/32
                0xd1, 0x14, 0x20, // Size1 maximum 32
            ]
        );
        assert_eq!(too_large.size1_value().unwrap().unwrap().value(), 32);
    }

    #[test]
    fn block2_response_fragments_match_first_middle_and_final_wire_bytes() {
        // RFC 7959 Sections 2.3, 2.4, and 4: Block2 describes response-body
        // fragments, while ETag and Size2 describe the complete body.
        let first = Coap::content()
            .acknowledgement()
            .message_id(0x2000)
            .block2_response_fragment_with_metadata(
                CoapBlock::block2(0, true, 0).unwrap(),
                (0xa0..=0xaf).collect::<Vec<_>>(),
                CoapEtag::try_new([0x6f, 0x00]).unwrap(),
                CoapSize2::new(37),
            );
        let middle = Coap::content()
            .acknowledgement()
            .message_id(0x2001)
            .block2_response_fragment(
                CoapBlock::block2(1, true, 0).unwrap(),
                (0xb0..=0xbf).collect::<Vec<_>>(),
            );
        let final_fragment = Coap::content()
            .acknowledgement()
            .message_id(0x2002)
            .block2_response_fragment(
                CoapBlock::block2(2, false, 0).unwrap(),
                vec![0xc0, 0xc1, 0xc2, 0xc3, 0xc4],
            );

        let first_bytes = [
            0x60, 0x45, 0x20, 0x00, // ACK, 2.05 Content, MID
            0x42, 0x6f, 0x00, // ETag 4, delta 4, length 2
            0xd1, 0x06, 0x08, // Block2 0/1/16
            0x51, 0x25, // Size2 37
            0xff, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
            0xad, 0xae, 0xaf,
        ];
        assert_eq!(
            Packet::from_layer(first.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &first_bytes
        );
        assert_eq!(
            Packet::from_layer(middle.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x60, 0x45, 0x20, 0x01, // ACK, 2.05 Content, MID
                0xd1, 0x0a, 0x18, // Block2 1/1/16
                0xff, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc,
                0xbd, 0xbe, 0xbf,
            ]
        );
        assert_eq!(
            Packet::from_layer(final_fragment.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x60, 0x45, 0x20, 0x02, // ACK, 2.05 Content, MID
                0xd1, 0x0a, 0x20, // Block2 2/0/16
                0xff, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4,
            ]
        );

        for message in [&first, &middle, &final_fragment] {
            assert!(message
                .block2_validation(CoapBlockTransport::Datagram, None)
                .expect("Block2 occurrence")
                .unwrap()
                .is_valid());
        }
        assert_eq!(first.block2_offset().unwrap().unwrap(), 0);
        assert_eq!(middle.block2_offset().unwrap().unwrap(), 16);
        assert_eq!(final_fragment.block2_offset().unwrap().unwrap(), 32);
        assert_eq!(
            first.etag_value().unwrap().unwrap().as_bytes(),
            &[0x6f, 0x00]
        );
        assert_eq!(first.size2_value().unwrap().unwrap().value(), 37);

        let decoded = Coap::decode(&first_bytes).unwrap();
        assert_eq!(
            decoded.block2_value().unwrap().unwrap().raw_bytes(),
            &[0x08]
        );
        assert_eq!(
            decoded.etag_value().unwrap().unwrap().as_bytes(),
            &[0x6f, 0x00]
        );
        assert_eq!(decoded.size2_value().unwrap().unwrap().value(), 37);
        assert_eq!(
            Packet::from_layer(decoded).compile().unwrap().as_bytes(),
            &first_bytes
        );
    }

    #[test]
    fn block2_size_negotiation_preserves_request_and_returned_selection() {
        // RFC 7959 Sections 2.3 and 2.4 permit a server to reduce the proposed
        // block size. Scaling NUM keeps the returned byte offset unchanged.
        let requested = CoapBlock::block2(2, false, 2).unwrap(); // offset 128, size 64
        let request = Coap::get()
            .message_id(0x3000)
            .block2_request_selection_with_size2(requested.clone());
        assert_eq!(
            Packet::from_layer(request.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x40, 0x01, 0x30, 0x00, // CON, GET, MID
                0xd1, 0x0a, 0x22, // Block2 2/0/64
                0x50, // Size2 request, canonical uint zero
            ]
        );
        assert!(request
            .block2_validation(CoapBlockTransport::Datagram, None)
            .unwrap()
            .unwrap()
            .is_valid());
        assert!(!request.validate().has_errors());
        assert_eq!(request.block2_offset().unwrap().unwrap(), 128);
        assert_eq!(request.size2_value().unwrap().unwrap().value(), 0);

        let invalid_size_request = Coap::get().size2(CoapSize2::new(1));
        assert!(invalid_size_request
            .validate()
            .issues()
            .iter()
            .any(|issue| {
                issue.field() == "coap.options[0].value"
                    && issue.reason() == "Size2 in a request must use the size-request value zero"
            }));

        let returned = CoapBlock::block2(4, true, 1).unwrap(); // offset 128, size 32
        let response = Coap::content()
            .acknowledgement()
            .message_id(0x3000)
            .block2_response_fragment_with_metadata(
                returned,
                vec![0x5a; 32],
                CoapEtag::try_new([0xde, 0xad]).unwrap(),
                CoapSize2::new(291),
            );
        let expected = [
            0x60, 0x45, 0x30, 0x00, // ACK, 2.05 Content, MID
            0x42, 0xde, 0xad, // ETag
            0xd1, 0x06, 0x49, // Block2 4/1/32
            0x52, 0x01, 0x23, // Size2 291
            0xff, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
            0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
            0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
        ];
        assert_eq!(
            Packet::from_layer(response.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &expected
        );
        assert!(response
            .block2_validation(CoapBlockTransport::Datagram, Some(&requested))
            .unwrap()
            .unwrap()
            .is_valid());
        assert_eq!(response.block2_offset().unwrap().unwrap(), 128);
    }

    #[test]
    fn block2_oversized_final_fragment_is_reported_without_blocking_compile() {
        // RFC 7959 Sections 2 and 2.3 define a final response fragment as the
        // possibly short remainder of the selected block size. Validation is
        // descriptive, so an inconsistent caller-selected payload still
        // compiles byte-for-byte.
        let oversized_final = Coap::content()
            .acknowledgement()
            .message_id(0x2003)
            .block2_response_fragment(
                CoapBlock::block2(2, false, 0).unwrap(),
                (0xd0..=0xe0).collect::<Vec<_>>(),
            );

        let report = oversized_final
            .block2_validation(CoapBlockTransport::Datagram, None)
            .expect("Block2 occurrence")
            .unwrap();
        assert!(matches!(
            report.issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block.payload-length",
                reason: "final Block2 payload must not exceed the selected block size",
            }]
        ));
        assert_eq!(
            Packet::from_layer(oversized_final)
                .compile()
                .unwrap()
                .as_bytes(),
            &[
                0x60, 0x45, 0x20, 0x03, // ACK, 2.05 Content, MID
                0xd1, 0x0a, 0x20, // final Block2 2/0/16
                0xff, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
                0xdd, 0xde, 0xdf, 0xe0,
            ]
        );
    }

    #[test]
    fn block2_validation_reports_m_size_offset_and_payload_without_blocking_compile() {
        let malformed_request =
            Coap::get().block2_request_selection(CoapBlock::block2(0, true, 0).unwrap());
        let request_report = malformed_request
            .block2_validation(CoapBlockTransport::Datagram, None)
            .unwrap()
            .unwrap();
        assert!(matches!(
            request_report.issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block2.request.more",
                reason: "Block2 request M bit must be zero",
            }]
        ));
        assert!(Packet::from_layer(malformed_request).compile().is_ok());

        let short_fragment = Coap::content()
            .block2_response_fragment(CoapBlock::block2(1, true, 0).unwrap(), vec![0; 15]);
        let short_report = short_fragment
            .block2_validation(CoapBlockTransport::Datagram, None)
            .unwrap()
            .unwrap();
        assert!(short_report.issues().iter().any(|issue| matches!(
            issue,
            CrafterError::InvalidFieldValue {
                field: "coap.block.payload-length",
                ..
            }
        )));
        assert!(Packet::from_layer(short_fragment).compile().is_ok());

        let requested = CoapBlock::block2(1, false, 0).unwrap(); // offset 16, size 16
        let incompatible = Coap::content()
            .block2_response_fragment(CoapBlock::block2(1, true, 1).unwrap(), vec![0; 32]);
        let response_report = incompatible
            .block2_validation(CoapBlockTransport::Datagram, Some(&requested))
            .unwrap()
            .unwrap();
        assert!(response_report.issues().iter().any(|issue| matches!(
            issue,
            CrafterError::InvalidFieldValue {
                field: "coap.block2.response.size",
                ..
            }
        )));
        assert!(response_report.issues().iter().any(|issue| matches!(
            issue,
            CrafterError::InvalidFieldValue {
                field: "coap.block2.response.offset",
                ..
            }
        )));
        assert!(Packet::from_layer(incompatible).compile().is_ok());
    }

    #[test]
    fn qblock_grouping_and_request_ranges_are_checked_and_stateless() {
        // RFC 9177 Sections 2 and 4.4 define MAX_PAYLOADS_SET by integer
        // division and give Q-Block2's M bit its request-range meanings.
        let selected = CoapBlock::qblock2(23, true, 2).unwrap();
        assert_eq!(selected.option_kind(), Some(CoapBlockKind::QBlock2));
        assert_eq!(selected.raw_bytes(), &[0x01, 0x7a]);
        assert_eq!(selected.qblock_set_index(10).unwrap(), 2);
        assert_eq!(selected.qblock_set_position(10).unwrap(), 3);
        assert_eq!(selected.qblock_set_start_number(10).unwrap(), 20);
        assert_eq!(selected.qblock_set_end_number(10).unwrap(), 29);
        assert_eq!(selected.qblock_next_number().unwrap(), 24);
        assert_eq!(selected.qblock2_request_range(10).unwrap(), (23, 29));
        assert!(selected.qblock2_request_covers(29, 10).unwrap());
        assert!(!selected.qblock2_request_covers(30, 10).unwrap());

        let whole_body = CoapBlock::qblock2(0, true, 0).unwrap();
        assert_eq!(
            whole_body.qblock2_request_range(10).unwrap(),
            (0, CoapBlock::MAX_NUMBER)
        );
        assert!(!whole_body.is_qblock2_continue(10).unwrap());

        let continue_set = CoapBlock::qblock2(20, true, 0).unwrap();
        assert_eq!(continue_set.qblock2_request_range(10).unwrap(), (20, 29));
        assert!(continue_set.is_qblock2_continue(10).unwrap());

        let single = CoapBlock::qblock2(23, false, 0).unwrap();
        assert_eq!(single.qblock2_request_range(10).unwrap(), (23, 23));
        assert!(single.qblock_precedes(
            &selected
                .qblock2_request_range(10)
                .and_then(|(number, _)| CoapBlock::qblock2(number + 1, false, 0))
                .unwrap()
        ));

        assert_eq!(CoapBlock::QBLOCK_DEFAULT_MAX_PAYLOADS, 10);
        assert!(selected.qblock_set_index(0).is_err());
        assert!(CoapBlock::qblock1(CoapBlock::MAX_NUMBER, false, 0)
            .unwrap()
            .qblock_next_number()
            .is_err());
    }

    #[test]
    fn qblock_validation_preserves_reserved_and_checks_payload_ranges() {
        let request = CoapBlock::qblock1(1, true, 0).unwrap();
        assert!(request
            .validate_qblock1_request(CoapBlockTransport::Datagram, 16)
            .is_valid());
        assert!(!request
            .validate_qblock1_request(CoapBlockTransport::Datagram, 15)
            .is_valid());

        let oversized_final = CoapBlock::qblock1(2, false, 0).unwrap();
        assert!(matches!(
            oversized_final
                .validate_qblock1_request(CoapBlockTransport::Datagram, 17)
                .issues(),
            [CrafterError::InvalidFieldValue {
                field: "coap.block.payload-length",
                reason: "final Q-Block1 payload must not exceed the selected block size",
            }]
        ));

        let requested = CoapBlock::qblock2(10, true, 1).unwrap();
        let returned = CoapBlock::qblock2(15, true, 1).unwrap();
        assert!(returned
            .validate_qblock2_response(CoapBlockTransport::Datagram, 32, Some(&requested), 10,)
            .is_valid());

        let outside = CoapBlock::qblock2(20, true, 1).unwrap();
        assert!(outside
            .validate_qblock2_response(CoapBlockTransport::Datagram, 32, Some(&requested), 10,)
            .issues()
            .iter()
            .any(|issue| matches!(
                issue,
                CrafterError::InvalidFieldValue {
                    field: "coap.qblock2.response.number",
                    ..
                }
            )));

        // SZX 7 and overlong uint bytes remain constructible and exact, while
        // opt-in validation reports that RFC 9177 does not assign BERT here.
        let reserved = CoapBlock::qblock1(0, false, 7).unwrap();
        assert_eq!(reserved.raw_bytes(), &[0x07]);
        assert!(!reserved
            .validate_qblock1_request(CoapBlockTransport::Reliable, 0)
            .is_valid());
        let raw =
            CoapBlock::from_raw_bytes_for(CoapBlockKind::QBlock2, vec![0, 0, 0, 0x10]).unwrap();
        assert_eq!(raw.raw_bytes(), &[0, 0, 0, 0x10]);
        assert!(!raw
            .validate_qblock2_request(CoapBlockTransport::Datagram, 10)
            .is_valid());
    }

    #[test]
    fn qblock_message_helpers_compile_decode_and_validate_required_metadata() {
        let request = Coap::put().message_id(0x4000).qblock1_request_fragment(
            CoapBlock::qblock1(0, true, 0).unwrap(),
            vec![0xa5; 16],
            CoapRequestTag::try_new([0x44]).unwrap(),
            CoapSize1::new(20),
        );
        let request_bytes = [
            0x40, 0x03, 0x40, 0x00, // CON, PUT, MID
            0xd1, 0x06, 0x08, // Q-Block1 0/1/16
            0xd1, 0x1c, 0x14, // Size1 20
            0xd1, 0xdb, 0x44, // Request-Tag
            0xff, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5,
            0xa5, 0xa5, 0xa5,
        ];
        assert_eq!(
            Packet::from_layer(request.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &request_bytes
        );
        assert!(!request.validate().has_errors());
        assert!(request
            .qblock1_validation(CoapBlockTransport::Datagram)
            .unwrap()
            .unwrap()
            .is_valid());
        let decoded_request = Coap::decode(&request_bytes).unwrap();
        assert_eq!(
            decoded_request
                .qblock1_value()
                .unwrap()
                .unwrap()
                .raw_bytes(),
            &[0x08]
        );

        let response = Coap::content()
            .acknowledgement()
            .message_id(0x4001)
            .qblock2_response_fragment(
                CoapBlock::qblock2(0, true, 0).unwrap(),
                vec![0x5a; 16],
                CoapEtag::try_new([0x99]).unwrap(),
                CoapSize2::new(20),
            );
        let response_bytes = [
            0x60, 0x45, 0x40, 0x01, // ACK, 2.05 Content, MID
            0x41, 0x99, // ETag
            0xd1, 0x0b, 0x14, // Size2 20
            0x31, 0x08, // Q-Block2 0/1/16
            0xff, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
            0x5a, 0x5a, 0x5a,
        ];
        assert_eq!(
            Packet::from_layer(response.clone())
                .compile()
                .unwrap()
                .as_bytes(),
            &response_bytes
        );
        assert!(!response.validate().has_errors());
        assert_eq!(response.qblock2_offset().unwrap().unwrap(), 0);

        let missing_metadata = Coap::put().qblock1(CoapBlock::qblock1(0, false, 0).unwrap());
        assert!(missing_metadata
            .validate()
            .issues()
            .iter()
            .any(|issue| { issue.reason() == "Q-Block1 requests require a Request-Tag option" }));
        assert!(missing_metadata
            .validate()
            .issues()
            .iter()
            .any(|issue| issue.reason() == "Q-Block1 requests require a Size1 option"));

        let out_of_order = Coap::get()
            .qblock2(CoapBlock::qblock2(3, false, 0).unwrap())
            .qblock2(CoapBlock::qblock2(2, false, 0).unwrap());
        assert!(out_of_order.validate().issues().iter().any(|issue| {
            issue.reason() == "repeated Q-Block2 request numbers must be strictly increasing"
        }));

        let mixed = Coap::get()
            .block2(CoapBlock::block2(0, false, 0).unwrap())
            .qblock2(CoapBlock::qblock2(0, false, 0).unwrap());
        assert!(mixed.validate().issues().iter().any(|issue| {
            issue.reason()
                == "Block and Q-Block options must not be mixed at the same protection level"
        }));
    }
}
