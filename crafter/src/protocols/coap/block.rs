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

    /// Convert this value to an exact CoAP option occurrence of `kind`.
    pub fn into_option(self, kind: CoapBlockKind) -> CoapOption {
        CoapOption::new(kind.option_number(), self.wire_value)
    }

    /// Validate source-level Block, Q-Block, BERT, and payload constraints.
    ///
    /// Validation is opt-in and never changes the exact raw representation.
    /// For ordinary descriptive blocks, a non-final payload must equal the
    /// selected block size. For reliable BERT, a non-final payload must be a
    /// positive multiple of 1024 bytes; final BERT payloads may include any
    /// number of complete units plus a final partial unit.
    pub fn validate(
        &self,
        kind: CoapBlockKind,
        transport: CoapBlockTransport,
        payload_len: usize,
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
            } else if self.more()
                && (payload_len == 0 || payload_len % COAP_BLOCK_BERT_UNIT as usize != 0)
            {
                validation.push(
                    "coap.block.payload-length",
                    "non-final BERT payload must be a positive multiple of 1024 bytes",
                );
            }
        } else if self.more() && payload_len as u128 != u128::from(self.block_size()) {
            validation.push(
                "coap.block.payload-length",
                "non-final block payload must equal the selected block size",
            );
        }

        validation
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
        assert_eq!(bert.block_size(), 1024);
        assert_eq!(bert.offset().unwrap(), 3072);
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
        assert!(final_bert
            .validate(CoapBlockKind::Block2, CoapBlockTransport::Reliable, 4711)
            .is_valid());
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
}
