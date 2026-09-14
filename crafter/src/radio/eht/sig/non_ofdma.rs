//! First EHT-SIG encoding block for a non-OFDMA single-user PPDU.

use super::super::{EhtMuPpduType, EhtUsigFields, EhtUsigFormat};

/// EHT-LTF size and guard-interval combination advertised by EHT-SIG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtLtfMode {
    /// Two-times EHT-LTF with an 800 ns guard interval.
    TwoXGi800,
    /// Two-times EHT-LTF with a 1600 ns guard interval.
    TwoXGi1600,
    /// Four-times EHT-LTF with an 800 ns guard interval.
    FourXGi800,
    /// Four-times EHT-LTF with a 3200 ns guard interval.
    FourXGi3200,
}

impl EhtLtfMode {
    /// EHT-LTF duration multiplier.
    pub const fn size(self) -> u8 {
        match self {
            Self::TwoXGi800 | Self::TwoXGi1600 => 2,
            Self::FourXGi800 | Self::FourXGi3200 => 4,
        }
    }

    /// Guard interval in nanoseconds.
    pub const fn guard_interval_ns(self) -> u16 {
        match self {
            Self::TwoXGi800 | Self::FourXGi800 => 800,
            Self::TwoXGi1600 => 1600,
            Self::FourXGi3200 => 3200,
        }
    }
}

/// Non-MU-MIMO EHT-SIG user parameters. Unsupported DATA modes remain visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtNonMuUser {
    /// Station identifier carried by the user field.
    pub sta_id: u16,
    /// Raw EHT MCS value; DATA admission validates supported combinations.
    pub mcs: u8,
    /// Preserved reserved/disregard bit.
    pub reserved: bool,
    /// Number of space-time streams.
    pub space_time_streams: u8,
    /// Whether beamforming is signaled.
    pub beamformed: bool,
    /// `true` for LDPC and `false` for BCC.
    pub ldpc: bool,
}

/// Integrity-checked first EHT-SIG block for a non-OFDMA single-user PPDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtNonOfdmaSignal {
    /// Spatial-reuse field.
    pub spatial_reuse: u8,
    /// EHT-LTF duration and guard-interval mode.
    pub ltf_mode: EhtLtfMode,
    /// Number of EHT-LTF symbols.
    pub ltf_symbols: u8,
    /// Whether an LDPC extra symbol segment is present.
    pub ldpc_extra_symbol: bool,
    /// Pre-FEC padding factor, represented as one through four.
    pub pre_fec_padding_factor: u8,
    /// Packet-extension disambiguity flag.
    pub pe_disambiguity: bool,
    /// Bits transmitted as one but ignored by receivers.
    pub disregard: u8,
    /// Number of users represented by this non-OFDMA encoding context.
    pub users: u8,
    /// First non-MU user field carried in the encoding block.
    pub first_user: EhtNonMuUser,
}

/// Failure while interpreting an EHT-SIG encoding block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtSigError {
    BitCount { required: usize, available: usize },
    NonBinary { index: usize, value: u8 },
    UnsupportedFormat,
    UserCount(u8),
    LtfSymbols(u8),
    Crc { expected: u8, received: u8 },
    TailBit { index: usize },
}

impl std::fmt::Display for EhtSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EHT-SIG: {self:?}")
    }
}

impl std::error::Error for EhtSigError {}

struct EncodingBlock<'a> {
    bits: &'a [u8],
}

impl<'a> EncodingBlock<'a> {
    fn new(bits: &'a [u8]) -> Result<Self, EhtSigError> {
        if bits.len() != 52 {
            return Err(EhtSigError::BitCount {
                required: 52,
                available: bits.len(),
            });
        }
        if let Some((index, &value)) = bits.iter().enumerate().find(|(_, value)| **value > 1) {
            return Err(EhtSigError::NonBinary { index, value });
        }
        let expected = crate::radio::ht::crc(&bits[..42]) >> 4;
        let received = bits[42..46]
            .iter()
            .fold(0u8, |value, bit| (value << 1) | bit);
        if expected != received {
            return Err(EhtSigError::Crc { expected, received });
        }
        if let Some(index) = (46..52).find(|index| bits[*index] != 0) {
            return Err(EhtSigError::TailBit { index });
        }
        Ok(Self { bits })
    }

    fn field(&self, start: usize, count: usize) -> u16 {
        self.bits[start..start + count]
            .iter()
            .enumerate()
            .fold(0u16, |value, (index, bit)| {
                value | (u16::from(*bit) << index)
            })
    }

    fn user(&self) -> EhtNonMuUser {
        EhtNonMuUser {
            sta_id: self.field(20, 11),
            mcs: self.field(31, 4) as u8,
            reserved: self.bits[35] != 0,
            space_time_streams: self.field(36, 4) as u8 + 1,
            beamformed: self.bits[40] != 0,
            ldpc: self.bits[41] != 0,
        }
    }
}

impl EhtNonOfdmaSignal {
    /// Decode the 52-bit common-plus-first-user encoding block. U-SIG must
    /// already identify a non-OFDMA single-user PPDU.
    pub fn decode(bits: &[u8], usig: &EhtUsigFields) -> Result<Self, EhtSigError> {
        if !matches!(
            usig.format,
            EhtUsigFormat::Mu(fields) if fields.ppdu_type == EhtMuPpduType::SingleUser
        ) {
            return Err(EhtSigError::UnsupportedFormat);
        }
        let block = EncodingBlock::new(bits)?;
        let users = block.field(17, 3) as u8 + 1;
        if users != 1 {
            return Err(EhtSigError::UserCount(users));
        }
        let ltf_symbols = match block.field(6, 3) as u8 {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 6,
            4 => 8,
            value => return Err(EhtSigError::LtfSymbols(value)),
        };
        let ltf_mode = match block.field(4, 2) {
            0 => EhtLtfMode::TwoXGi800,
            1 => EhtLtfMode::TwoXGi1600,
            2 => EhtLtfMode::FourXGi800,
            3 => EhtLtfMode::FourXGi3200,
            _ => unreachable!(),
        };
        let padding = block.field(10, 2) as u8;
        Ok(Self {
            spatial_reuse: block.field(0, 4) as u8,
            ltf_mode,
            ltf_symbols,
            ldpc_extra_symbol: block.bits[9] != 0,
            pre_fec_padding_factor: if padding == 0 { 4 } else { padding },
            pe_disambiguity: block.bits[12] != 0,
            disregard: block.field(13, 4) as u8,
            users,
            first_user: block.user(),
        })
    }
}
