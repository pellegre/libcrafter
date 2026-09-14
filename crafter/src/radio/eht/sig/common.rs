use super::{block::EncodingBlock, EhtSigError};

/// EHT-LTF size and guard-interval combination advertised by EHT-SIG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtLtfMode {
    TwoXGi800,
    TwoXGi1600,
    FourXGi800,
    FourXGi3200,
}

impl EhtLtfMode {
    pub const fn size(self) -> u8 {
        match self {
            Self::TwoXGi800 | Self::TwoXGi1600 => 2,
            Self::FourXGi800 | Self::FourXGi3200 => 4,
        }
    }

    pub const fn guard_interval_ns(self) -> u16 {
        match self {
            Self::TwoXGi800 | Self::FourXGi800 => 800,
            Self::TwoXGi1600 => 1600,
            Self::FourXGi3200 => 3200,
        }
    }
}

pub(super) struct Overflow {
    pub spatial_reuse: u8,
    pub ltf_mode: EhtLtfMode,
    pub ltf_symbols: u8,
    pub ldpc_extra_symbol: bool,
    pub pre_fec_padding_factor: u8,
    pub pe_disambiguity: bool,
    pub disregard: u8,
}

impl Overflow {
    pub(super) fn decode(block: &EncodingBlock<'_>) -> Result<Self, EhtSigError> {
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
            ldpc_extra_symbol: block.bit(9),
            pre_fec_padding_factor: if padding == 0 { 4 } else { padding },
            pe_disambiguity: block.bit(12),
            disregard: block.field(13, 4) as u8,
        })
    }
}
