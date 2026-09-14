use super::super::{block::EncodingBlock, common::Overflow, EhtLtfMode, EhtSigError};

/// Common EHT-SIG parameters shared by non-OFDMA users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtNonOfdmaCommon {
    pub spatial_reuse: u8,
    pub ltf_mode: EhtLtfMode,
    pub ltf_symbols: u8,
    pub ldpc_extra_symbol: bool,
    pub pre_fec_padding_factor: u8,
    pub pe_disambiguity: bool,
    pub disregard: u8,
    pub users: u8,
}

impl EhtNonOfdmaCommon {
    pub(super) fn decode(block: &EncodingBlock<'_>) -> Result<Self, EhtSigError> {
        let fields = Overflow::decode(block)?;
        Ok(Self {
            spatial_reuse: fields.spatial_reuse,
            ltf_mode: fields.ltf_mode,
            ltf_symbols: fields.ltf_symbols,
            ldpc_extra_symbol: fields.ldpc_extra_symbol,
            pre_fec_padding_factor: fields.pre_fec_padding_factor,
            pe_disambiguity: fields.pe_disambiguity,
            disregard: fields.disregard,
            users: block.field(17, 3) as u8 + 1,
        })
    }
}
