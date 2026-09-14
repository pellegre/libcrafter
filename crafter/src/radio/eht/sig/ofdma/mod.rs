//! 20 MHz OFDMA EHT-SIG common and user encoding blocks.

mod allocation;
mod common;
#[cfg(test)]
mod tests;

pub use allocation::{
    EhtOfdmaUserKind, EhtResourceUnit, EhtRuAllocation20, EhtRuComponent, EhtRuSize,
};
pub use common::EhtOfdmaCommon;

use super::super::{EhtMuPpduType, EhtUsigFields, EhtUsigFormat};
use super::{block::EncodingBlock, EhtMuMimoUser, EhtNonMuUser, EhtSigError};

/// One EHT-SIG user interpreted with the RU Allocation subfield's context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtOfdmaUser {
    NonMu(EhtNonMuUser),
    MuMimo(EhtMuMimoUser),
}

/// Complete integrity-checked 20 MHz OFDMA EHT-SIG content channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EhtOfdmaSignal {
    pub common: EhtOfdmaCommon,
    pub users: Vec<Result<EhtOfdmaUser, EhtSigError>>,
}

impl EhtOfdmaSignal {
    pub(in crate::radio) fn required_bits(
        first: &[u8],
        usig: &EhtUsigFields,
    ) -> Result<usize, EhtSigError> {
        context(usig)?;
        let block = EncodingBlock::new(first, 26, 0, 0)?;
        let common = EhtOfdmaCommon::decode(&block)?;
        Ok(layout_bits(common.allocation.user_count()))
    }

    /// Decode the common block followed by independently terminated pairs of
    /// User fields. Semantic MU-MIMO errors preserve transmitted positions.
    pub fn decode(bits: &[u8], usig: &EhtUsigFields) -> Result<Self, EhtSigError> {
        context(usig)?;
        if bits.len() < 36 {
            return Err(EhtSigError::BitCount {
                required: 36,
                available: bits.len(),
            });
        }
        let first = EncodingBlock::new(&bits[..36], 26, 0, 0)?;
        let common = EhtOfdmaCommon::decode(&first)?;
        let required = layout_bits(common.allocation.user_count());
        if bits.len() != required {
            return Err(EhtSigError::BitCount {
                required,
                available: bits.len(),
            });
        }
        let mut users = Vec::with_capacity(usize::from(common.allocation.user_count()));
        let mut cursor = 36;
        let mut block_index = 1;
        while users.len() < usize::from(common.allocation.user_count()) {
            let count = (usize::from(common.allocation.user_count()) - users.len()).min(2);
            let protected = 22 * count;
            let length = protected + 10;
            let block = EncodingBlock::new(
                &bits[cursor..cursor + length],
                protected,
                block_index,
                cursor,
            )?;
            for position in 0..count {
                let start = 22 * position;
                let user = match common.allocation.user_kind() {
                    EhtOfdmaUserKind::NonMu => {
                        Ok(EhtOfdmaUser::NonMu(EhtNonMuUser::decode(&block, start)))
                    }
                    EhtOfdmaUserKind::MuMimo => {
                        EhtMuMimoUser::decode(&block, start, users.len()).map(EhtOfdmaUser::MuMimo)
                    }
                };
                users.push(user);
            }
            cursor += length;
            block_index += 1;
        }
        Ok(Self { common, users })
    }
}

fn context(usig: &EhtUsigFields) -> Result<(), EhtSigError> {
    if usig.bandwidth_code != 0 {
        return Err(EhtSigError::Bandwidth(usig.bandwidth_code));
    }
    match usig.format {
        EhtUsigFormat::Mu(fields) if fields.ppdu_type == EhtMuPpduType::DownlinkOfdma => Ok(()),
        _ => Err(EhtSigError::UnsupportedFormat),
    }
}

fn layout_bits(users: u8) -> usize {
    let users = usize::from(users);
    36 + (users / 2) * 54 + (users % 2) * 32
}
