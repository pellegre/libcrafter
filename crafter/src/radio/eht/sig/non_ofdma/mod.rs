//! Non-OFDMA EHT-SIG common and user encoding blocks.

mod block;
mod common;
#[cfg(test)]
mod tests;
mod user;

pub use common::{EhtLtfMode, EhtNonOfdmaCommon};
pub use user::{EhtMuMimoUser, EhtNonMuUser};

use self::block::EncodingBlock;
use super::super::{EhtMuPpduType, EhtUsigFields, EhtUsigFormat};

/// Users carried by a complete non-OFDMA EHT-SIG content channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EhtNonOfdmaUsers {
    Single(EhtNonMuUser),
    MuMimo(Vec<Result<EhtMuMimoUser, EhtSigError>>),
}

impl EhtNonOfdmaUsers {
    pub fn len(&self) -> usize {
        match self {
            Self::Single(_) => 1,
            Self::MuMimo(users) => users.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Single(_) => false,
            Self::MuMimo(users) => users.is_empty(),
        }
    }
}

/// Complete integrity-checked non-OFDMA EHT-SIG content channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EhtNonOfdmaSignal {
    pub common: EhtNonOfdmaCommon,
    pub users: EhtNonOfdmaUsers,
}

/// Failure while interpreting one or more EHT-SIG encoding blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtSigError {
    BitCount {
        required: usize,
        available: usize,
    },
    NonBinary {
        index: usize,
        value: u8,
    },
    UnsupportedFormat,
    UserCount(u8),
    LtfSymbols(u8),
    MuMimoStaId {
        user: usize,
    },
    MuMimoMcs {
        user: usize,
        value: u8,
    },
    Crc {
        block: usize,
        expected: u8,
        received: u8,
    },
    TailBit {
        block: usize,
        index: usize,
    },
}

impl std::fmt::Display for EhtSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EHT-SIG: {self:?}")
    }
}

impl std::error::Error for EhtSigError {}

impl EhtNonOfdmaSignal {
    pub(in crate::radio) fn required_bits(
        first: &[u8],
        usig: &EhtUsigFields,
    ) -> Result<usize, EhtSigError> {
        let (ppdu_type, _, common) = header(first, usig)?;
        layout_bits(ppdu_type, common.users)
    }

    /// Decode independently terminated EHT-SIG encoding blocks concatenated
    /// in content-channel order, including each block's CRC and tail bits.
    pub fn decode(bits: &[u8], usig: &EhtUsigFields) -> Result<Self, EhtSigError> {
        if ppdu_type(usig)? == EhtMuPpduType::SingleUser {
            require_length(bits, 52)?;
        }
        if bits.len() < 52 {
            return Err(EhtSigError::BitCount {
                required: 52,
                available: bits.len(),
            });
        }
        let (ppdu_type, first, common) = header(&bits[..52], usig)?;
        require_length(bits, layout_bits(ppdu_type, common.users)?)?;
        let users = match ppdu_type {
            EhtMuPpduType::SingleUser => EhtNonOfdmaUsers::Single(EhtNonMuUser::decode(&first, 20)),
            EhtMuPpduType::DownlinkMuMimo => {
                let mut decoded = Vec::with_capacity(usize::from(common.users));
                decoded.push(EhtMuMimoUser::decode(&first, 20, 0));
                let mut cursor = 52;
                let mut block_index = 1;
                while decoded.len() < usize::from(common.users) {
                    let count = (usize::from(common.users) - decoded.len()).min(2);
                    let protected = 22 * count;
                    let length = protected + 10;
                    let block = EncodingBlock::new(
                        &bits[cursor..cursor + length],
                        protected,
                        block_index,
                        cursor,
                    )?;
                    for position in 0..count {
                        decoded.push(EhtMuMimoUser::decode(&block, 22 * position, decoded.len()));
                    }
                    cursor += length;
                    block_index += 1;
                }
                EhtNonOfdmaUsers::MuMimo(decoded)
            }
            EhtMuPpduType::DownlinkOfdma => unreachable!(),
        };
        Ok(Self { common, users })
    }
}

fn header<'a>(
    first: &'a [u8],
    usig: &EhtUsigFields,
) -> Result<(EhtMuPpduType, EncodingBlock<'a>, EhtNonOfdmaCommon), EhtSigError> {
    let ppdu_type = ppdu_type(usig)?;
    let block = EncodingBlock::new(first, 42, 0, 0)?;
    let common = EhtNonOfdmaCommon::decode(&block)?;
    match ppdu_type {
        EhtMuPpduType::SingleUser if common.users != 1 => {
            return Err(EhtSigError::UserCount(common.users))
        }
        EhtMuPpduType::DownlinkMuMimo if common.users < 2 => {
            return Err(EhtSigError::UserCount(common.users))
        }
        _ => {}
    }
    Ok((ppdu_type, block, common))
}

fn ppdu_type(usig: &EhtUsigFields) -> Result<EhtMuPpduType, EhtSigError> {
    let ppdu_type = match usig.format {
        EhtUsigFormat::Mu(fields) => fields.ppdu_type,
        EhtUsigFormat::TriggerBased(_) => return Err(EhtSigError::UnsupportedFormat),
    };
    if !matches!(
        ppdu_type,
        EhtMuPpduType::SingleUser | EhtMuPpduType::DownlinkMuMimo
    ) {
        return Err(EhtSigError::UnsupportedFormat);
    }
    Ok(ppdu_type)
}

fn layout_bits(ppdu_type: EhtMuPpduType, users: u8) -> Result<usize, EhtSigError> {
    match ppdu_type {
        EhtMuPpduType::SingleUser if users == 1 => Ok(52),
        EhtMuPpduType::DownlinkMuMimo if users >= 2 => {
            let remaining = usize::from(users - 1);
            Ok(52 + (remaining / 2) * 54 + (remaining % 2) * 32)
        }
        _ => Err(EhtSigError::UserCount(users)),
    }
}

fn require_length(bits: &[u8], required: usize) -> Result<(), EhtSigError> {
    if bits.len() != required {
        return Err(EhtSigError::BitCount {
            required,
            available: bits.len(),
        });
    }
    Ok(())
}
