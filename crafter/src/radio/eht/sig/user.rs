use super::{block::EncodingBlock, EhtSigError};

/// User parameters for a non-MU-MIMO allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtNonMuUser {
    pub sta_id: u16,
    pub mcs: u8,
    pub reserved: bool,
    pub space_time_streams: u8,
    pub beamformed: bool,
    pub ldpc: bool,
}

impl EhtNonMuUser {
    pub(super) fn decode(block: &EncodingBlock<'_>, start: usize) -> Self {
        Self {
            sta_id: block.field(start, 11),
            mcs: block.field(start + 11, 4) as u8,
            reserved: block.bit(start + 15),
            space_time_streams: block.field(start + 16, 4) as u8 + 1,
            beamformed: block.bit(start + 20),
            ldpc: block.bit(start + 21),
        }
    }
}

/// User parameters for a MU-MIMO allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtMuMimoUser {
    pub sta_id: u16,
    pub mcs: u8,
    pub ldpc: bool,
    /// Raw Table 36-42 index. Stream separation is receiver-context dependent.
    pub spatial_configuration: u8,
}

impl EhtMuMimoUser {
    pub(super) fn decode(
        block: &EncodingBlock<'_>,
        start: usize,
        user: usize,
    ) -> Result<Self, EhtSigError> {
        let sta_id = block.field(start, 11);
        if sta_id == 2046 {
            return Err(EhtSigError::MuMimoStaId { user });
        }
        let mcs = block.field(start + 11, 4) as u8;
        if mcs > 13 {
            return Err(EhtSigError::MuMimoMcs { user, value: mcs });
        }
        Ok(Self {
            sta_id,
            mcs,
            ldpc: block.bit(start + 15),
            spatial_configuration: block.field(start + 16, 6) as u8,
        })
    }
}
