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
    Bandwidth(u8),
    RuAllocation(u16),
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
