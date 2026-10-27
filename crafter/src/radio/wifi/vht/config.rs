//! Single-stream VHT20 selections, IEEE 802.11-2020 Table 21-29.
use crate::radio::{RadioError, WifiFcsPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VhtMcs {
    Mcs0,
    Mcs1,
    Mcs2,
    Mcs3,
    Mcs4,
    Mcs5,
    Mcs6,
    Mcs7,
    Mcs8,
}

impl VhtMcs {
    pub const ALL: [Self; 9] = [
        Self::Mcs0,
        Self::Mcs1,
        Self::Mcs2,
        Self::Mcs3,
        Self::Mcs4,
        Self::Mcs5,
        Self::Mcs6,
        Self::Mcs7,
        Self::Mcs8,
    ];
    pub const fn index(self) -> u8 {
        self as u8
    }
    pub const fn rate_bps(self, guard: VhtGuardInterval) -> u32 {
        (self.parameters().1 as u64 * 20_000_000 / guard.symbol_samples() as u64) as u32
    }
    pub(super) const fn parameters(self) -> (usize, usize) {
        [
            (1, 26),
            (2, 52),
            (2, 78),
            (4, 104),
            (4, 156),
            (6, 208),
            (6, 234),
            (6, 260),
            (8, 312),
        ][self as usize]
    }
}
impl TryFrom<u8> for VhtMcs {
    type Error = RadioError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::ALL
            .get(usize::from(value))
            .copied()
            .ok_or(RadioError::Invalid {
                field: "mcs",
                reason: "one-stream VHT20 requires MCS 0 through 8",
            })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VhtCoding {
    #[default]
    Bcc,
    Ldpc,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VhtGuardInterval {
    #[default]
    Long,
    Short,
}
impl VhtGuardInterval {
    pub const fn samples(self) -> usize {
        match self {
            Self::Long => 16,
            Self::Short => 8,
        }
    }
    pub const fn symbol_samples(self) -> usize {
        64 + self.samples()
    }
}

/// Offline VHT20 single-user transmit configuration. Opening hardware is separate.
#[derive(Debug, Clone, PartialEq)]
pub struct VhtTxConfig {
    pub mcs: VhtMcs,
    pub coding: VhtCoding,
    pub guard_interval: VhtGuardInterval,
    pub fcs: WifiFcsPolicy,
    pub scrambler_seed: u8,
    pub leading_samples: usize,
    pub trailing_samples: usize,
    pub scale: f64,
    pub max_psdu_bytes: usize,
    pub max_samples: usize,
    /// Post-BCC input bits, emitted verbatim, including intentionally invalid CRC/tail.
    pub signal_a_override: Option<[u8; 48]>,
    pub signal_b_override: Option<[u8; 26]>,
    pub legacy_signal_override: Option<[u8; 24]>,
}
impl VhtTxConfig {
    pub fn new(mcs: VhtMcs) -> Self {
        Self {
            mcs,
            coding: VhtCoding::Bcc,
            guard_interval: VhtGuardInterval::Long,
            fcs: WifiFcsPolicy::Auto,
            scrambler_seed: 0x5d,
            leading_samples: 64,
            trailing_samples: 64,
            scale: 300.,
            max_psdu_bytes: 65_535,
            max_samples: 10_000_000,
            signal_a_override: None,
            signal_b_override: None,
            legacy_signal_override: None,
        }
    }
    pub fn with_coding(mut self, coding: VhtCoding) -> Self {
        self.coding = coding;
        self
    }
    pub fn with_guard_interval(mut self, guard: VhtGuardInterval) -> Self {
        self.guard_interval = guard;
        self
    }
    pub fn with_fcs(mut self, fcs: WifiFcsPolicy) -> Self {
        self.fcs = fcs;
        self
    }
}
