//! VHT20 SU duration and LDPC information sizing, IEEE 802.11-2020 21.3.10/20.
use super::{VhtGuardInterval, VhtMcs};
use crate::radio::wifi::ht::ldpc::{rate::Layout, Rate};

pub(super) fn code_rate(mcs: VhtMcs) -> Rate {
    use Rate::*;
    [
        Half,
        Half,
        ThreeQuarters,
        Half,
        ThreeQuarters,
        TwoThirds,
        ThreeQuarters,
        FiveSixths,
        ThreeQuarters,
    ][mcs.index() as usize]
}

pub(super) fn ldpc_encode(apep: usize, mcs: VhtMcs) -> Layout {
    let (bits, data) = mcs.parameters();
    let initial = (8 * apep + 16).div_ceil(data);
    Layout::from_payload(initial * data, 52 * bits, code_rate(mcs), 1)
}

pub(super) fn ldpc_receive(symbols: usize, mcs: VhtMcs, extra: bool) -> Option<Layout> {
    if symbols == 0 || symbols > 1512 {
        return None;
    }
    let initial = symbols
        .checked_sub(usize::from(extra))
        .filter(|n| *n != 0)?;
    let (bits, data) = mcs.parameters();
    let layout = Layout::from_payload(initial * data, 52 * bits, code_rate(mcs), 1);
    (layout.symbols == symbols && layout.extra_symbol_group == extra).then_some(layout)
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Timing {
    pub symbols: usize,
    pub data_offset: usize,
    pub end_offset: usize,
}
impl Timing {
    /// Offsets are relative to L-SIG, after the 320-sample legacy training.
    pub fn receive(length: usize, guard: VhtGuardInterval, disambiguation: bool) -> Option<Self> {
        if length > 4095 || length % 3 != 0 {
            return None;
        }
        let units = (length / 3).checked_sub(4)?;
        let symbols = if guard == VhtGuardInterval::Short {
            let n = (10 * units / 9).checked_sub(usize::from(disambiguation))?;
            if (n % 10 == 9) != disambiguation || (9 * n).div_ceil(10) != units {
                return None;
            }
            n
        } else {
            if disambiguation {
                return None;
            }
            units
        };
        if symbols == 0 {
            return None;
        }
        Some(Self {
            symbols,
            data_offset: 480,
            end_offset: 480 + symbols * guard.symbol_samples(),
        })
    }
    pub fn legacy_length(symbols: usize, guard: VhtGuardInterval) -> Option<usize> {
        let units = (symbols * guard.symbol_samples()).div_ceil(80);
        let length = 3 * (units + 4);
        (length <= 4095).then_some(length)
    }
}
