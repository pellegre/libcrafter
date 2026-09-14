//! HE-specific mappings into shared 20 MHz resource-unit geometry.

use super::Tones;

impl Tones {
    /// Normal Trigger User Info RU byte, Table 9-29i. MU-RTS uses a different
    /// encoding and must be excluded by the caller. No RA range is expanded.
    pub fn from_he_trigger(bandwidth: u8, allocation: u8) -> Option<Self> {
        if bandwidth != 0 || allocation & 1 != 0 {
            return None;
        }
        let code = allocation >> 1;
        let (size, index) = match code {
            0..=8 => (26, usize::from(code) + 1),
            37..=40 => (52, usize::from(code) - 36),
            53..=54 => (106, usize::from(code) - 52),
            61 => (242, 1),
            _ => return None,
        };
        Self::ru(size, index)
    }

    /// Table 27-26 columns to Table 27-7 equal-size RU ordinals. User counts
    /// do not change geometry, including explicitly empty allocations.
    pub fn from_he_assignment(ru: &crate::radio::he::mu::sig_b::HeRu20Assignment) -> Option<Self> {
        let index = match (ru.tones, ru.first_slot) {
            (26, slot @ 1..=9) => usize::from(slot),
            (52, 1) | (106, 1) | (242, 1) => 1,
            (52, 3) | (106, 6) => 2,
            (52, 6) => 3,
            (52, 8) => 4,
            _ => return None,
        };
        Self::ru(ru.tones, index)
    }

    /// Bandwidth bits have allocation meaning only in independently verified ER.
    pub fn for_he_su(er: bool, bandwidth: u8) -> Option<Self> {
        if bandwidth > u8::from(er) {
            return None;
        }
        Self::ru(
            if er && bandwidth == 1 { 106 } else { 242 },
            if er && bandwidth == 1 { 2 } else { 1 },
        )
    }
}
