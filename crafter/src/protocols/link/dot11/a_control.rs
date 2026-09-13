//! IEEE 802.11ax HE A-Control fields.

const HE_VARIANT_MASK: u32 = 0b11;
const HE_VARIANT: u32 = 0b11;
const CONTROL_ID_SHIFT: u8 = 2;
const CONTROL_ID_MASK: u32 = 0x0f << CONTROL_ID_SHIFT;
const TRS_CONTROL_ID: u32 = 0;
const CONTROL_INFORMATION_SHIFT: u8 = 6;
const TRS_INFORMATION_MASK: u32 = (1 << 26) - 1;

/// Triggered response scheduling information carried by an HE A-Control field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Dot11TrsControl {
    information: u32,
}

impl Dot11TrsControl {
    /// Construct an empty TRS Control information value.
    pub const fn new() -> Self {
        Self { information: 0 }
    }

    /// Preserve the low 26 bits of a TRS Control Information subfield.
    pub const fn from_information_bits(information: u32) -> Self {
        Self {
            information: information & TRS_INFORMATION_MASK,
        }
    }

    /// Decode a complete HE-variant HT Control value when its first A-Control
    /// entry is the 30-bit TRS Control entry.
    pub const fn from_ht_control(ht_control: u32) -> Option<Self> {
        if ht_control & HE_VARIANT_MASK != HE_VARIANT
            || (ht_control & CONTROL_ID_MASK) >> CONTROL_ID_SHIFT != TRS_CONTROL_ID
        {
            return None;
        }
        Some(Self::from_information_bits(
            ht_control >> CONTROL_INFORMATION_SHIFT,
        ))
    }

    /// Raw 26-bit Control Information value.
    pub const fn information_bits(self) -> u32 {
        self.information
    }

    /// Complete four-octet HE-variant HT Control value.
    pub const fn ht_control(self) -> u32 {
        HE_VARIANT | (TRS_CONTROL_ID << CONTROL_ID_SHIFT) | (self.information << 6)
    }

    /// Number of HE TB DATA symbols minus one, as encoded on the wire.
    pub const fn ul_data_symbols_raw(self) -> u8 {
        (self.information & 0x1f) as u8
    }

    /// Number of HE TB DATA symbols requested by this control field.
    pub const fn ul_data_symbols(self) -> u8 {
        self.ul_data_symbols_raw() + 1
    }

    /// Trigger User Info RU Allocation encoding.
    pub const fn ru_allocation(self) -> u8 {
        ((self.information >> 5) & 0xff) as u8
    }

    /// Raw five-bit AP transmit-power encoding.
    pub const fn ap_tx_power(self) -> u8 {
        ((self.information >> 13) & 0x1f) as u8
    }

    /// Raw five-bit target receive-power encoding.
    pub const fn target_receive_power(self) -> u8 {
        ((self.information >> 18) & 0x1f) as u8
    }

    /// Requested HE MCS, in the TRS-defined range zero through three.
    pub const fn mcs(self) -> u8 {
        ((self.information >> 23) & 0x03) as u8
    }

    /// Reserved wire bit. Parsing preserves it; scheduling rejects it.
    pub const fn reserved(self) -> bool {
        self.information & (1 << 25) != 0
    }

    /// Set the raw five-bit UL Data Symbols value.
    pub const fn with_ul_data_symbols_raw(self, value: u8) -> Self {
        self.with_subfield(0x1f, 0, value as u32)
    }

    /// Set the RU Allocation subfield.
    pub const fn with_ru_allocation(self, value: u8) -> Self {
        self.with_subfield(0xff << 5, 5, value as u32)
    }

    /// Set the raw AP Tx Power subfield.
    pub const fn with_ap_tx_power(self, value: u8) -> Self {
        self.with_subfield(0x1f << 13, 13, value as u32)
    }

    /// Set the raw UL Target Receive Power subfield.
    pub const fn with_target_receive_power(self, value: u8) -> Self {
        self.with_subfield(0x1f << 18, 18, value as u32)
    }

    /// Set the two-bit UL HE-MCS subfield.
    pub const fn with_mcs(self, value: u8) -> Self {
        self.with_subfield(0x03 << 23, 23, value as u32)
    }

    /// Set or clear the reserved wire bit.
    pub const fn with_reserved(self, value: bool) -> Self {
        self.with_subfield(1 << 25, 25, value as u32)
    }

    const fn with_subfield(mut self, mask: u32, shift: u8, value: u32) -> Self {
        self.information = (self.information & !mask) | ((value << shift) & mask);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trs_control_maps_every_information_bit() {
        for bit in 0..26 {
            let information = 1 << bit;
            let control = Dot11TrsControl::from_information_bits(information);
            assert_eq!(control.information_bits(), information);
            assert_eq!(control.ht_control(), 3 | (information << 6));
            assert_eq!(
                Dot11TrsControl::from_ht_control(control.ht_control()),
                Some(control)
            );
        }
        assert_eq!(
            Dot11TrsControl::from_information_bits(u32::MAX).information_bits(),
            TRS_INFORMATION_MASK
        );
    }

    #[test]
    fn trs_control_exposes_typed_fields_and_builders() {
        let control = Dot11TrsControl::new()
            .with_ul_data_symbols_raw(31)
            .with_ru_allocation(122)
            .with_ap_tx_power(30)
            .with_target_receive_power(31)
            .with_mcs(3)
            .with_reserved(true);
        assert_eq!(control.ul_data_symbols_raw(), 31);
        assert_eq!(control.ul_data_symbols(), 32);
        assert_eq!(control.ru_allocation(), 122);
        assert_eq!(control.ap_tx_power(), 30);
        assert_eq!(control.target_receive_power(), 31);
        assert_eq!(control.mcs(), 3);
        assert!(control.reserved());
    }

    #[test]
    fn trs_control_requires_he_variant_and_control_id_zero() {
        let value = Dot11TrsControl::new().with_mcs(3).ht_control();
        for variant in 0..3 {
            assert_eq!(
                Dot11TrsControl::from_ht_control((value & !3) | variant),
                None
            );
        }
        for control_id in 1..=15 {
            assert_eq!(
                Dot11TrsControl::from_ht_control(value | (control_id << CONTROL_ID_SHIFT)),
                None
            );
        }
    }
}
