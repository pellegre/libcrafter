//! Radiotap link metadata scaffolding.
//!
//! Field IDs and layout metadata follow the radiotap source entries recorded in
//! `docs/protocols/dot11-source-manifest.md`.

/// Present bit: TSFT.
pub const RADIOTAP_FIELD_TSFT: u8 = 0;
/// Present bit: Flags.
pub const RADIOTAP_FIELD_FLAGS: u8 = 1;
/// Present bit: Rate.
pub const RADIOTAP_FIELD_RATE: u8 = 2;
/// Present bit: Channel.
pub const RADIOTAP_FIELD_CHANNEL: u8 = 3;
/// Present bit: FHSS.
pub const RADIOTAP_FIELD_FHSS: u8 = 4;
/// Present bit: Antenna signal.
pub const RADIOTAP_FIELD_ANTENNA_SIGNAL: u8 = 5;
/// Present bit: Antenna noise.
pub const RADIOTAP_FIELD_ANTENNA_NOISE: u8 = 6;
/// Present bit: Lock quality.
pub const RADIOTAP_FIELD_LOCK_QUALITY: u8 = 7;
/// Present bit: TX attenuation.
pub const RADIOTAP_FIELD_TX_ATTENUATION: u8 = 8;
/// Present bit: dB TX attenuation.
pub const RADIOTAP_FIELD_DB_TX_ATTENUATION: u8 = 9;
/// Present bit: dBm TX power.
pub const RADIOTAP_FIELD_DBM_TX_POWER: u8 = 10;
/// Present bit: Antenna.
pub const RADIOTAP_FIELD_ANTENNA: u8 = 11;
/// Present bit: RX flags.
pub const RADIOTAP_FIELD_RX_FLAGS: u8 = 14;
/// Present bit: TX flags.
pub const RADIOTAP_FIELD_TX_FLAGS: u8 = 15;
/// Present bit: RTS retries.
///
/// This suggested/unofficial radiotap field is selected for Linux/NetBSD
/// compatibility and conflicts with an RSSI assignment in the radiotap notes.
pub const RADIOTAP_FIELD_RTS_RETRIES: u8 = 16;
/// Present bit: data retries.
pub const RADIOTAP_FIELD_DATA_RETRIES: u8 = 17;
/// Present bit: MCS.
pub const RADIOTAP_FIELD_MCS: u8 = 19;
/// Present bit: A-MPDU status.
pub const RADIOTAP_FIELD_A_MPDU_STATUS: u8 = 20;
/// Present bit: VHT.
pub const RADIOTAP_FIELD_VHT: u8 = 21;
/// Present bit 31 indicates another present bitmap word, not a data field.
pub const RADIOTAP_PRESENT_EXTENDED: u32 = 0x8000_0000;

/// Present mask: TSFT.
pub const RADIOTAP_PRESENT_TSFT: u32 = present_mask(RADIOTAP_FIELD_TSFT);
/// Present mask: Flags.
pub const RADIOTAP_PRESENT_FLAGS: u32 = present_mask(RADIOTAP_FIELD_FLAGS);
/// Present mask: Rate.
pub const RADIOTAP_PRESENT_RATE: u32 = present_mask(RADIOTAP_FIELD_RATE);
/// Present mask: Channel.
pub const RADIOTAP_PRESENT_CHANNEL: u32 = present_mask(RADIOTAP_FIELD_CHANNEL);
/// Present mask: FHSS.
pub const RADIOTAP_PRESENT_FHSS: u32 = present_mask(RADIOTAP_FIELD_FHSS);
/// Present mask: Antenna signal.
pub const RADIOTAP_PRESENT_ANTENNA_SIGNAL: u32 = present_mask(RADIOTAP_FIELD_ANTENNA_SIGNAL);
/// Present mask: Antenna noise.
pub const RADIOTAP_PRESENT_ANTENNA_NOISE: u32 = present_mask(RADIOTAP_FIELD_ANTENNA_NOISE);
/// Present mask: Lock quality.
pub const RADIOTAP_PRESENT_LOCK_QUALITY: u32 = present_mask(RADIOTAP_FIELD_LOCK_QUALITY);
/// Present mask: TX attenuation.
pub const RADIOTAP_PRESENT_TX_ATTENUATION: u32 = present_mask(RADIOTAP_FIELD_TX_ATTENUATION);
/// Present mask: dB TX attenuation.
pub const RADIOTAP_PRESENT_DB_TX_ATTENUATION: u32 = present_mask(RADIOTAP_FIELD_DB_TX_ATTENUATION);
/// Present mask: dBm TX power.
pub const RADIOTAP_PRESENT_DBM_TX_POWER: u32 = present_mask(RADIOTAP_FIELD_DBM_TX_POWER);
/// Present mask: Antenna.
pub const RADIOTAP_PRESENT_ANTENNA: u32 = present_mask(RADIOTAP_FIELD_ANTENNA);
/// Present mask: RX flags.
pub const RADIOTAP_PRESENT_RX_FLAGS: u32 = present_mask(RADIOTAP_FIELD_RX_FLAGS);
/// Present mask: TX flags.
pub const RADIOTAP_PRESENT_TX_FLAGS: u32 = present_mask(RADIOTAP_FIELD_TX_FLAGS);
/// Present mask: RTS retries.
pub const RADIOTAP_PRESENT_RTS_RETRIES: u32 = present_mask(RADIOTAP_FIELD_RTS_RETRIES);
/// Present mask: data retries.
pub const RADIOTAP_PRESENT_DATA_RETRIES: u32 = present_mask(RADIOTAP_FIELD_DATA_RETRIES);
/// Present mask: MCS.
pub const RADIOTAP_PRESENT_MCS: u32 = present_mask(RADIOTAP_FIELD_MCS);
/// Present mask: A-MPDU status.
pub const RADIOTAP_PRESENT_A_MPDU_STATUS: u32 = present_mask(RADIOTAP_FIELD_A_MPDU_STATUS);
/// Present mask: VHT.
pub const RADIOTAP_PRESENT_VHT: u32 = present_mask(RADIOTAP_FIELD_VHT);

const fn present_mask(bit: u8) -> u32 {
    1u32 << (bit as u32)
}

/// Fixed layout metadata for one selected radiotap field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RadiotapFieldMetadata {
    bit: u8,
    present_mask: u32,
    alignment: usize,
    size: usize,
}

impl RadiotapFieldMetadata {
    const fn new(bit: u8, alignment: usize, size: usize) -> Self {
        Self {
            bit,
            present_mask: present_mask(bit),
            alignment,
            size,
        }
    }

    /// Present bit number for this field.
    pub const fn bit(&self) -> u8 {
        self.bit
    }

    /// Mask for this field within a 32-bit radiotap present word.
    pub const fn present_mask(&self) -> u32 {
        self.present_mask
    }

    /// Required field alignment relative to the start of the radiotap header.
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Fixed field size in octets.
    pub const fn size(&self) -> usize {
        self.size
    }
}

/// Selected phase 1.5 radiotap fields with fixed size and alignment metadata.
pub const RADIOTAP_SELECTED_FIELD_METADATA: [RadiotapFieldMetadata; 19] = [
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_TSFT, 8, 8),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_FLAGS, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_RATE, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_CHANNEL, 2, 4),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_FHSS, 1, 2),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_ANTENNA_SIGNAL, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_ANTENNA_NOISE, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_LOCK_QUALITY, 2, 2),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_TX_ATTENUATION, 2, 2),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_DB_TX_ATTENUATION, 2, 2),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_DBM_TX_POWER, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_ANTENNA, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_RX_FLAGS, 2, 2),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_TX_FLAGS, 2, 2),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_RTS_RETRIES, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_DATA_RETRIES, 1, 1),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_MCS, 1, 3),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_A_MPDU_STATUS, 4, 8),
    RadiotapFieldMetadata::new(RADIOTAP_FIELD_VHT, 2, 12),
];

/// Return fixed layout metadata for a selected radiotap field bit.
pub fn radiotap_field_metadata(bit: u16) -> Option<RadiotapFieldMetadata> {
    RADIOTAP_SELECTED_FIELD_METADATA
        .iter()
        .copied()
        .find(|metadata| metadata.bit as u16 == bit)
}

/// Placeholder for radiotap metadata preceding IEEE 802.11 frames.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Radiotap {
    _private: (),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radiotap_constants_selected_present_bits_have_source_backed_masks() {
        let cases = [
            (RADIOTAP_FIELD_TSFT, RADIOTAP_PRESENT_TSFT),
            (RADIOTAP_FIELD_FLAGS, RADIOTAP_PRESENT_FLAGS),
            (RADIOTAP_FIELD_RATE, RADIOTAP_PRESENT_RATE),
            (RADIOTAP_FIELD_CHANNEL, RADIOTAP_PRESENT_CHANNEL),
            (RADIOTAP_FIELD_FHSS, RADIOTAP_PRESENT_FHSS),
            (
                RADIOTAP_FIELD_ANTENNA_SIGNAL,
                RADIOTAP_PRESENT_ANTENNA_SIGNAL,
            ),
            (RADIOTAP_FIELD_ANTENNA_NOISE, RADIOTAP_PRESENT_ANTENNA_NOISE),
            (RADIOTAP_FIELD_LOCK_QUALITY, RADIOTAP_PRESENT_LOCK_QUALITY),
            (
                RADIOTAP_FIELD_TX_ATTENUATION,
                RADIOTAP_PRESENT_TX_ATTENUATION,
            ),
            (
                RADIOTAP_FIELD_DB_TX_ATTENUATION,
                RADIOTAP_PRESENT_DB_TX_ATTENUATION,
            ),
            (RADIOTAP_FIELD_DBM_TX_POWER, RADIOTAP_PRESENT_DBM_TX_POWER),
            (RADIOTAP_FIELD_ANTENNA, RADIOTAP_PRESENT_ANTENNA),
            (RADIOTAP_FIELD_RX_FLAGS, RADIOTAP_PRESENT_RX_FLAGS),
            (RADIOTAP_FIELD_TX_FLAGS, RADIOTAP_PRESENT_TX_FLAGS),
            (RADIOTAP_FIELD_RTS_RETRIES, RADIOTAP_PRESENT_RTS_RETRIES),
            (RADIOTAP_FIELD_DATA_RETRIES, RADIOTAP_PRESENT_DATA_RETRIES),
            (RADIOTAP_FIELD_MCS, RADIOTAP_PRESENT_MCS),
            (RADIOTAP_FIELD_A_MPDU_STATUS, RADIOTAP_PRESENT_A_MPDU_STATUS),
            (RADIOTAP_FIELD_VHT, RADIOTAP_PRESENT_VHT),
        ];

        for (bit, mask) in cases {
            assert_eq!(mask, 1u32 << bit);
        }

        assert_eq!(RADIOTAP_FIELD_TSFT, 0);
        assert_eq!(RADIOTAP_FIELD_TX_FLAGS, 15);
        assert_eq!(RADIOTAP_FIELD_RTS_RETRIES, 16);
        assert_eq!(RADIOTAP_FIELD_DATA_RETRIES, 17);
        assert_eq!(RADIOTAP_FIELD_MCS, 19);
        assert_eq!(RADIOTAP_FIELD_A_MPDU_STATUS, 20);
        assert_eq!(RADIOTAP_FIELD_VHT, 21);
        assert_eq!(RADIOTAP_PRESENT_EXTENDED, 0x8000_0000);
    }

    #[test]
    fn radiotap_constants_metadata_lookup_reports_alignment_and_size() {
        let cases = [
            (RADIOTAP_FIELD_TSFT, RADIOTAP_PRESENT_TSFT, 8, 8),
            (RADIOTAP_FIELD_FLAGS, RADIOTAP_PRESENT_FLAGS, 1, 1),
            (RADIOTAP_FIELD_RATE, RADIOTAP_PRESENT_RATE, 1, 1),
            (RADIOTAP_FIELD_CHANNEL, RADIOTAP_PRESENT_CHANNEL, 2, 4),
            (RADIOTAP_FIELD_FHSS, RADIOTAP_PRESENT_FHSS, 1, 2),
            (
                RADIOTAP_FIELD_ANTENNA_SIGNAL,
                RADIOTAP_PRESENT_ANTENNA_SIGNAL,
                1,
                1,
            ),
            (
                RADIOTAP_FIELD_ANTENNA_NOISE,
                RADIOTAP_PRESENT_ANTENNA_NOISE,
                1,
                1,
            ),
            (
                RADIOTAP_FIELD_LOCK_QUALITY,
                RADIOTAP_PRESENT_LOCK_QUALITY,
                2,
                2,
            ),
            (
                RADIOTAP_FIELD_TX_ATTENUATION,
                RADIOTAP_PRESENT_TX_ATTENUATION,
                2,
                2,
            ),
            (
                RADIOTAP_FIELD_DB_TX_ATTENUATION,
                RADIOTAP_PRESENT_DB_TX_ATTENUATION,
                2,
                2,
            ),
            (
                RADIOTAP_FIELD_DBM_TX_POWER,
                RADIOTAP_PRESENT_DBM_TX_POWER,
                1,
                1,
            ),
            (RADIOTAP_FIELD_ANTENNA, RADIOTAP_PRESENT_ANTENNA, 1, 1),
            (RADIOTAP_FIELD_RX_FLAGS, RADIOTAP_PRESENT_RX_FLAGS, 2, 2),
            (RADIOTAP_FIELD_TX_FLAGS, RADIOTAP_PRESENT_TX_FLAGS, 2, 2),
            (
                RADIOTAP_FIELD_RTS_RETRIES,
                RADIOTAP_PRESENT_RTS_RETRIES,
                1,
                1,
            ),
            (
                RADIOTAP_FIELD_DATA_RETRIES,
                RADIOTAP_PRESENT_DATA_RETRIES,
                1,
                1,
            ),
            (RADIOTAP_FIELD_MCS, RADIOTAP_PRESENT_MCS, 1, 3),
            (
                RADIOTAP_FIELD_A_MPDU_STATUS,
                RADIOTAP_PRESENT_A_MPDU_STATUS,
                4,
                8,
            ),
            (RADIOTAP_FIELD_VHT, RADIOTAP_PRESENT_VHT, 2, 12),
        ];

        assert_eq!(RADIOTAP_SELECTED_FIELD_METADATA.len(), cases.len());

        for (bit, mask, alignment, size) in cases {
            let metadata = radiotap_field_metadata(bit.into()).unwrap();
            assert_eq!(metadata.bit(), bit);
            assert_eq!(metadata.present_mask(), mask);
            assert_eq!(metadata.alignment(), alignment);
            assert_eq!(metadata.size(), size);
        }
    }

    #[test]
    fn radiotap_constants_metadata_lookup_treats_unselected_bits_as_unknown() {
        for bit in [12, 13, 18, 22, 29, 30, 31, 32, 63] {
            assert_eq!(radiotap_field_metadata(bit), None);
        }
    }
}
