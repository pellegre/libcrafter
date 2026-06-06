//! Radiotap link metadata scaffolding.
//!
//! Field IDs and layout metadata follow the radiotap source entries recorded in
//! `docs/protocols/dot11-source-manifest.md`.

use crate::error::{CrafterError, Result};

const RADIOTAP_PRESENT_WORD_LEN: usize = 4;
const RADIOTAP_PRESENT_EXTENSION_BIT: u16 = 31;

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

/// Radiotap present bitmap words.
///
/// Each word is encoded little-endian. Bit 31 in each word is the extension
/// flag and is normalized from the number of words rather than treated as a
/// data-field bit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadiotapPresent {
    words: Vec<u32>,
}

impl RadiotapPresent {
    /// Create an empty present bitmap with the required first word.
    pub fn new() -> Self {
        Self { words: vec![0] }
    }

    /// Build a present bitmap from already grouped words.
    pub fn from_words(words: impl Into<Vec<u32>>) -> Self {
        let mut present = Self {
            words: words.into(),
        };
        present.normalize_extension_bits();
        present
    }

    /// Decode one or more little-endian radiotap present words.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        let mut offset = 0;
        let mut words = Vec::new();

        loop {
            let required = offset + RADIOTAP_PRESENT_WORD_LEN;
            if bytes.len() < required {
                return Err(CrafterError::buffer_too_short(
                    "radiotap.present",
                    required,
                    bytes.len(),
                ));
            }

            let word = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            let has_extension = word & RADIOTAP_PRESENT_EXTENDED != 0;
            words.push(word);
            offset = required;

            if !has_extension {
                break;
            }
        }

        Ok((Self::from_words(words), offset))
    }

    /// Build a deterministic present bitmap from typed and raw field bits.
    pub fn from_field_bits<Typed, Raw>(typed_bits: Typed, raw_bits: Raw) -> Result<Self>
    where
        Typed: IntoIterator<Item = u16>,
        Raw: IntoIterator<Item = u16>,
    {
        let mut present = Self::new();

        for bit in typed_bits {
            present.insert_field_bit(bit)?;
        }
        for bit in raw_bits {
            present.insert_field_bit(bit)?;
        }

        Ok(present)
    }

    /// Mark one radiotap data-field bit as present.
    pub fn insert_field_bit(&mut self, bit: u16) -> Result<()> {
        validate_radiotap_field_bit(bit)?;
        let word_index = usize::from(bit / 32);
        let bit_index = u32::from(bit % 32);

        if self.words.len() <= word_index {
            self.words.resize(word_index + 1, 0);
        }

        self.words[word_index] |= 1u32 << bit_index;
        self.normalize_extension_bits();
        Ok(())
    }

    /// Return true when the given radiotap data-field bit is marked present.
    pub fn is_field_present(&self, bit: u16) -> bool {
        if is_extension_field_bit(bit) {
            return false;
        }

        let word_index = usize::from(bit / 32);
        let bit_index = u32::from(bit % 32);
        self.words
            .get(word_index)
            .map(|word| word & (1u32 << bit_index) != 0)
            .unwrap_or(false)
    }

    /// Present bitmap words with normalized extension bits.
    pub fn words(&self) -> &[u32] {
        &self.words
    }

    /// Number of bytes used by the encoded bitmap words.
    pub fn encoded_len(&self) -> usize {
        self.words.len() * RADIOTAP_PRESENT_WORD_LEN
    }

    /// Encode the bitmap words as little-endian radiotap present words.
    pub fn encode(&self, out: &mut Vec<u8>) {
        for word in &self.words {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }

    /// Encode the bitmap words into a new byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode(&mut bytes);
        bytes
    }

    fn normalize_extension_bits(&mut self) {
        if self.words.is_empty() {
            self.words.push(0);
        }

        let last_index = self.words.len() - 1;
        for (index, word) in self.words.iter_mut().enumerate() {
            *word &= !RADIOTAP_PRESENT_EXTENDED;
            if index != last_index {
                *word |= RADIOTAP_PRESENT_EXTENDED;
            }
        }
    }
}

impl Default for RadiotapPresent {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_radiotap_field_bit(bit: u16) -> Result<()> {
    if is_extension_field_bit(bit) {
        return Err(CrafterError::invalid_field_value(
            "radiotap.present.bit",
            "bit 31 of each present word is the extension flag",
        ));
    }

    Ok(())
}

fn is_extension_field_bit(bit: u16) -> bool {
    bit % 32 == RADIOTAP_PRESENT_EXTENSION_BIT
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
    fn radiotap_present_bitmap_decodes_single_word_and_reencodes_little_endian() {
        let word = RADIOTAP_PRESENT_FLAGS | RADIOTAP_PRESENT_RATE;
        let mut bytes = word.to_le_bytes().to_vec();
        bytes.extend_from_slice(b"tail");

        let (present, consumed) = RadiotapPresent::decode(&bytes).unwrap();

        assert_eq!(consumed, 4);
        assert_eq!(present.words(), &[word]);
        assert!(present.is_field_present(RADIOTAP_FIELD_FLAGS.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_RATE.into()));
        assert!(!present.is_field_present(RADIOTAP_FIELD_TSFT.into()));
        assert_eq!(present.encoded_len(), 4);
        assert_eq!(present.to_bytes(), word.to_le_bytes().to_vec());
    }

    #[test]
    fn radiotap_present_bitmap_decodes_extended_words_until_terminator() {
        let first = RADIOTAP_PRESENT_EXTENDED | RADIOTAP_PRESENT_FLAGS;
        let second = 0x0000_0005_u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&first.to_le_bytes());
        bytes.extend_from_slice(&second.to_le_bytes());
        bytes.extend_from_slice(b"payload");

        let (present, consumed) = RadiotapPresent::decode(&bytes).unwrap();

        assert_eq!(consumed, 8);
        assert_eq!(present.words(), &[first, second]);
        assert!(present.is_field_present(RADIOTAP_FIELD_FLAGS.into()));
        assert!(present.is_field_present(32));
        assert!(present.is_field_present(34));
        assert!(!present.is_field_present(31));
        assert!(!present.is_field_present(63));
        assert_eq!(
            present.to_bytes(),
            [first.to_le_bytes(), second.to_le_bytes()].concat()
        );
    }

    #[test]
    fn radiotap_present_bitmap_encodes_deterministically_from_typed_and_raw_bits() {
        let present = RadiotapPresent::from_field_bits(
            [u16::from(RADIOTAP_FIELD_RATE), 34],
            [32, u16::from(RADIOTAP_FIELD_FLAGS)],
        )
        .unwrap();
        let same_present = RadiotapPresent::from_field_bits(
            [32, u16::from(RADIOTAP_FIELD_FLAGS)],
            [u16::from(RADIOTAP_FIELD_RATE), 34],
        )
        .unwrap();

        assert_eq!(
            present.words(),
            &[
                RADIOTAP_PRESENT_EXTENDED | RADIOTAP_PRESENT_FLAGS | RADIOTAP_PRESENT_RATE,
                0x5
            ]
        );
        assert_eq!(present, same_present);
        assert_eq!(
            present.to_bytes(),
            [
                (RADIOTAP_PRESENT_EXTENDED | RADIOTAP_PRESENT_FLAGS | RADIOTAP_PRESENT_RATE)
                    .to_le_bytes(),
                0x5_u32.to_le_bytes(),
            ]
            .concat()
        );

        let err = RadiotapPresent::from_field_bits([31], []).unwrap_err();
        assert_eq!(
            err,
            CrafterError::invalid_field_value(
                "radiotap.present.bit",
                "bit 31 of each present word is the extension flag",
            )
        );
    }

    #[test]
    fn radiotap_present_bitmap_truncated_extension_word_is_structured_error() {
        let first = RADIOTAP_PRESENT_EXTENDED | RADIOTAP_PRESENT_FLAGS;
        let mut bytes = first.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0xaa, 0xbb]);

        let err = RadiotapPresent::decode(&bytes).unwrap_err();

        assert_eq!(
            err,
            CrafterError::buffer_too_short("radiotap.present", 8, 6)
        );
    }

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
