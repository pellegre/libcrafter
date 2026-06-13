//! Radiotap link metadata scaffolding.
//!
//! Field IDs and layout metadata follow the radiotap source entries recorded in
//! `docs/protocols/dot11-source-manifest.md`.

use core::any::Any;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use crate::registry::ProtocolRegistry;

use super::decode_dot11_with_registry;

pub(crate) const RADIOTAP_FIXED_HEADER_LEN: usize = 4;
pub(crate) const RADIOTAP_MIN_HEADER_LEN: usize = 8;
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

/// Radiotap Flags bit: frame includes an FCS trailer.
pub const RADIOTAP_FLAGS_FCS_PRESENT: u8 = 0x10;
/// Radiotap Flags bit: frame failed the FCS check.
pub const RADIOTAP_FLAGS_FAILED_FCS: u8 = 0x40;
/// Alias for [`RADIOTAP_FLAGS_FAILED_FCS`].
pub const RADIOTAP_FLAGS_BAD_FCS: u8 = RADIOTAP_FLAGS_FAILED_FCS;
/// Radiotap RX flags bit reserved by current radiotap docs.
///
/// This bit was previously used for FCS-failed metadata. Current radiotap
/// records FCS failure through [`RADIOTAP_FLAGS_FAILED_FCS`] instead.
pub const RADIOTAP_RX_FLAGS_RESERVED_WAS_FCS_FAILED: u16 = 0x0001;
/// Radiotap RX flags bit: PLCP CRC check failed.
pub const RADIOTAP_RX_FLAGS_PLCP_CRC_FAILED: u16 = 0x0002;

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

/// Calculate field padding from the start of the radiotap header.
pub const fn radiotap_field_padding(offset_from_header_start: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        0
    } else {
        let remainder = offset_from_header_start % alignment;
        if remainder == 0 {
            0
        } else {
            alignment - remainder
        }
    }
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

    /// Present data-field bits in radiotap field order.
    pub fn field_bits(&self) -> impl Iterator<Item = u16> + '_ {
        self.words
            .iter()
            .enumerate()
            .flat_map(|(word_index, word)| {
                (0u16..32).filter_map(move |bit_index| {
                    if bit_index == RADIOTAP_PRESENT_EXTENSION_BIT {
                        return None;
                    }

                    let mask = 1u32 << u32::from(bit_index);
                    if word & mask == 0 {
                        return None;
                    }

                    let base_bit = word_index
                        .checked_mul(32)
                        .and_then(|bit| u16::try_from(bit).ok())?;
                    Some(base_bit + bit_index)
                })
            })
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

/// Raw radiotap Flags field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RadiotapFlags {
    bits: u8,
}

impl RadiotapFlags {
    /// Build radiotap Flags from the raw field byte.
    pub const fn from_bits(bits: u8) -> Self {
        Self { bits }
    }

    /// Raw radiotap Flags bits.
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// Return true when the flags indicate an FCS trailer is present.
    pub const fn fcs_present(&self) -> bool {
        self.bits & RADIOTAP_FLAGS_FCS_PRESENT != 0
    }

    /// Return true when the flags indicate the frame failed the FCS check.
    pub const fn failed_fcs(&self) -> bool {
        self.bits & RADIOTAP_FLAGS_FAILED_FCS != 0
    }

    /// FCS-related metadata carried by this Flags field.
    pub const fn fcs_status(&self) -> RadiotapFcsStatus {
        RadiotapFcsStatus::new(self.fcs_present(), self.failed_fcs())
    }
}

impl From<u8> for RadiotapFlags {
    fn from(bits: u8) -> Self {
        Self::from_bits(bits)
    }
}

/// FCS metadata from radiotap Flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RadiotapFcsStatus {
    present: bool,
    failed: bool,
}

impl RadiotapFcsStatus {
    /// Build FCS metadata from presence and failure markers.
    pub const fn new(present: bool, failed: bool) -> Self {
        Self { present, failed }
    }

    /// Return true when radiotap says an FCS trailer is present.
    pub const fn present(&self) -> bool {
        self.present
    }

    /// Return true when radiotap says the frame failed the FCS check.
    pub const fn failed(&self) -> bool {
        self.failed
    }
}

/// Raw radiotap Channel field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RadiotapChannel {
    frequency: u16,
    flags: u16,
}

impl RadiotapChannel {
    /// Build a Channel field from frequency and channel flags.
    pub const fn new(frequency: u16, flags: u16) -> Self {
        Self { frequency, flags }
    }

    /// Channel frequency in MHz.
    pub const fn frequency(&self) -> u16 {
        self.frequency
    }

    /// Raw channel flags.
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Encode the Channel field as little-endian radiotap bytes.
    pub const fn to_bytes(self) -> [u8; 4] {
        let frequency = self.frequency.to_le_bytes();
        let flags = self.flags.to_le_bytes();
        [frequency[0], frequency[1], flags[0], flags[1]]
    }
}

impl From<(u16, u16)> for RadiotapChannel {
    fn from((frequency, flags): (u16, u16)) -> Self {
        Self::new(frequency, flags)
    }
}

/// Raw radiotap RX flags field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RadiotapRxFlags {
    bits: u16,
}

impl RadiotapRxFlags {
    /// Build RX flags from the raw field bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Raw RX flags bits.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Return true when the reserved bit formerly used for FCS-failed metadata is set.
    pub const fn reserved_fcs_failed_bit(&self) -> bool {
        self.bits & RADIOTAP_RX_FLAGS_RESERVED_WAS_FCS_FAILED != 0
    }

    /// Return true when radiotap says the PLCP CRC check failed.
    pub const fn plcp_crc_failed(&self) -> bool {
        self.bits & RADIOTAP_RX_FLAGS_PLCP_CRC_FAILED != 0
    }
}

impl From<u16> for RadiotapRxFlags {
    fn from(bits: u16) -> Self {
        Self::from_bits(bits)
    }
}

/// Raw radiotap TX flags field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RadiotapTxFlags {
    bits: u16,
}

impl RadiotapTxFlags {
    /// Build TX flags from the raw field bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Raw TX flags bits.
    pub const fn bits(&self) -> u16 {
        self.bits
    }
}

impl From<u16> for RadiotapTxFlags {
    fn from(bits: u16) -> Self {
        Self::from_bits(bits)
    }
}

/// Raw bytes for a radiotap present bit libcrafter does not type yet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RadiotapUnknownField {
    present_bit: u16,
    alignment: usize,
    raw_bytes: Vec<u8>,
}

impl RadiotapUnknownField {
    /// Build an unknown field while preserving the present bit, alignment, and bytes.
    pub fn new(present_bit: u16, alignment: usize, raw_bytes: impl Into<Vec<u8>>) -> Result<Self> {
        validate_radiotap_field_bit(present_bit)?;
        if alignment == 0 {
            return Err(CrafterError::invalid_field_value(
                "radiotap.field.alignment",
                "alignment must be at least one octet",
            ));
        }

        Ok(Self {
            present_bit,
            alignment,
            raw_bytes: raw_bytes.into(),
        })
    }

    /// Present bit that identified this unknown field.
    pub const fn present_bit(&self) -> u16 {
        self.present_bit
    }

    /// Alignment used for this field relative to the radiotap header start.
    pub const fn alignment(&self) -> usize {
        self.alignment
    }

    /// Raw field body bytes, excluding alignment padding.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }

    /// Raw field body length in bytes.
    pub fn size(&self) -> usize {
        self.raw_bytes.len()
    }
}

/// Stored radiotap field value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RadiotapField {
    /// TSFT timestamp.
    Tsft(u64),
    /// Flags field.
    Flags(RadiotapFlags),
    /// Rate field in 500 kbit/s units.
    Rate(u8),
    /// Channel field.
    Channel(RadiotapChannel),
    /// FHSS field bytes.
    Fhss([u8; 2]),
    /// Antenna signal in dBm.
    AntennaSignal(i8),
    /// Antenna noise in dBm.
    AntennaNoise(i8),
    /// Lock quality.
    LockQuality(u16),
    /// TX attenuation.
    TxAttenuation(u16),
    /// dB TX attenuation.
    DbTxAttenuation(u16),
    /// dBm TX power.
    DbmTxPower(i8),
    /// Antenna index.
    Antenna(u8),
    /// RX flags field.
    RxFlags(RadiotapRxFlags),
    /// TX flags field.
    TxFlags(RadiotapTxFlags),
    /// RTS retry count.
    RtsRetries(u8),
    /// Data retry count.
    DataRetries(u8),
    /// MCS field bytes.
    Mcs([u8; 3]),
    /// A-MPDU status field bytes.
    AMpduStatus([u8; 8]),
    /// VHT field bytes.
    Vht([u8; 12]),
    /// Unknown field preserved from, or prepared for, a radiotap header.
    Unknown(RadiotapUnknownField),
}

impl RadiotapField {
    /// Build an unknown radiotap field from raw metadata.
    pub fn unknown(
        present_bit: u16,
        alignment: usize,
        raw_bytes: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self::Unknown(RadiotapUnknownField::new(
            present_bit,
            alignment,
            raw_bytes,
        )?))
    }

    /// Present bit represented by this field.
    pub const fn present_bit(&self) -> u16 {
        match self {
            Self::Tsft(_) => RADIOTAP_FIELD_TSFT as u16,
            Self::Flags(_) => RADIOTAP_FIELD_FLAGS as u16,
            Self::Rate(_) => RADIOTAP_FIELD_RATE as u16,
            Self::Channel(_) => RADIOTAP_FIELD_CHANNEL as u16,
            Self::Fhss(_) => RADIOTAP_FIELD_FHSS as u16,
            Self::AntennaSignal(_) => RADIOTAP_FIELD_ANTENNA_SIGNAL as u16,
            Self::AntennaNoise(_) => RADIOTAP_FIELD_ANTENNA_NOISE as u16,
            Self::LockQuality(_) => RADIOTAP_FIELD_LOCK_QUALITY as u16,
            Self::TxAttenuation(_) => RADIOTAP_FIELD_TX_ATTENUATION as u16,
            Self::DbTxAttenuation(_) => RADIOTAP_FIELD_DB_TX_ATTENUATION as u16,
            Self::DbmTxPower(_) => RADIOTAP_FIELD_DBM_TX_POWER as u16,
            Self::Antenna(_) => RADIOTAP_FIELD_ANTENNA as u16,
            Self::RxFlags(_) => RADIOTAP_FIELD_RX_FLAGS as u16,
            Self::TxFlags(_) => RADIOTAP_FIELD_TX_FLAGS as u16,
            Self::RtsRetries(_) => RADIOTAP_FIELD_RTS_RETRIES as u16,
            Self::DataRetries(_) => RADIOTAP_FIELD_DATA_RETRIES as u16,
            Self::Mcs(_) => RADIOTAP_FIELD_MCS as u16,
            Self::AMpduStatus(_) => RADIOTAP_FIELD_A_MPDU_STATUS as u16,
            Self::Vht(_) => RADIOTAP_FIELD_VHT as u16,
            Self::Unknown(field) => field.present_bit(),
        }
    }

    /// Required field alignment relative to the radiotap header start.
    pub fn alignment(&self) -> usize {
        match self {
            Self::Unknown(field) => field.alignment(),
            _ => radiotap_field_metadata(self.present_bit())
                .map(|metadata| metadata.alignment())
                .unwrap_or(1),
        }
    }

    /// Field body size in bytes, excluding alignment padding.
    pub fn size(&self) -> usize {
        match self {
            Self::Unknown(field) => field.size(),
            _ => radiotap_field_metadata(self.present_bit())
                .map(|metadata| metadata.size())
                .unwrap_or(0),
        }
    }

    /// Return true for raw fields whose bit is not typed by libcrafter.
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown(_))
    }

    /// Unknown-field metadata, when this field is raw/unknown.
    pub const fn unknown_field(&self) -> Option<&RadiotapUnknownField> {
        match self {
            Self::Unknown(field) => Some(field),
            _ => None,
        }
    }

    pub(crate) fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::Tsft(value) => out.extend_from_slice(&value.to_le_bytes()),
            Self::Flags(value) => out.push(value.bits()),
            Self::Rate(value) => out.push(*value),
            Self::Channel(value) => out.extend_from_slice(&value.to_bytes()),
            Self::Fhss(value) => out.extend_from_slice(value),
            Self::AntennaSignal(value) => out.push(*value as u8),
            Self::AntennaNoise(value) => out.push(*value as u8),
            Self::LockQuality(value) => out.extend_from_slice(&value.to_le_bytes()),
            Self::TxAttenuation(value) => out.extend_from_slice(&value.to_le_bytes()),
            Self::DbTxAttenuation(value) => out.extend_from_slice(&value.to_le_bytes()),
            Self::DbmTxPower(value) => out.push(*value as u8),
            Self::Antenna(value) => out.push(*value),
            Self::RxFlags(value) => out.extend_from_slice(&value.bits().to_le_bytes()),
            Self::TxFlags(value) => out.extend_from_slice(&value.bits().to_le_bytes()),
            Self::RtsRetries(value) => out.push(*value),
            Self::DataRetries(value) => out.push(*value),
            Self::Mcs(value) => out.extend_from_slice(value),
            Self::AMpduStatus(value) => out.extend_from_slice(value),
            Self::Vht(value) => out.extend_from_slice(value),
            Self::Unknown(field) => out.extend_from_slice(field.raw_bytes()),
        }
    }
}

/// Radiotap metadata preceding IEEE 802.11 frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Radiotap {
    version: Field<u8>,
    pad: Field<u8>,
    length: Field<u16>,
    present: Field<RadiotapPresent>,
    fields: Vec<RadiotapField>,
    raw_fields: Vec<u8>,
}

impl Radiotap {
    /// Create an empty radiotap metadata layer.
    ///
    /// Radiotap fields are absent until the caller sets them or decode records
    /// them from wire bytes.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(0),
            pad: Field::defaulted(0),
            length: Field::unset(),
            present: Field::unset(),
            fields: Vec::new(),
            raw_fields: Vec::new(),
        }
    }

    /// Set the radiotap version byte.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Current radiotap version byte, when known.
    pub fn version_value(&self) -> Option<u8> {
        self.version.value().copied()
    }

    /// Set the radiotap pad byte.
    pub fn pad(mut self, pad: u8) -> Self {
        self.pad.set_user(pad);
        self
    }

    /// Current radiotap pad byte, when known.
    pub fn pad_value(&self) -> Option<u8> {
        self.pad.value().copied()
    }

    /// Declared radiotap header length from decode, when present.
    ///
    /// Constructed radiotap layers compile this value from the encoded present
    /// words, selected field bodies, and preserved raw field bytes.
    pub fn length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// Stored radiotap fields in insertion order.
    pub fn fields(&self) -> &[RadiotapField] {
        &self.fields
    }

    /// Stored typed radiotap fields.
    pub fn typed_fields(&self) -> impl Iterator<Item = &RadiotapField> {
        self.fields.iter().filter(|field| !field.is_unknown())
    }

    /// Stored raw unknown radiotap fields.
    pub fn unknown_fields(&self) -> impl Iterator<Item = &RadiotapUnknownField> {
        self.fields.iter().filter_map(RadiotapField::unknown_field)
    }

    /// Raw radiotap field bytes preserved after the last typed field.
    ///
    /// These bytes are recorded during decode when an untyped present bit makes
    /// the remaining implicit field lengths unknowable, or when the declared
    /// radiotap header contains trailing metadata this phase does not type.
    pub fn raw_fields(&self) -> &[u8] {
        &self.raw_fields
    }

    /// Return a stored field by present bit.
    pub fn field(&self, present_bit: u16) -> Option<&RadiotapField> {
        self.fields
            .iter()
            .find(|field| field.present_bit() == present_bit)
    }

    /// Store or replace a radiotap field.
    pub fn with_field(mut self, field: RadiotapField) -> Self {
        self.set_field(field);
        self
    }

    /// Store or replace an unknown radiotap field.
    pub fn unknown_field(
        self,
        present_bit: u16,
        alignment: usize,
        raw_bytes: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Ok(self.with_field(RadiotapField::unknown(present_bit, alignment, raw_bytes)?))
    }

    /// Present bitmap implied by stored typed and unknown fields.
    pub fn present(&self) -> Result<RadiotapPresent> {
        if let Some(present) = self.present.value() {
            Ok(present.clone())
        } else {
            self.inferred_present()
        }
    }

    /// Present bits for typed fields.
    pub fn typed_field_bits(&self) -> impl Iterator<Item = u16> + '_ {
        self.typed_fields().map(RadiotapField::present_bit)
    }

    /// Present bits for raw unknown fields.
    pub fn unknown_field_bits(&self) -> impl Iterator<Item = u16> + '_ {
        self.unknown_fields().map(RadiotapUnknownField::present_bit)
    }

    /// Set the TSFT field.
    pub fn tsft(mut self, tsft: u64) -> Self {
        self.set_field(RadiotapField::Tsft(tsft));
        self
    }

    /// Current TSFT field, if present.
    pub fn tsft_value(&self) -> Option<u64> {
        match self.field(RADIOTAP_FIELD_TSFT.into()) {
            Some(RadiotapField::Tsft(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the Flags field.
    pub fn flags(mut self, flags: impl Into<RadiotapFlags>) -> Self {
        self.set_field(RadiotapField::Flags(flags.into()));
        self
    }

    /// Current Flags field, if present.
    pub fn flags_value(&self) -> Option<RadiotapFlags> {
        match self.field(RADIOTAP_FIELD_FLAGS.into()) {
            Some(RadiotapField::Flags(value)) => Some(*value),
            _ => None,
        }
    }

    /// Current FCS metadata, if the Flags field is present.
    pub fn fcs_status(&self) -> Option<RadiotapFcsStatus> {
        self.flags_value().map(|flags| flags.fcs_status())
    }

    /// Set the Rate field in 500 kbit/s units.
    pub fn rate(mut self, rate: u8) -> Self {
        self.set_field(RadiotapField::Rate(rate));
        self
    }

    /// Current Rate field in 500 kbit/s units, if present.
    pub fn rate_value(&self) -> Option<u8> {
        match self.field(RADIOTAP_FIELD_RATE.into()) {
            Some(RadiotapField::Rate(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the Channel field.
    pub fn channel(mut self, channel: impl Into<RadiotapChannel>) -> Self {
        self.set_field(RadiotapField::Channel(channel.into()));
        self
    }

    /// Current Channel field, if present.
    pub fn channel_value(&self) -> Option<RadiotapChannel> {
        match self.field(RADIOTAP_FIELD_CHANNEL.into()) {
            Some(RadiotapField::Channel(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the FHSS field bytes.
    pub fn fhss(mut self, fhss: [u8; 2]) -> Self {
        self.set_field(RadiotapField::Fhss(fhss));
        self
    }

    /// Current FHSS field bytes, if present.
    pub fn fhss_value(&self) -> Option<[u8; 2]> {
        match self.field(RADIOTAP_FIELD_FHSS.into()) {
            Some(RadiotapField::Fhss(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the Antenna signal field in dBm.
    pub fn antenna_signal(mut self, antenna_signal: i8) -> Self {
        self.set_field(RadiotapField::AntennaSignal(antenna_signal));
        self
    }

    /// Current Antenna signal field in dBm, if present.
    pub fn antenna_signal_value(&self) -> Option<i8> {
        match self.field(RADIOTAP_FIELD_ANTENNA_SIGNAL.into()) {
            Some(RadiotapField::AntennaSignal(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the Antenna noise field in dBm.
    pub fn antenna_noise(mut self, antenna_noise: i8) -> Self {
        self.set_field(RadiotapField::AntennaNoise(antenna_noise));
        self
    }

    /// Current Antenna noise field in dBm, if present.
    pub fn antenna_noise_value(&self) -> Option<i8> {
        match self.field(RADIOTAP_FIELD_ANTENNA_NOISE.into()) {
            Some(RadiotapField::AntennaNoise(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the Lock quality field.
    pub fn lock_quality(mut self, lock_quality: u16) -> Self {
        self.set_field(RadiotapField::LockQuality(lock_quality));
        self
    }

    /// Current Lock quality field, if present.
    pub fn lock_quality_value(&self) -> Option<u16> {
        match self.field(RADIOTAP_FIELD_LOCK_QUALITY.into()) {
            Some(RadiotapField::LockQuality(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the TX attenuation field.
    pub fn tx_attenuation(mut self, tx_attenuation: u16) -> Self {
        self.set_field(RadiotapField::TxAttenuation(tx_attenuation));
        self
    }

    /// Current TX attenuation field, if present.
    pub fn tx_attenuation_value(&self) -> Option<u16> {
        match self.field(RADIOTAP_FIELD_TX_ATTENUATION.into()) {
            Some(RadiotapField::TxAttenuation(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the dB TX attenuation field.
    pub fn db_tx_attenuation(mut self, db_tx_attenuation: u16) -> Self {
        self.set_field(RadiotapField::DbTxAttenuation(db_tx_attenuation));
        self
    }

    /// Current dB TX attenuation field, if present.
    pub fn db_tx_attenuation_value(&self) -> Option<u16> {
        match self.field(RADIOTAP_FIELD_DB_TX_ATTENUATION.into()) {
            Some(RadiotapField::DbTxAttenuation(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the dBm TX power field.
    pub fn dbm_tx_power(mut self, dbm_tx_power: i8) -> Self {
        self.set_field(RadiotapField::DbmTxPower(dbm_tx_power));
        self
    }

    /// Current dBm TX power field, if present.
    pub fn dbm_tx_power_value(&self) -> Option<i8> {
        match self.field(RADIOTAP_FIELD_DBM_TX_POWER.into()) {
            Some(RadiotapField::DbmTxPower(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the Antenna field.
    pub fn antenna(mut self, antenna: u8) -> Self {
        self.set_field(RadiotapField::Antenna(antenna));
        self
    }

    /// Current Antenna field, if present.
    pub fn antenna_value(&self) -> Option<u8> {
        match self.field(RADIOTAP_FIELD_ANTENNA.into()) {
            Some(RadiotapField::Antenna(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the RX flags field.
    pub fn rx_flags(mut self, rx_flags: impl Into<RadiotapRxFlags>) -> Self {
        self.set_field(RadiotapField::RxFlags(rx_flags.into()));
        self
    }

    /// Current RX flags field, if present.
    pub fn rx_flags_value(&self) -> Option<RadiotapRxFlags> {
        match self.field(RADIOTAP_FIELD_RX_FLAGS.into()) {
            Some(RadiotapField::RxFlags(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the TX flags field.
    pub fn tx_flags(mut self, tx_flags: impl Into<RadiotapTxFlags>) -> Self {
        self.set_field(RadiotapField::TxFlags(tx_flags.into()));
        self
    }

    /// Current TX flags field, if present.
    pub fn tx_flags_value(&self) -> Option<RadiotapTxFlags> {
        match self.field(RADIOTAP_FIELD_TX_FLAGS.into()) {
            Some(RadiotapField::TxFlags(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the RTS retry count.
    pub fn rts_retries(mut self, rts_retries: u8) -> Self {
        self.set_field(RadiotapField::RtsRetries(rts_retries));
        self
    }

    /// Current RTS retry count, if present.
    pub fn rts_retries_value(&self) -> Option<u8> {
        match self.field(RADIOTAP_FIELD_RTS_RETRIES.into()) {
            Some(RadiotapField::RtsRetries(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the data retry count.
    pub fn data_retries(mut self, data_retries: u8) -> Self {
        self.set_field(RadiotapField::DataRetries(data_retries));
        self
    }

    /// Current data retry count, if present.
    pub fn data_retries_value(&self) -> Option<u8> {
        match self.field(RADIOTAP_FIELD_DATA_RETRIES.into()) {
            Some(RadiotapField::DataRetries(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the MCS field bytes.
    pub fn mcs(mut self, mcs: [u8; 3]) -> Self {
        self.set_field(RadiotapField::Mcs(mcs));
        self
    }

    /// Current MCS field bytes, if present.
    pub fn mcs_value(&self) -> Option<[u8; 3]> {
        match self.field(RADIOTAP_FIELD_MCS.into()) {
            Some(RadiotapField::Mcs(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the A-MPDU status field bytes.
    pub fn a_mpdu_status(mut self, a_mpdu_status: [u8; 8]) -> Self {
        self.set_field(RadiotapField::AMpduStatus(a_mpdu_status));
        self
    }

    /// Current A-MPDU status field bytes, if present.
    pub fn a_mpdu_status_value(&self) -> Option<[u8; 8]> {
        match self.field(RADIOTAP_FIELD_A_MPDU_STATUS.into()) {
            Some(RadiotapField::AMpduStatus(value)) => Some(*value),
            _ => None,
        }
    }

    /// Set the VHT field bytes.
    pub fn vht(mut self, vht: [u8; 12]) -> Self {
        self.set_field(RadiotapField::Vht(vht));
        self
    }

    /// Current VHT field bytes, if present.
    pub fn vht_value(&self) -> Option<[u8; 12]> {
        match self.field(RADIOTAP_FIELD_VHT.into()) {
            Some(RadiotapField::Vht(value)) => Some(*value),
            _ => None,
        }
    }

    fn set_field(&mut self, field: RadiotapField) {
        let present_bit = field.present_bit();

        if let Some(existing) = self
            .fields
            .iter_mut()
            .find(|existing| existing.present_bit() == present_bit)
        {
            *existing = field;
        } else {
            self.fields.push(field);
        }
    }

    pub(crate) fn fields_in_present_order(&self) -> Vec<&RadiotapField> {
        let mut fields = self.fields.iter().collect::<Vec<_>>();
        fields.sort_by_key(|field| field.present_bit());
        fields
    }

    pub(crate) fn encoded_fields_len_from_offset(
        &self,
        fields_offset_from_header_start: usize,
    ) -> usize {
        let mut offset = fields_offset_from_header_start;

        for field in self.fields_in_present_order() {
            offset += radiotap_field_padding(offset, field.alignment());
            offset += field.size();
        }

        offset - fields_offset_from_header_start + self.raw_fields.len()
    }

    pub(crate) fn compile_fields_from_offset(
        &self,
        fields_offset_from_header_start: usize,
        out: &mut Vec<u8>,
    ) -> usize {
        let initial_len = out.len();
        let mut offset = fields_offset_from_header_start;

        for field in self.fields_in_present_order() {
            let padding = radiotap_field_padding(offset, field.alignment());
            out.resize(out.len() + padding, 0);
            offset += padding;
            field.encode_body(out);
            offset += field.size();
        }

        out.extend_from_slice(&self.raw_fields);

        out.len() - initial_len
    }

    pub(crate) fn decode_fields_from_header(
        present: &RadiotapPresent,
        header: &[u8],
        fields_offset_from_header_start: usize,
    ) -> Result<(Vec<RadiotapField>, usize)> {
        let mut fields = Vec::new();
        let mut offset = fields_offset_from_header_start;

        for bit in present.field_bits() {
            let Some(metadata) = radiotap_field_metadata(bit) else {
                break;
            };

            offset += radiotap_field_padding(offset, metadata.alignment());
            let required = offset + metadata.size();
            if header.len() < required {
                return Err(CrafterError::buffer_too_short(
                    "radiotap.field",
                    required,
                    header.len(),
                ));
            }

            fields.push(decode_radiotap_field(bit, &header[offset..required])?);
            offset = required;
        }

        Ok((fields, offset))
    }

    fn inferred_present(&self) -> Result<RadiotapPresent> {
        RadiotapPresent::from_field_bits(self.typed_field_bits(), self.unknown_field_bits())
    }

    fn effective_version(&self) -> u8 {
        self.version.value().copied().unwrap_or(0)
    }

    fn effective_pad(&self) -> u8 {
        self.pad.value().copied().unwrap_or(0)
    }

    fn header_len_with_present(&self, present: &RadiotapPresent) -> usize {
        let fields_offset = RADIOTAP_FIXED_HEADER_LEN + present.encoded_len();
        RADIOTAP_FIXED_HEADER_LEN
            + present.encoded_len()
            + self.encoded_fields_len_from_offset(fields_offset)
    }

    fn fallback_header_len(&self) -> usize {
        let present_len = self
            .present
            .value()
            .map(RadiotapPresent::encoded_len)
            .unwrap_or(RADIOTAP_PRESENT_WORD_LEN);
        let fields_offset = RADIOTAP_FIXED_HEADER_LEN + present_len;
        RADIOTAP_FIXED_HEADER_LEN + present_len + self.encoded_fields_len_from_offset(fields_offset)
    }

    fn compiled_header_len(&self) -> Result<u16> {
        let present = self.present()?;
        let header_len = self.header_len_with_present(&present);
        u16::try_from(header_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "radiotap.length",
                "encoded radiotap header exceeds u16 length",
            )
        })
    }
}

impl Default for Radiotap {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Radiotap {
    fn name(&self) -> &'static str {
        "Radiotap"
    }

    fn summary(&self) -> String {
        let present = self.present();
        let length = match &present {
            Ok(present) => self
                .compiled_header_len()
                .map(usize::from)
                .unwrap_or_else(|_| self.header_len_with_present(present)),
            Err(_) => self
                .length_value()
                .map(usize::from)
                .unwrap_or_else(|| self.fallback_header_len()),
        };
        let mut fields = vec![
            format!("version={}", self.effective_version()),
            format!("len={length}"),
            format!("fields={}", self.fields.len()),
        ];
        match present {
            Ok(present) => fields.push(format!("present={}", radiotap_present_summary(&present))),
            Err(err) => {
                fields.push("present=malformed".to_string());
                fields.push(format!("present_error={err}"));
            }
        }

        if !self.raw_fields.is_empty() {
            fields.push(format!("raw_fields_len={}", self.raw_fields.len()));
        }
        if let Some(fcs) = self.fcs_status() {
            fields.push(format!("fcs_present={}", fcs.present()));
            fields.push(format!("failed_fcs={}", fcs.failed()));
        }

        format!("Radiotap({})", fields.join(", "))
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let present = self.present();
        let length = match &present {
            Ok(present) => self
                .compiled_header_len()
                .map(usize::from)
                .unwrap_or_else(|_| self.header_len_with_present(present)),
            Err(_) => self
                .length_value()
                .map(usize::from)
                .unwrap_or_else(|| self.fallback_header_len()),
        };
        let mut fields = vec![
            ("version", self.effective_version().to_string()),
            ("pad", format!("0x{:02x}", self.effective_pad())),
            ("length", length.to_string()),
            ("field_count", self.fields.len().to_string()),
        ];
        match present {
            Ok(present) => fields.push(("present", radiotap_present_summary(&present))),
            Err(err) => {
                fields.push(("present", "malformed".to_string()));
                fields.push(("present_error", err.to_string()));
            }
        }

        for field in self.fields_in_present_order() {
            fields.push((field.inspection_name(), field.inspection_value()));
        }

        if !self.raw_fields.is_empty() {
            fields.push(("raw_fields_len", self.raw_fields.len().to_string()));
            fields.push(("raw_fields", radiotap_hex_bytes(&self.raw_fields)));
        }
        if let Some(fcs) = self.fcs_status() {
            fields.push(("fcs_present", fcs.present().to_string()));
            fields.push(("failed_fcs", fcs.failed().to_string()));
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        self.present()
            .map(|present| self.header_len_with_present(&present))
            .unwrap_or_else(|_| self.fallback_header_len())
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let present = self.present()?;
        let length = self.compiled_header_len()?;
        let fields_offset = RADIOTAP_FIXED_HEADER_LEN + present.encoded_len();

        out.push(self.effective_version());
        out.push(self.effective_pad());
        out.extend_from_slice(&length.to_le_bytes());
        present.encode(out);
        self.compile_fields_from_offset(fields_offset, out);
        Ok(())
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R> Div<R> for Radiotap
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

/// Decode radiotap metadata followed by an IEEE 802.11 MAC frame.
pub(crate) fn decode_radiotap_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> Result<Packet> {
    let (radiotap, tail) = decode_radiotap(bytes)?;
    let packet = Packet::new().push(radiotap);

    if tail.is_empty() {
        Ok(packet)
    } else {
        decode_dot11_with_registry(registry, tail).map(|dot11| packet.concat(dot11))
    }
}

fn decode_radiotap(bytes: &[u8]) -> Result<(Radiotap, &[u8])> {
    if bytes.len() < RADIOTAP_FIXED_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "radiotap.header",
            RADIOTAP_FIXED_HEADER_LEN,
            bytes.len(),
        ));
    }

    let declared_len = u16::from_le_bytes([bytes[2], bytes[3]]);
    let header_len = usize::from(declared_len);
    if header_len < RADIOTAP_MIN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "radiotap.header",
            RADIOTAP_MIN_HEADER_LEN,
            header_len,
        ));
    }
    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            "radiotap.header",
            header_len,
            bytes.len(),
        ));
    }

    let header = &bytes[..header_len];
    let (present, present_len) = RadiotapPresent::decode(&header[RADIOTAP_FIXED_HEADER_LEN..])?;
    let fields_offset = RADIOTAP_FIXED_HEADER_LEN + present_len;
    let (fields, consumed) = Radiotap::decode_fields_from_header(&present, header, fields_offset)?;

    let radiotap = Radiotap {
        version: Field::user(bytes[0]),
        pad: Field::user(bytes[1]),
        length: Field::user(declared_len),
        present: Field::user(present),
        fields,
        raw_fields: header[consumed..].to_vec(),
    };

    Ok((radiotap, &bytes[header_len..]))
}

fn radiotap_field_array<const N: usize>(context: &'static str, bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .get(..N)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| CrafterError::buffer_too_short(context, N, bytes.len()))
}

pub(crate) fn decode_radiotap_field(bit: u16, bytes: &[u8]) -> Result<RadiotapField> {
    let Some(metadata) = radiotap_field_metadata(bit) else {
        return Err(CrafterError::invalid_field_value(
            "radiotap.field.bit",
            "unknown radiotap field bit",
        ));
    };
    if bytes.len() < metadata.size() {
        return Err(CrafterError::buffer_too_short(
            "radiotap.field",
            metadata.size(),
            bytes.len(),
        ));
    }
    let bytes = &bytes[..metadata.size()];

    let field = match bit {
        bit if bit == u16::from(RADIOTAP_FIELD_TSFT) => RadiotapField::Tsft(u64::from_le_bytes(
            radiotap_field_array("radiotap.field.tsft", bytes)?,
        )),
        bit if bit == u16::from(RADIOTAP_FIELD_FLAGS) => {
            RadiotapField::Flags(RadiotapFlags::from_bits(bytes[0]))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_RATE) => RadiotapField::Rate(bytes[0]),
        bit if bit == u16::from(RADIOTAP_FIELD_CHANNEL) => {
            RadiotapField::Channel(RadiotapChannel::new(
                u16::from_le_bytes([bytes[0], bytes[1]]),
                u16::from_le_bytes([bytes[2], bytes[3]]),
            ))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_FHSS) => {
            RadiotapField::Fhss(bytes.try_into().expect("FHSS size"))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_ANTENNA_SIGNAL) => {
            RadiotapField::AntennaSignal(bytes[0] as i8)
        }
        bit if bit == u16::from(RADIOTAP_FIELD_ANTENNA_NOISE) => {
            RadiotapField::AntennaNoise(bytes[0] as i8)
        }
        bit if bit == u16::from(RADIOTAP_FIELD_LOCK_QUALITY) => {
            RadiotapField::LockQuality(u16::from_le_bytes([bytes[0], bytes[1]]))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_TX_ATTENUATION) => {
            RadiotapField::TxAttenuation(u16::from_le_bytes([bytes[0], bytes[1]]))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_DB_TX_ATTENUATION) => {
            RadiotapField::DbTxAttenuation(u16::from_le_bytes([bytes[0], bytes[1]]))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_DBM_TX_POWER) => {
            RadiotapField::DbmTxPower(bytes[0] as i8)
        }
        bit if bit == u16::from(RADIOTAP_FIELD_ANTENNA) => RadiotapField::Antenna(bytes[0]),
        bit if bit == u16::from(RADIOTAP_FIELD_RX_FLAGS) => {
            RadiotapField::RxFlags(RadiotapRxFlags::from_bits(u16::from_le_bytes([
                bytes[0], bytes[1],
            ])))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_TX_FLAGS) => {
            RadiotapField::TxFlags(RadiotapTxFlags::from_bits(u16::from_le_bytes([
                bytes[0], bytes[1],
            ])))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_RTS_RETRIES) => RadiotapField::RtsRetries(bytes[0]),
        bit if bit == u16::from(RADIOTAP_FIELD_DATA_RETRIES) => {
            RadiotapField::DataRetries(bytes[0])
        }
        bit if bit == u16::from(RADIOTAP_FIELD_MCS) => {
            RadiotapField::Mcs(bytes.try_into().expect("MCS size"))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_A_MPDU_STATUS) => {
            RadiotapField::AMpduStatus(bytes.try_into().expect("A-MPDU status size"))
        }
        bit if bit == u16::from(RADIOTAP_FIELD_VHT) => {
            RadiotapField::Vht(bytes.try_into().expect("VHT size"))
        }
        _ => {
            return Err(CrafterError::invalid_field_value(
                "radiotap.field.bit",
                "unknown radiotap field bit",
            ))
        }
    };

    Ok(field)
}

impl RadiotapField {
    fn inspection_name(&self) -> &'static str {
        match self {
            Self::Tsft(_) => "tsft",
            Self::Flags(_) => "flags",
            Self::Rate(_) => "rate_500kbps",
            Self::Channel(_) => "channel",
            Self::Fhss(_) => "fhss",
            Self::AntennaSignal(_) => "antenna_signal_dbm",
            Self::AntennaNoise(_) => "antenna_noise_dbm",
            Self::LockQuality(_) => "lock_quality",
            Self::TxAttenuation(_) => "tx_attenuation",
            Self::DbTxAttenuation(_) => "db_tx_attenuation",
            Self::DbmTxPower(_) => "dbm_tx_power_dbm",
            Self::Antenna(_) => "antenna",
            Self::RxFlags(_) => "rx_flags",
            Self::TxFlags(_) => "tx_flags",
            Self::RtsRetries(_) => "rts_retries",
            Self::DataRetries(_) => "data_retries",
            Self::Mcs(_) => "mcs",
            Self::AMpduStatus(_) => "a_mpdu_status",
            Self::Vht(_) => "vht",
            Self::Unknown(_) => "unknown_field",
        }
    }

    fn inspection_value(&self) -> String {
        match self {
            Self::Tsft(value) => value.to_string(),
            Self::Flags(value) => format!("0x{:02x}", value.bits()),
            Self::Rate(value) => value.to_string(),
            Self::Channel(value) => {
                format!(
                    "frequency={}, flags=0x{:04x}",
                    value.frequency(),
                    value.flags()
                )
            }
            Self::Fhss(value) => radiotap_hex_bytes(value),
            Self::AntennaSignal(value) => value.to_string(),
            Self::AntennaNoise(value) => value.to_string(),
            Self::LockQuality(value) => value.to_string(),
            Self::TxAttenuation(value) => value.to_string(),
            Self::DbTxAttenuation(value) => value.to_string(),
            Self::DbmTxPower(value) => value.to_string(),
            Self::Antenna(value) => value.to_string(),
            Self::RxFlags(value) => format!("0x{:04x}", value.bits()),
            Self::TxFlags(value) => format!("0x{:04x}", value.bits()),
            Self::RtsRetries(value) => value.to_string(),
            Self::DataRetries(value) => value.to_string(),
            Self::Mcs(value) => radiotap_hex_bytes(value),
            Self::AMpduStatus(value) => radiotap_hex_bytes(value),
            Self::Vht(value) => radiotap_hex_bytes(value),
            Self::Unknown(value) => format!(
                "bit={}, align={}, bytes={}",
                value.present_bit(),
                value.alignment(),
                radiotap_hex_bytes(value.raw_bytes())
            ),
        }
    }
}

fn radiotap_present_summary(present: &RadiotapPresent) -> String {
    present
        .words()
        .iter()
        .map(|word| format!("0x{word:08x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn radiotap_hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac::MacAddr;
    use crate::packet::{LinkType, Raw};
    use crate::protocols::link::Dot11;

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

    #[test]
    fn radiotap_alignment_padding_from_header_start_handles_required_boundaries() {
        assert_eq!(radiotap_field_padding(8, 1), 0);
        assert_eq!(radiotap_field_padding(9, 2), 1);
        assert_eq!(radiotap_field_padding(10, 4), 2);
        assert_eq!(radiotap_field_padding(12, 8), 4);
        assert_eq!(radiotap_field_padding(16, 8), 0);
    }

    #[test]
    fn radiotap_alignment_compile_fields_inserts_padding_by_present_order() {
        let radiotap = Radiotap::new()
            .unknown_field(32, 4, [0xde, 0xad, 0xbe, 0xef])
            .unwrap()
            .with_field(RadiotapField::AMpduStatus([
                0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
            ]))
            .channel((0x1122, 0x3344))
            .flags(0x5a)
            .tsft(0x0102_0304_0506_0708);
        let present = radiotap.present().unwrap();
        let fields_offset = RADIOTAP_FIXED_HEADER_LEN + present.encoded_len();
        let mut encoded = Vec::new();

        let emitted = radiotap.compile_fields_from_offset(fields_offset, &mut encoded);

        assert_eq!(fields_offset, 12);
        assert_eq!(emitted, encoded.len());
        assert_eq!(
            radiotap.encoded_fields_len_from_offset(fields_offset),
            encoded.len()
        );
        assert_eq!(
            encoded,
            vec![
                // TSFT aligns from header offset 12 to 16.
                0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
                // Flags is 1-byte aligned.
                0x5a, // Channel aligns from header offset 25 to 26.
                0x00, 0x22, 0x11, 0x44, 0x33,
                // A-MPDU status aligns from header offset 30 to 32.
                0x00, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                // Unknown bit 32 uses its stored 4-byte alignment.
                0xde, 0xad, 0xbe, 0xef,
            ]
        );
    }

    #[test]
    fn radiotap_alignment_decode_fields_skips_padding_by_present_order() {
        let present = RadiotapPresent::from_words([
            RADIOTAP_PRESENT_EXTENDED
                | RADIOTAP_PRESENT_TSFT
                | RADIOTAP_PRESENT_FLAGS
                | RADIOTAP_PRESENT_CHANNEL
                | RADIOTAP_PRESENT_A_MPDU_STATUS,
            0,
        ]);
        let fields_offset = RADIOTAP_FIXED_HEADER_LEN + present.encoded_len();
        let mut header = vec![0; fields_offset];
        header.extend_from_slice(&[
            // TSFT aligns from header offset 12 to 16.
            0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            // Flags is 1-byte aligned.
            0x5a, // Channel aligns from header offset 25 to 26.
            0x00, 0x22, 0x11, 0x44, 0x33,
            // A-MPDU status aligns from header offset 30 to 32.
            0x00, 0x00, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        ]);

        let (fields, consumed) =
            Radiotap::decode_fields_from_header(&present, &header, fields_offset).unwrap();

        assert_eq!(fields_offset, 12);
        assert_eq!(consumed, header.len());
        assert_eq!(
            fields,
            vec![
                RadiotapField::Tsft(0x0102_0304_0506_0708),
                RadiotapField::Flags(RadiotapFlags::from_bits(0x5a)),
                RadiotapField::Channel(RadiotapChannel::new(0x1122, 0x3344)),
                RadiotapField::AMpduStatus([0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,]),
            ]
        );
    }

    #[test]
    fn radiotap_fields_empty_layer_does_not_invent_defaults() {
        let radiotap = Radiotap::new();

        assert!(radiotap.fields().is_empty());
        assert_eq!(radiotap.tsft_value(), None);
        assert_eq!(radiotap.flags_value(), None);
        assert_eq!(radiotap.rate_value(), None);
        assert_eq!(radiotap.channel_value(), None);
        assert_eq!(radiotap.antenna_signal_value(), None);
        assert_eq!(radiotap.antenna_value(), None);
        assert_eq!(radiotap.rx_flags_value(), None);
        assert_eq!(radiotap.tx_flags_value(), None);
        assert_eq!(radiotap.present().unwrap().words(), &[0]);
    }

    #[test]
    fn radiotap_fields_typed_setters_store_values_and_present_bits() {
        let radiotap = Radiotap::new()
            .tsft(0x0102_0304_0506_0708)
            .flags(RADIOTAP_FLAGS_FCS_PRESENT | RADIOTAP_FLAGS_FAILED_FCS)
            .rate(12)
            .channel((2412, 0x00a0))
            .antenna_signal(-42)
            .antenna(2)
            .rx_flags(0x0002)
            .tx_flags(0x0008);

        assert_eq!(radiotap.tsft_value(), Some(0x0102_0304_0506_0708));
        assert_eq!(
            radiotap.flags_value().map(|flags| flags.bits()),
            Some(RADIOTAP_FLAGS_FCS_PRESENT | RADIOTAP_FLAGS_FAILED_FCS)
        );
        assert_eq!(
            radiotap.fcs_status(),
            Some(RadiotapFcsStatus::new(true, true))
        );
        assert_eq!(radiotap.rate_value(), Some(12));
        assert_eq!(
            radiotap.channel_value(),
            Some(RadiotapChannel::new(2412, 0x00a0))
        );
        assert_eq!(
            radiotap.channel_value().map(RadiotapChannel::to_bytes),
            Some([0x6c, 0x09, 0xa0, 0x00])
        );
        assert_eq!(radiotap.antenna_signal_value(), Some(-42));
        assert_eq!(radiotap.antenna_value(), Some(2));
        assert_eq!(
            radiotap.rx_flags_value().map(|flags| flags.bits()),
            Some(0x0002)
        );
        assert_eq!(
            radiotap.tx_flags_value().map(|flags| flags.bits()),
            Some(0x0008)
        );

        let present = radiotap.present().unwrap();
        assert!(present.is_field_present(RADIOTAP_FIELD_TSFT.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_FLAGS.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_RATE.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_CHANNEL.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_ANTENNA_SIGNAL.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_ANTENNA.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_RX_FLAGS.into()));
        assert!(present.is_field_present(RADIOTAP_FIELD_TX_FLAGS.into()));
        assert!(!present.is_field_present(RADIOTAP_FIELD_ANTENNA_NOISE.into()));

        assert_eq!(
            radiotap.field(RADIOTAP_FIELD_CHANNEL.into()),
            Some(&RadiotapField::Channel(RadiotapChannel::new(2412, 0x00a0)))
        );
        assert_eq!(
            radiotap
                .typed_field_bits()
                .collect::<std::collections::BTreeSet<_>>(),
            [
                RADIOTAP_FIELD_TSFT.into(),
                RADIOTAP_FIELD_FLAGS.into(),
                RADIOTAP_FIELD_RATE.into(),
                RADIOTAP_FIELD_CHANNEL.into(),
                RADIOTAP_FIELD_ANTENNA_SIGNAL.into(),
                RADIOTAP_FIELD_ANTENNA.into(),
                RADIOTAP_FIELD_RX_FLAGS.into(),
                RADIOTAP_FIELD_TX_FLAGS.into(),
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn radiotap_fields_unknown_preserves_present_bit_alignment_and_bytes() {
        let radiotap = Radiotap::new()
            .unknown_field(32, 4, [0xde, 0xad, 0xbe, 0xef])
            .unwrap();
        let unknown = radiotap.unknown_fields().next().unwrap();

        assert_eq!(unknown.present_bit(), 32);
        assert_eq!(unknown.alignment(), 4);
        assert_eq!(unknown.raw_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(unknown.size(), 4);
        assert_eq!(radiotap.unknown_field_bits().collect::<Vec<_>>(), vec![32]);

        let field = radiotap.field(32).unwrap();
        assert!(field.is_unknown());
        assert_eq!(field.present_bit(), 32);
        assert_eq!(field.alignment(), 4);
        assert_eq!(field.size(), 4);
        assert_eq!(
            radiotap.present().unwrap().words(),
            &[RADIOTAP_PRESENT_EXTENDED, 0x1]
        );
    }

    #[test]
    fn radiotap_fields_setters_replace_by_present_bit_without_defaults() {
        let radiotap = Radiotap::new()
            .rate(11)
            .rate(22)
            .with_field(RadiotapField::Unknown(
                RadiotapUnknownField::new(RADIOTAP_FIELD_RATE.into(), 1, [0xff]).unwrap(),
            ));

        assert_eq!(radiotap.rate_value(), None);
        assert_eq!(radiotap.fields().len(), 1);
        assert_eq!(
            radiotap
                .unknown_fields()
                .next()
                .map(|field| field.raw_bytes()),
            Some(&[0xff][..])
        );
    }

    #[test]
    fn radiotap_fields_reject_extension_bit_as_unknown_field() {
        let err = RadiotapUnknownField::new(31, 1, []).unwrap_err();
        assert_eq!(
            err,
            CrafterError::invalid_field_value(
                "radiotap.present.bit",
                "bit 31 of each present word is the extension flag",
            )
        );

        let err = RadiotapUnknownField::new(32, 0, []).unwrap_err();
        assert_eq!(
            err,
            CrafterError::invalid_field_value(
                "radiotap.field.alignment",
                "alignment must be at least one octet",
            )
        );
    }

    #[test]
    fn radiotap_layer_compile_computes_length_present_and_inspection() {
        let packet = Radiotap::new()
            .flags(RADIOTAP_FLAGS_FCS_PRESENT)
            .rate(12)
            .channel((2412, 0x00a0))
            / Raw::from([0xaa, 0xbb]);
        let radiotap = packet.layer::<Radiotap>().unwrap();

        assert_eq!(radiotap.encoded_len(), 14);
        assert_eq!(radiotap.version_value(), Some(0));
        assert_eq!(radiotap.pad_value(), Some(0));
        assert_eq!(radiotap.length_value(), None);
        assert_eq!(
            radiotap.fcs_status(),
            Some(RadiotapFcsStatus::new(true, false))
        );
        assert_eq!(
            radiotap.present().unwrap().words(),
            &[RADIOTAP_PRESENT_FLAGS | RADIOTAP_PRESENT_RATE | RADIOTAP_PRESENT_CHANNEL]
        );

        let compiled = packet.compile().unwrap();

        assert_eq!(
            compiled.as_bytes(),
            &[
                0x00, 0x00, 0x0e, 0x00, // version, pad, it_len
                0x0e, 0x00, 0x00, 0x00, // present: Flags, Rate, Channel
                0x10, 0x0c, // Flags and Rate
                0x6c, 0x09, 0xa0, 0x00, // Channel
                0xaa, 0xbb,
            ]
        );
        assert!(packet.summary().contains("Radiotap("));
        assert!(packet.show().contains("fcs_present: true"));
    }

    #[test]
    fn radiotap_layer_decode_dispatches_dot11_and_round_trips() {
        let dot11 = Dot11::data()
            .addr1(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
            .addr2(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]))
            .addr3(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]))
            .sequence_number(7);
        let dot11_bytes = Packet::from_layer(dot11).compile().unwrap();
        let mut bytes = vec![
            0x00, 0x00, 0x0a, 0x00, // version, pad, it_len
            0x06, 0x00, 0x00, 0x00, // present: Flags, Rate
            0x50, 0x16,
        ];
        bytes.extend_from_slice(dot11_bytes.as_bytes());

        let decoded = Packet::decode_from_link(LinkType::Radiotap, &bytes).unwrap();
        let radiotap = decoded.layer::<Radiotap>().unwrap();

        assert_eq!(radiotap.length_value(), Some(10));
        assert_eq!(radiotap.flags_value(), Some(RadiotapFlags::from_bits(0x50)));
        assert_eq!(
            radiotap.fcs_status(),
            Some(RadiotapFcsStatus::new(true, true))
        );
        assert_eq!(radiotap.rate_value(), Some(0x16));
        assert!(radiotap.raw_fields().is_empty());
        assert!(decoded.layer::<Dot11>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn radiotap_decode_from_link_dispatches_radiotap_root_and_inner_dot11() {
        let dot11 = Dot11::data()
            .addr1(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]))
            .addr2(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02]))
            .addr3(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x03]))
            .sequence_number(37);
        let dot11_bytes = Packet::from_layer(dot11).compile().unwrap();
        let mut bytes = vec![
            0x00, 0x00, 0x08, 0x00, // version, pad, it_len
            0x00, 0x00, 0x00, 0x00, // present: no fields
        ];
        bytes.extend_from_slice(dot11_bytes.as_bytes());

        let decoded = Packet::decode_from_link(LinkType::Radiotap, &bytes).unwrap();
        let radiotap = decoded.layer::<Radiotap>().unwrap();
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(radiotap.version_value(), Some(0));
        assert_eq!(radiotap.length_value(), Some(8));
        assert!(radiotap.fields().is_empty());
        assert_eq!(dot11.sequence_number_value(), Some(37));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn radiotap_decode_from_link_keeps_bare_dot11_link_root_separate() {
        let dot11 = Dot11::data()
            .addr1(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x11]))
            .addr2(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x12]))
            .addr3(MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x13]))
            .sequence_number(38);
        let bytes = Packet::from_layer(dot11).compile().unwrap();

        let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes()).unwrap();
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert!(decoded.layer::<Radiotap>().is_none());
        assert_eq!(dot11.sequence_number_value(), Some(38));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    #[test]
    fn radiotap_fcs_metadata_failed_fcs_decodes_typed_layers_and_preserves_tail() {
        let dot11 = Dot11::data()
            .addr1(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
            .addr2(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]))
            .addr3(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]))
            .sequence_number(11);
        let dot11_bytes = Packet::from_layer(dot11).compile().unwrap();
        let fcs = [0xde, 0xad, 0xbe, 0xef];
        let present = RADIOTAP_PRESENT_FLAGS | RADIOTAP_PRESENT_RX_FLAGS;
        let mut bytes = vec![
            0x00, 0x00, 0x0c, 0x00, // version, pad, it_len
        ];
        bytes.extend_from_slice(&present.to_le_bytes());
        bytes.extend_from_slice(&[
            RADIOTAP_FLAGS_FCS_PRESENT | RADIOTAP_FLAGS_FAILED_FCS,
            0x00, // alignment padding before RX flags
        ]);
        bytes.extend_from_slice(&RADIOTAP_RX_FLAGS_PLCP_CRC_FAILED.to_le_bytes());
        bytes.extend_from_slice(dot11_bytes.as_bytes());
        bytes.extend_from_slice(&fcs);

        let decoded = Packet::decode_from_link(LinkType::Radiotap, &bytes).unwrap();
        let radiotap = decoded.layer::<Radiotap>().unwrap();
        let rx_flags = radiotap.rx_flags_value().unwrap();

        assert_eq!(
            radiotap.fcs_status(),
            Some(RadiotapFcsStatus::new(true, true))
        );
        assert_eq!(rx_flags.bits(), RADIOTAP_RX_FLAGS_PLCP_CRC_FAILED);
        assert!(rx_flags.plcp_crc_failed());
        assert!(!rx_flags.reserved_fcs_failed_bit());
        assert!(decoded.layer::<Dot11>().is_some());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &fcs);

        let summary = decoded.summary();
        assert!(summary.contains("fcs_present=true"), "{summary}");
        assert!(summary.contains("failed_fcs=true"), "{summary}");
        let show = decoded.show();
        assert!(show.contains("rx_flags: 0x0002"), "{show}");
        assert!(show.contains("failed_fcs: true"), "{show}");
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn radiotap_fcs_metadata_rx_reserved_bit_is_not_failed_fcs_status() {
        let dot11 = Dot11::data()
            .addr1(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
            .addr2(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]))
            .addr3(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]))
            .sequence_number(12);
        let dot11_bytes = Packet::from_layer(dot11).compile().unwrap();
        let mut bytes = vec![
            0x00, 0x00, 0x0a, 0x00, // version, pad, it_len
        ];
        bytes.extend_from_slice(&RADIOTAP_PRESENT_RX_FLAGS.to_le_bytes());
        bytes.extend_from_slice(&RADIOTAP_RX_FLAGS_RESERVED_WAS_FCS_FAILED.to_le_bytes());
        bytes.extend_from_slice(dot11_bytes.as_bytes());

        let decoded = Packet::decode_from_link(LinkType::Radiotap, &bytes).unwrap();
        let radiotap = decoded.layer::<Radiotap>().unwrap();
        let rx_flags = radiotap.rx_flags_value().unwrap();

        assert_eq!(radiotap.fcs_status(), None);
        assert_eq!(rx_flags.bits(), RADIOTAP_RX_FLAGS_RESERVED_WAS_FCS_FAILED);
        assert!(rx_flags.reserved_fcs_failed_bit());
        assert!(!rx_flags.plcp_crc_failed());
        assert!(decoded.layer::<Dot11>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn radiotap_layer_decode_preserves_unknown_header_tail() {
        let bytes = [
            0x00, 0x00, 0x0c, 0x00, // version, pad, it_len
            0x00, 0x00, 0x00, 0x20, // present: untyped bit 29
            0xde, 0xad, 0xbe, 0xef,
        ];

        let decoded = Packet::decode_from_link(LinkType::Radiotap, bytes).unwrap();
        let radiotap = decoded.layer::<Radiotap>().unwrap();

        assert_eq!(radiotap.present().unwrap().words(), &[0x2000_0000]);
        assert_eq!(radiotap.raw_fields(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn radiotap_decode_preserves_header_fields_raw_tail_and_inner_dot11() {
        let dot11 = Dot11::data()
            .addr1(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]))
            .addr2(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]))
            .addr3(MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x03]))
            .sequence_number(9);
        let dot11_bytes = Packet::from_layer(dot11).compile().unwrap();
        let present =
            RADIOTAP_PRESENT_FLAGS | RADIOTAP_PRESENT_RATE | RADIOTAP_PRESENT_CHANNEL | 0x2000_0000;
        let mut bytes = vec![
            0x00, 0x2a, 0x10, 0x00, // version, pad, it_len
        ];
        bytes.extend_from_slice(&present.to_le_bytes());
        bytes.extend_from_slice(&[
            0x50, // Flags: FCS present + failed FCS
            0x16, // Rate
            0x6c, 0x09, 0xa0, 0x00, // Channel
            0xde, 0xad, // raw bytes for the untyped present bit
        ]);
        bytes.extend_from_slice(dot11_bytes.as_bytes());

        let decoded = Packet::decode_from_link(LinkType::Radiotap, &bytes).unwrap();
        let radiotap = decoded.layer::<Radiotap>().unwrap();
        let dot11 = decoded.layer::<Dot11>().unwrap();

        assert_eq!(radiotap.version_value(), Some(0));
        assert_eq!(radiotap.pad_value(), Some(0x2a));
        assert_eq!(radiotap.length_value(), Some(16));
        assert_eq!(radiotap.present().unwrap().words(), &[present]);
        assert_eq!(radiotap.flags_value(), Some(RadiotapFlags::from_bits(0x50)));
        assert_eq!(
            radiotap.fcs_status(),
            Some(RadiotapFcsStatus::new(true, true))
        );
        assert_eq!(radiotap.rate_value(), Some(0x16));
        assert_eq!(
            radiotap.channel_value(),
            Some(RadiotapChannel::new(2412, 0x00a0))
        );
        assert_eq!(radiotap.raw_fields(), &[0xde, 0xad]);
        assert_eq!(dot11.sequence_number_value(), Some(9));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
    }

    #[test]
    fn radiotap_decode_returns_structured_errors_for_header_lengths() {
        let short_base = [
            0x00, 0x00, 0x08, 0x00, // version, pad, it_len
            0x00, 0x00, 0x00,
        ];
        let short_base_err = Packet::decode_from_link(LinkType::Radiotap, short_base).unwrap_err();
        assert_eq!(
            short_base_err,
            CrafterError::buffer_too_short("radiotap.header", 8, 7)
        );

        let invalid_len = [
            0x00, 0x00, 0x04, 0x00, // version, pad, invalid it_len
            0x00, 0x00, 0x00, 0x00,
        ];
        let invalid_len_err =
            Packet::decode_from_link(LinkType::Radiotap, invalid_len).unwrap_err();
        assert_eq!(
            invalid_len_err,
            CrafterError::buffer_too_short("radiotap.header", 8, 4)
        );
    }

    #[test]
    fn radiotap_decode_returns_structured_errors_for_truncated_fields() {
        let truncated_present = [
            0x00, 0x00, 0x08, 0x00, // version, pad, it_len
            0x00, 0x00, 0x00, 0x80, // present extension without following word
        ];
        let truncated_present_err =
            Packet::decode_from_link(LinkType::Radiotap, truncated_present).unwrap_err();
        assert_eq!(
            truncated_present_err,
            CrafterError::buffer_too_short("radiotap.present", 8, 4)
        );

        let truncated_channel = [
            0x00, 0x00, 0x0a, 0x00, // version, pad, it_len
            0x08, 0x00, 0x00, 0x00, // present: Channel
            0x6c, 0x09,
        ];
        let truncated_channel_err =
            Packet::decode_from_link(LinkType::Radiotap, truncated_channel).unwrap_err();
        assert_eq!(
            truncated_channel_err,
            CrafterError::buffer_too_short("radiotap.field", 12, 10)
        );
    }
}
