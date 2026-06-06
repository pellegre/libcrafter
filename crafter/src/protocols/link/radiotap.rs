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

/// Radiotap Flags bit: frame includes an FCS trailer.
pub const RADIOTAP_FLAGS_FCS_PRESENT: u8 = 0x10;
/// Radiotap Flags bit: frame failed the FCS check.
pub const RADIOTAP_FLAGS_FAILED_FCS: u8 = 0x40;
/// Alias for [`RADIOTAP_FLAGS_FAILED_FCS`].
pub const RADIOTAP_FLAGS_BAD_FCS: u8 = RADIOTAP_FLAGS_FAILED_FCS;

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
}

/// Radiotap metadata preceding IEEE 802.11 frames.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Radiotap {
    fields: Vec<RadiotapField>,
}

impl Radiotap {
    /// Create an empty radiotap metadata layer.
    ///
    /// Radiotap fields are absent until the caller sets them or decode records
    /// them from wire bytes.
    pub fn new() -> Self {
        Self { fields: Vec::new() }
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
        RadiotapPresent::from_field_bits(self.typed_field_bits(), self.unknown_field_bits())
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
}
