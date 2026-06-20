//! IGMP group-record model.
//!
//! Group records are populated during the IGMPv3 report steps.

use core::net::Ipv4Addr;

use crate::error::{CrafterError, Result};
use crate::field::{Field, FieldState};

use super::constants::{
    IGMP_DEFAULT_AUX_DATA_LEN, IGMP_DEFAULT_SOURCE_COUNT, IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES,
    IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES, IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE,
    IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE, IGMP_RECORD_TYPE_MODE_IS_EXCLUDE,
    IGMP_RECORD_TYPE_MODE_IS_INCLUDE, IGMP_V3_GROUP_RECORD_HEADER_LEN,
};

const IGMP_GROUP_RECORD_AUX_DATA_UNIT: usize = 4;

/// Source-backed IGMPv3 Group Record Type value.
///
/// RFC 9776 section 4.2.13 defines values `1..=6`. Value `0` is kept as a
/// reserved byte, and every other value is preserved as [`IgmpRecordType::Unknown`]
/// so future or malformed records remain constructible and inspectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IgmpRecordType {
    /// Reserved zero value.
    Reserved,
    /// MODE_IS_INCLUDE (1), a Current-State Record.
    ModeIsInclude,
    /// MODE_IS_EXCLUDE (2), a Current-State Record.
    ModeIsExclude,
    /// CHANGE_TO_INCLUDE_MODE (3), a Filter-Mode-Change Record.
    ChangeToIncludeMode,
    /// CHANGE_TO_EXCLUDE_MODE (4), a Filter-Mode-Change Record.
    ChangeToExcludeMode,
    /// ALLOW_NEW_SOURCES (5), a Source-List-Change Record.
    AllowNewSources,
    /// BLOCK_OLD_SOURCES (6), a Source-List-Change Record.
    BlockOldSources,
    /// Any Record Type not defined by RFC 9776 section 4.2.13.
    Unknown(u8),
}

impl IgmpRecordType {
    /// Return the raw wire Record Type byte.
    pub const fn code(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::ModeIsInclude => IGMP_RECORD_TYPE_MODE_IS_INCLUDE,
            Self::ModeIsExclude => IGMP_RECORD_TYPE_MODE_IS_EXCLUDE,
            Self::ChangeToIncludeMode => IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE,
            Self::ChangeToExcludeMode => IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE,
            Self::AllowNewSources => IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES,
            Self::BlockOldSources => IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES,
            Self::Unknown(code) => code,
        }
    }

    /// Return the raw wire Record Type byte.
    pub const fn raw(self) -> u8 {
        self.code()
    }

    /// Return the raw wire Record Type byte.
    pub const fn to_u8(self) -> u8 {
        self.code()
    }

    /// Classify a raw Record Type byte without rejecting unknown values.
    pub const fn from_u8(code: u8) -> Self {
        igmp_record_type(code)
    }

    /// Return source-backed metadata for this Record Type.
    pub const fn meta(self) -> IgmpRecordTypeMeta {
        igmp_record_type_meta(self.code())
    }
}

impl core::fmt::Display for IgmpRecordType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let meta = self.meta();
        match meta.status {
            IgmpRecordTypeStatus::Unassigned => write!(f, "Unknown({})", meta.code),
            _ => f.write_str(meta.name),
        }
    }
}

/// Assignment status for an IGMPv3 Group Record Type value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IgmpRecordTypeStatus {
    /// Defined by RFC 9776 section 4.2.13.
    Assigned,
    /// Reserved zero value.
    Reserved,
    /// Not defined by RFC 9776 section 4.2.13.
    Unassigned,
}

/// One source-backed IGMPv3 Group Record Type metadata entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IgmpRecordTypeMeta {
    /// Raw wire Record Type byte.
    pub code: u8,
    /// Record Type classification preserving raw unknown values.
    pub record_type: IgmpRecordType,
    /// Stable RFC token, or a status label for unassigned values.
    pub name: &'static str,
    /// Stable summary label suitable for later `summary()` and `show()` output.
    pub summary: &'static str,
    /// Assignment status.
    pub status: IgmpRecordTypeStatus,
}

/// Classify an IGMPv3 Group Record Type byte without rejecting unknown values.
pub const fn igmp_record_type(code: u8) -> IgmpRecordType {
    match code {
        0 => IgmpRecordType::Reserved,
        IGMP_RECORD_TYPE_MODE_IS_INCLUDE => IgmpRecordType::ModeIsInclude,
        IGMP_RECORD_TYPE_MODE_IS_EXCLUDE => IgmpRecordType::ModeIsExclude,
        IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE => IgmpRecordType::ChangeToIncludeMode,
        IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE => IgmpRecordType::ChangeToExcludeMode,
        IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES => IgmpRecordType::AllowNewSources,
        IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES => IgmpRecordType::BlockOldSources,
        other => IgmpRecordType::Unknown(other),
    }
}

/// Return metadata for an IGMPv3 Group Record Type byte.
pub const fn igmp_record_type_meta(code: u8) -> IgmpRecordTypeMeta {
    match code {
        0 => record_type_meta(
            code,
            IgmpRecordType::Reserved,
            "Reserved",
            "Reserved Record Type",
            IgmpRecordTypeStatus::Reserved,
        ),
        IGMP_RECORD_TYPE_MODE_IS_INCLUDE => record_type_meta(
            code,
            IgmpRecordType::ModeIsInclude,
            "MODE_IS_INCLUDE",
            "Current-State Record: MODE_IS_INCLUDE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_MODE_IS_EXCLUDE => record_type_meta(
            code,
            IgmpRecordType::ModeIsExclude,
            "MODE_IS_EXCLUDE",
            "Current-State Record: MODE_IS_EXCLUDE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE => record_type_meta(
            code,
            IgmpRecordType::ChangeToIncludeMode,
            "CHANGE_TO_INCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_INCLUDE_MODE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE => record_type_meta(
            code,
            IgmpRecordType::ChangeToExcludeMode,
            "CHANGE_TO_EXCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_EXCLUDE_MODE",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES => record_type_meta(
            code,
            IgmpRecordType::AllowNewSources,
            "ALLOW_NEW_SOURCES",
            "Source-List-Change Record: ALLOW_NEW_SOURCES",
            IgmpRecordTypeStatus::Assigned,
        ),
        IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES => record_type_meta(
            code,
            IgmpRecordType::BlockOldSources,
            "BLOCK_OLD_SOURCES",
            "Source-List-Change Record: BLOCK_OLD_SOURCES",
            IgmpRecordTypeStatus::Assigned,
        ),
        other => record_type_meta(
            other,
            IgmpRecordType::Unknown(other),
            "Unassigned",
            "Unknown Record Type",
            IgmpRecordTypeStatus::Unassigned,
        ),
    }
}

/// Return the assignment status for an IGMPv3 Group Record Type byte.
pub const fn igmp_record_type_status(code: u8) -> IgmpRecordTypeStatus {
    igmp_record_type_meta(code).status
}

/// Return a source-backed name when the Record Type byte has one.
pub const fn igmp_record_type_name(code: u8) -> Option<&'static str> {
    let meta = igmp_record_type_meta(code);
    match meta.status {
        IgmpRecordTypeStatus::Unassigned => None,
        _ => Some(meta.name),
    }
}

/// Return a stable summary label for an IGMPv3 Group Record Type byte.
pub const fn igmp_record_type_summary(code: u8) -> &'static str {
    igmp_record_type_meta(code).summary
}

const fn record_type_meta(
    code: u8,
    record_type: IgmpRecordType,
    name: &'static str,
    summary: &'static str,
    status: IgmpRecordTypeStatus,
) -> IgmpRecordTypeMeta {
    IgmpRecordTypeMeta {
        code,
        record_type,
        name,
        summary,
        status,
    }
}

/// One IGMPv3 Group Record inside a Version 3 Membership Report.
///
/// RFC 9776 section 4.2 lays a group record out as Record Type (1 octet), Aux
/// Data Len (1 octet, in 32-bit words), Number of Sources (2 octets),
/// Multicast Address (4 octets), N Source Addresses, and then auxiliary data.
/// The count fields auto-fill from the carried source and auxiliary-data bytes
/// unless the caller pins them explicitly for malformed-packet construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgmpGroupRecord {
    record_type: IgmpRecordType,
    auxiliary_data_len: Field<u8>,
    number_of_sources: Field<u16>,
    multicast_address: Ipv4Addr,
    source_addresses: Vec<Ipv4Addr>,
    auxiliary_data: Vec<u8>,
}

impl IgmpGroupRecord {
    /// Create an IGMPv3 group record for `multicast_address`.
    pub fn new(record_type: IgmpRecordType, multicast_address: Ipv4Addr) -> Self {
        Self {
            record_type,
            auxiliary_data_len: Field::unset(),
            number_of_sources: Field::unset(),
            multicast_address,
            source_addresses: Vec::new(),
            auxiliary_data: Vec::new(),
        }
    }

    /// Build a MODE_IS_INCLUDE record for `multicast_address`.
    pub fn mode_is_include(multicast_address: Ipv4Addr) -> Self {
        Self::new(IgmpRecordType::ModeIsInclude, multicast_address)
    }

    /// Build a MODE_IS_EXCLUDE record for `multicast_address`.
    pub fn mode_is_exclude(multicast_address: Ipv4Addr) -> Self {
        Self::new(IgmpRecordType::ModeIsExclude, multicast_address)
    }

    /// Build a CHANGE_TO_INCLUDE_MODE record for `multicast_address`.
    pub fn change_to_include_mode(multicast_address: Ipv4Addr) -> Self {
        Self::new(IgmpRecordType::ChangeToIncludeMode, multicast_address)
    }

    /// Build a CHANGE_TO_EXCLUDE_MODE record for `multicast_address`.
    pub fn change_to_exclude_mode(multicast_address: Ipv4Addr) -> Self {
        Self::new(IgmpRecordType::ChangeToExcludeMode, multicast_address)
    }

    /// Build an ALLOW_NEW_SOURCES record for `multicast_address`.
    pub fn allow_new_sources(multicast_address: Ipv4Addr) -> Self {
        Self::new(IgmpRecordType::AllowNewSources, multicast_address)
    }

    /// Build a BLOCK_OLD_SOURCES record for `multicast_address`.
    pub fn block_old_sources(multicast_address: Ipv4Addr) -> Self {
        Self::new(IgmpRecordType::BlockOldSources, multicast_address)
    }

    /// Set the Record Type from source-backed metadata.
    pub fn with_record_type(mut self, record_type: IgmpRecordType) -> Self {
        self.record_type = record_type;
        self
    }

    /// Set the raw Record Type byte, preserving unknown values.
    pub fn with_raw_record_type(self, record_type: u8) -> Self {
        self.with_record_type(IgmpRecordType::from_u8(record_type))
    }

    /// Set the raw Aux Data Len field in 32-bit words.
    pub fn with_auxiliary_data_len(mut self, words: u8) -> Self {
        self.auxiliary_data_len.set_user(words);
        self
    }

    /// Compatibility alias for the Aux Data Len field.
    pub fn with_aux_data_len(self, words: u8) -> Self {
        self.with_auxiliary_data_len(words)
    }

    /// Set the raw Number of Sources field.
    pub fn with_number_of_sources(mut self, count: u16) -> Self {
        self.number_of_sources.set_user(count);
        self
    }

    /// Set the Multicast Address field.
    pub fn with_multicast_address(mut self, multicast_address: Ipv4Addr) -> Self {
        self.multicast_address = multicast_address;
        self
    }

    /// Replace the source-address vector.
    pub fn with_source_addresses(mut self, source_addresses: impl Into<Vec<Ipv4Addr>>) -> Self {
        self.source_addresses = source_addresses.into();
        self
    }

    /// Append one source address.
    pub fn with_source_address(mut self, source_address: Ipv4Addr) -> Self {
        self.source_addresses.push(source_address);
        self
    }

    /// Replace the auxiliary-data bytes.
    pub fn with_auxiliary_data(mut self, auxiliary_data: impl Into<Vec<u8>>) -> Self {
        self.auxiliary_data = auxiliary_data.into();
        self
    }

    /// Compatibility alias for auxiliary-data bytes.
    pub fn with_aux_data(self, auxiliary_data: impl Into<Vec<u8>>) -> Self {
        self.with_auxiliary_data(auxiliary_data)
    }

    /// Append one auxiliary-data byte.
    pub fn with_auxiliary_data_byte(mut self, byte: u8) -> Self {
        self.auxiliary_data.push(byte);
        self
    }

    /// Source-backed Record Type classification.
    pub fn record_type(&self) -> IgmpRecordType {
        self.record_type
    }

    /// Raw Record Type byte.
    pub fn record_type_value(&self) -> u8 {
        self.record_type.code()
    }

    /// Raw Record Type byte.
    pub fn raw_record_type_value(&self) -> u8 {
        self.record_type_value()
    }

    /// Source-backed Record Type metadata.
    pub fn record_type_meta(&self) -> IgmpRecordTypeMeta {
        self.record_type.meta()
    }

    /// Aux Data Len field value in 32-bit words.
    pub fn auxiliary_data_len_value(&self) -> u8 {
        if self.auxiliary_data.is_empty() {
            return value_or_copy(&self.auxiliary_data_len, IGMP_DEFAULT_AUX_DATA_LEN);
        }
        value_or_copy(
            &self.auxiliary_data_len,
            auxiliary_data_len_words(self.auxiliary_data.len()),
        )
    }

    /// Compatibility alias for the Aux Data Len field.
    pub fn aux_data_len_value(&self) -> u8 {
        self.auxiliary_data_len_value()
    }

    /// Number of Sources field value, derived from the vector unless explicit.
    pub fn number_of_sources_value(&self) -> u16 {
        if self.source_addresses.is_empty() {
            return value_or_copy(&self.number_of_sources, IGMP_DEFAULT_SOURCE_COUNT);
        }
        value_or_copy(&self.number_of_sources, self.source_addresses.len() as u16)
    }

    /// Multicast Address field.
    pub fn multicast_address(&self) -> Ipv4Addr {
        self.multicast_address
    }

    /// Multicast Address field.
    pub fn multicast_address_value(&self) -> Ipv4Addr {
        self.multicast_address
    }

    /// Source Address vector.
    pub fn source_addresses(&self) -> &[Ipv4Addr] {
        &self.source_addresses
    }

    /// Auxiliary-data bytes as supplied by the caller or decoder.
    pub fn auxiliary_data(&self) -> &[u8] {
        &self.auxiliary_data
    }

    /// Compatibility alias for auxiliary-data bytes.
    pub fn aux_data(&self) -> &[u8] {
        self.auxiliary_data()
    }

    /// Assignment state for the Aux Data Len field.
    pub fn auxiliary_data_len_state(&self) -> FieldState {
        self.auxiliary_data_len.state()
    }

    /// Compatibility alias for the Aux Data Len field state.
    pub fn aux_data_len_state(&self) -> FieldState {
        self.auxiliary_data_len_state()
    }

    /// Assignment state for the Number of Sources field.
    pub fn number_of_sources_state(&self) -> FieldState {
        self.number_of_sources.state()
    }

    /// One-line record summary.
    pub fn summary(&self) -> String {
        format!(
            "IgmpGroupRecord(type={}, group={}, sources={}, aux_words={}, aux={}B)",
            self.record_type,
            self.multicast_address,
            self.number_of_sources_value(),
            self.auxiliary_data_len_value(),
            self.auxiliary_data.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "record_type",
                format!("{} (0x{:02x})", self.record_type, self.record_type_value()),
            ),
            (
                "auxiliary_data_len",
                self.auxiliary_data_len_value().to_string(),
            ),
            (
                "number_of_sources",
                self.number_of_sources_value().to_string(),
            ),
            ("multicast_address", self.multicast_address.to_string()),
            (
                "source_addresses",
                self.source_addresses
                    .iter()
                    .map(Ipv4Addr::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            ("auxiliary_data", hex_bytes(&self.auxiliary_data)),
        ]
    }

    /// Serialized length in octets.
    pub fn encoded_len(&self) -> usize {
        IGMP_V3_GROUP_RECORD_HEADER_LEN
            + self.source_addresses.len() * 4
            + usize::from(self.auxiliary_data_len_value()) * IGMP_GROUP_RECORD_AUX_DATA_UNIT
    }

    /// Decode one IGMPv3 group record and return the unconsumed tail.
    ///
    /// The Aux Data Len and Number of Sources fields are marked explicit so the
    /// decoded wire counters survive even if builder vectors are changed later.
    pub fn decode_with_tail(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < IGMP_V3_GROUP_RECORD_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "igmp.group_record",
                IGMP_V3_GROUP_RECORD_HEADER_LEN,
                bytes.len(),
            ));
        }

        let record_type = IgmpRecordType::from_u8(bytes[0]);
        let auxiliary_data_len = bytes[1];
        let number_of_sources = u16::from_be_bytes([bytes[2], bytes[3]]);
        let multicast_address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let sources_len = usize::from(number_of_sources) * 4;
        let sources_end = IGMP_V3_GROUP_RECORD_HEADER_LEN + sources_len;
        if bytes.len() < sources_end {
            return Err(CrafterError::buffer_too_short(
                "igmp.group_record.source_addresses",
                sources_end,
                bytes.len(),
            ));
        }

        let auxiliary_len = usize::from(auxiliary_data_len) * IGMP_GROUP_RECORD_AUX_DATA_UNIT;
        let auxiliary_end = sources_end + auxiliary_len;
        if bytes.len() < auxiliary_end {
            return Err(CrafterError::buffer_too_short(
                "igmp.group_record.auxiliary_data",
                auxiliary_end,
                bytes.len(),
            ));
        }

        let mut source_addresses = Vec::with_capacity(usize::from(number_of_sources));
        for source in bytes[IGMP_V3_GROUP_RECORD_HEADER_LEN..sources_end].chunks_exact(4) {
            source_addresses.push(Ipv4Addr::new(source[0], source[1], source[2], source[3]));
        }

        let record = Self {
            record_type,
            auxiliary_data_len: Field::user(auxiliary_data_len),
            number_of_sources: Field::user(number_of_sources),
            multicast_address,
            source_addresses,
            auxiliary_data: bytes[sources_end..auxiliary_end].to_vec(),
        };

        Ok((record, &bytes[auxiliary_end..]))
    }

    /// Decode one IGMPv3 group record, ignoring any unconsumed tail bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (record, _) = Self::decode_with_tail(bytes)?;
        Ok(record)
    }

    /// Serialize this group record to its wire bytes.
    pub fn compile(&self) -> Result<Vec<u8>> {
        self.try_compile()
    }

    /// Serialize this group record to its wire bytes.
    pub fn try_compile(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }

    /// Append this group record's wire bytes to `out`.
    pub fn try_encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        let auxiliary_len = self.auxiliary_wire_len()?;

        out.push(self.record_type_value());
        out.push(self.auxiliary_data_len_value());
        out.extend_from_slice(&self.number_of_sources_value().to_be_bytes());
        out.extend_from_slice(&self.multicast_address.octets());
        for source_address in &self.source_addresses {
            out.extend_from_slice(&source_address.octets());
        }

        let emitted_auxiliary_len = auxiliary_len.min(self.auxiliary_data.len());
        out.extend_from_slice(&self.auxiliary_data[..emitted_auxiliary_len]);
        out.resize(out.len() + auxiliary_len - emitted_auxiliary_len, 0);

        Ok(())
    }

    /// Append this group record's wire bytes to `out`.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        self.try_encode_into(out)
    }

    fn auxiliary_wire_len(&self) -> Result<usize> {
        let auxiliary_len =
            usize::from(self.auxiliary_data_len_value()) * IGMP_GROUP_RECORD_AUX_DATA_UNIT;
        if self.auxiliary_data_len.is_user_set() && self.auxiliary_data.len() < auxiliary_len {
            return Err(CrafterError::buffer_too_short(
                "igmp.group_record.auxiliary_data",
                auxiliary_len,
                self.auxiliary_data.len(),
            ));
        }

        Ok(auxiliary_len)
    }
}

impl Default for IgmpGroupRecord {
    fn default() -> Self {
        Self::new(IgmpRecordType::Reserved, Ipv4Addr::UNSPECIFIED)
    }
}

impl core::fmt::Display for IgmpGroupRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.summary())
    }
}

fn auxiliary_data_len_words(auxiliary_data_len: usize) -> u8 {
    let words = auxiliary_data_len.div_ceil(IGMP_GROUP_RECORD_AUX_DATA_UNIT);
    u8::try_from(words).unwrap_or(u8::MAX)
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod igmp_group_record_model {
    use super::*;

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 80)
    }

    fn doc_source_a() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn doc_source_b() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn igmp_group_record_model_defaults_to_empty_reserved_record() {
        let record = IgmpGroupRecord::default();

        assert_eq!(record.record_type(), IgmpRecordType::Reserved);
        assert_eq!(record.record_type_value(), 0);
        assert_eq!(record.raw_record_type_value(), 0);
        assert_eq!(
            record.record_type_meta().status,
            IgmpRecordTypeStatus::Reserved
        );
        assert_eq!(record.auxiliary_data_len_value(), 0);
        assert_eq!(record.number_of_sources_value(), 0);
        assert_eq!(record.multicast_address(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(record.multicast_address_value(), Ipv4Addr::UNSPECIFIED);
        assert!(record.source_addresses().is_empty());
        assert!(record.auxiliary_data().is_empty());
        assert!(record.aux_data().is_empty());
        assert_eq!(record.auxiliary_data_len_state(), FieldState::Unset);
        assert_eq!(record.aux_data_len_state(), FieldState::Unset);
        assert_eq!(record.number_of_sources_state(), FieldState::Unset);
        assert_eq!(record.encoded_len(), IGMP_V3_GROUP_RECORD_HEADER_LEN);
        assert_eq!(
            record.compile().expect("compile default record"),
            vec![0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            record.summary(),
            "IgmpGroupRecord(type=Reserved, group=0.0.0.0, sources=0, aux_words=0, aux=0B)"
        );
    }

    #[test]
    fn igmp_group_record_model_auto_fills_sources_and_known_record_type() {
        let record = IgmpGroupRecord::mode_is_include(doc_group())
            .with_source_address(doc_source_a())
            .with_source_address(doc_source_b());

        assert_eq!(record.record_type(), IgmpRecordType::ModeIsInclude);
        assert_eq!(record.record_type_value(), IGMP_RECORD_TYPE_MODE_IS_INCLUDE);
        assert_eq!(record.number_of_sources_value(), 2);
        assert_eq!(record.number_of_sources_state(), FieldState::Unset);
        assert_eq!(record.auxiliary_data_len_value(), 0);
        assert_eq!(record.source_addresses(), &[doc_source_a(), doc_source_b()]);
        assert_eq!(
            record.summary(),
            "IgmpGroupRecord(type=MODE_IS_INCLUDE, group=233.252.0.80, sources=2, aux_words=0, aux=0B)"
        );
        assert_eq!(
            record.inspection_fields(),
            vec![
                ("record_type", "MODE_IS_INCLUDE (0x01)".to_string()),
                ("auxiliary_data_len", "0".to_string()),
                ("number_of_sources", "2".to_string()),
                ("multicast_address", "233.252.0.80".to_string()),
                ("source_addresses", "192.0.2.10,198.51.100.20".to_string()),
                ("auxiliary_data", String::new()),
            ]
        );

        assert_eq!(
            record.compile().expect("compile source record"),
            vec![0x01, 0x00, 0x00, 0x02, 233, 252, 0, 80, 192, 0, 2, 10, 198, 51, 100, 20,]
        );
    }

    #[test]
    fn igmp_group_record_model_preserves_unknown_record_type() {
        let record = IgmpGroupRecord::new(IgmpRecordType::ModeIsExclude, doc_group())
            .with_raw_record_type(0xc8);

        assert_eq!(record.record_type(), IgmpRecordType::Unknown(0xc8));
        assert_eq!(record.record_type_value(), 0xc8);
        assert_eq!(
            record.record_type_meta().status,
            IgmpRecordTypeStatus::Unassigned
        );
        assert_eq!(
            record.compile().expect("compile unknown record type")[0],
            0xc8
        );
    }

    #[test]
    fn igmp_group_record_model_auto_fills_auxiliary_data_length_and_padding() {
        let record =
            IgmpGroupRecord::allow_new_sources(doc_group()).with_auxiliary_data([0xde, 0xad, 0xbe]);

        assert_eq!(record.auxiliary_data_len_value(), 1);
        assert_eq!(record.auxiliary_data_len_state(), FieldState::Unset);
        assert_eq!(record.encoded_len(), IGMP_V3_GROUP_RECORD_HEADER_LEN + 4);
        assert_eq!(record.auxiliary_data(), &[0xde, 0xad, 0xbe]);
        assert_eq!(
            record.compile().expect("compile padded aux data"),
            vec![0x05, 0x01, 0x00, 0x00, 233, 252, 0, 80, 0xde, 0xad, 0xbe, 0x00]
        );
    }

    #[test]
    fn igmp_group_record_model_preserves_explicit_count_and_aux_length() {
        let record = IgmpGroupRecord::block_old_sources(doc_group())
            .with_source_addresses(vec![doc_source_a(), doc_source_b()])
            .with_number_of_sources(7)
            .with_aux_data([1, 2, 3, 4, 5, 6, 7, 8])
            .with_aux_data_len(2);

        assert_eq!(record.number_of_sources_value(), 7);
        assert_eq!(record.number_of_sources_state(), FieldState::User);
        assert_eq!(record.aux_data_len_value(), 2);
        assert_eq!(record.aux_data_len_state(), FieldState::User);
        assert_eq!(
            record.compile().expect("compile explicit aux length"),
            vec![
                0x06, 0x02, 0x00, 0x07, 233, 252, 0, 80, 192, 0, 2, 10, 198, 51, 100, 20, 1, 2, 3,
                4, 5, 6, 7, 8,
            ]
        );
    }

    #[test]
    fn igmp_group_record_model_explicit_short_aux_length_truncates_encoded_aux_region() {
        let record = IgmpGroupRecord::change_to_exclude_mode(doc_group())
            .with_auxiliary_data([1, 2, 3, 4, 5, 6])
            .with_auxiliary_data_len(1);

        assert_eq!(record.auxiliary_data(), &[1, 2, 3, 4, 5, 6]);
        assert_eq!(record.auxiliary_data_len_value(), 1);
        assert_eq!(record.encoded_len(), IGMP_V3_GROUP_RECORD_HEADER_LEN + 4);
        assert_eq!(
            record.compile().expect("compile truncated aux data"),
            vec![0x04, 0x01, 0x00, 0x00, 233, 252, 0, 80, 1, 2, 3, 4]
        );
    }
}

#[cfg(test)]
mod igmp_group_record_encode {
    use super::*;

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 80)
    }

    fn doc_source_a() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn doc_source_b() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn igmp_group_record_encode_zero_sources_and_zero_auxiliary_data() -> crate::Result<()> {
        let record = IgmpGroupRecord::mode_is_include(doc_group());

        assert_eq!(record.number_of_sources_value(), 0);
        assert_eq!(record.auxiliary_data_len_value(), 0);
        assert_eq!(
            record.try_compile()?,
            vec![0x01, 0x00, 0x00, 0x00, 233, 252, 0, 80]
        );

        Ok(())
    }

    #[test]
    fn igmp_group_record_encode_multiple_sources_auto_fills_count() -> crate::Result<()> {
        let record = IgmpGroupRecord::mode_is_exclude(doc_group())
            .with_source_address(doc_source_a())
            .with_source_address(doc_source_b());

        assert_eq!(record.number_of_sources_value(), 2);
        assert_eq!(record.number_of_sources_state(), FieldState::Unset);
        assert_eq!(
            record.try_compile()?,
            vec![0x02, 0x00, 0x00, 0x02, 233, 252, 0, 80, 192, 0, 2, 10, 198, 51, 100, 20,]
        );

        Ok(())
    }

    #[test]
    fn igmp_group_record_encode_pads_unset_auxiliary_data_len() -> crate::Result<()> {
        let record =
            IgmpGroupRecord::allow_new_sources(doc_group()).with_auxiliary_data([0xaa, 0xbb]);

        assert_eq!(record.auxiliary_data_len_value(), 1);
        assert_eq!(record.auxiliary_data_len_state(), FieldState::Unset);
        assert_eq!(
            record.try_compile()?,
            vec![0x05, 0x01, 0x00, 0x00, 233, 252, 0, 80, 0xaa, 0xbb, 0x00, 0x00]
        );

        Ok(())
    }

    #[test]
    fn igmp_group_record_encode_preserves_explicit_malformed_source_count() -> crate::Result<()> {
        let record = IgmpGroupRecord::block_old_sources(doc_group())
            .with_source_addresses(vec![doc_source_a(), doc_source_b()])
            .with_number_of_sources(7);

        assert_eq!(record.number_of_sources_value(), 7);
        assert_eq!(record.number_of_sources_state(), FieldState::User);
        assert_eq!(
            record.try_compile()?,
            vec![0x06, 0x00, 0x00, 0x07, 233, 252, 0, 80, 192, 0, 2, 10, 198, 51, 100, 20,]
        );

        Ok(())
    }

    #[test]
    fn igmp_group_record_encode_preserves_representable_explicit_auxiliary_length(
    ) -> crate::Result<()> {
        let record = IgmpGroupRecord::change_to_exclude_mode(doc_group())
            .with_auxiliary_data([1, 2, 3, 4, 5, 6])
            .with_auxiliary_data_len(1);

        assert_eq!(record.auxiliary_data_len_value(), 1);
        assert_eq!(record.auxiliary_data_len_state(), FieldState::User);
        assert_eq!(
            record.try_compile()?,
            vec![0x04, 0x01, 0x00, 0x00, 233, 252, 0, 80, 1, 2, 3, 4]
        );

        Ok(())
    }

    #[test]
    fn igmp_group_record_encode_errors_when_explicit_auxiliary_length_requires_missing_bytes() {
        let record = IgmpGroupRecord::allow_new_sources(doc_group())
            .with_auxiliary_data([1, 2, 3])
            .with_auxiliary_data_len(2);

        assert_eq!(
            record.try_compile(),
            Err(CrafterError::buffer_too_short(
                "igmp.group_record.auxiliary_data",
                8,
                3,
            ))
        );
    }

    #[test]
    fn igmp_group_record_encode_try_encode_into_appends_after_existing_bytes() -> crate::Result<()>
    {
        let record = IgmpGroupRecord::mode_is_include(doc_group());
        let mut bytes = vec![0xfe, 0xed];

        record.try_encode_into(&mut bytes)?;

        assert_eq!(
            bytes,
            vec![0xfe, 0xed, 0x01, 0x00, 0x00, 0x00, 233, 252, 0, 80]
        );

        Ok(())
    }
}

#[cfg(test)]
mod igmp_group_record_decode {
    use super::*;

    fn doc_group() -> Ipv4Addr {
        Ipv4Addr::new(233, 252, 0, 80)
    }

    fn doc_source_a() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn doc_source_b() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn igmp_group_record_decode_known_record_with_sources_and_auxiliary_data() -> crate::Result<()>
    {
        let bytes = [
            0x02, 0x01, 0x00, 0x02, 233, 252, 0, 80, 192, 0, 2, 10, 198, 51, 100, 20, 0xde, 0xad,
            0xbe, 0xef,
        ];

        let record = IgmpGroupRecord::decode(&bytes)?;

        assert_eq!(record.record_type(), IgmpRecordType::ModeIsExclude);
        assert_eq!(record.record_type_value(), IGMP_RECORD_TYPE_MODE_IS_EXCLUDE);
        assert_eq!(record.auxiliary_data_len_value(), 1);
        assert_eq!(record.auxiliary_data_len_state(), FieldState::User);
        assert_eq!(record.number_of_sources_value(), 2);
        assert_eq!(record.number_of_sources_state(), FieldState::User);
        assert_eq!(record.multicast_address(), doc_group());
        assert_eq!(record.source_addresses(), &[doc_source_a(), doc_source_b()]);
        assert_eq!(record.auxiliary_data(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(record.try_compile()?, bytes);

        Ok(())
    }

    #[test]
    fn igmp_group_record_decode_unknown_record_type_value() -> crate::Result<()> {
        let bytes = [0xc8, 0x00, 0x00, 0x00, 233, 252, 0, 80];

        let record = IgmpGroupRecord::decode(&bytes)?;

        assert_eq!(record.record_type(), IgmpRecordType::Unknown(0xc8));
        assert_eq!(record.record_type_value(), 0xc8);
        assert_eq!(
            record.record_type_meta().status,
            IgmpRecordTypeStatus::Unassigned
        );
        assert_eq!(record.try_compile()?, bytes);

        Ok(())
    }

    #[test]
    fn igmp_group_record_decode_zero_source_record_marks_wire_counts_explicit() -> crate::Result<()>
    {
        let bytes = [0x01, 0x00, 0x00, 0x00, 233, 252, 0, 80];

        let record = IgmpGroupRecord::decode(&bytes)?;

        assert_eq!(record.record_type(), IgmpRecordType::ModeIsInclude);
        assert_eq!(record.auxiliary_data_len_value(), 0);
        assert_eq!(record.auxiliary_data_len_state(), FieldState::User);
        assert_eq!(record.number_of_sources_value(), 0);
        assert_eq!(record.number_of_sources_state(), FieldState::User);
        assert!(record.source_addresses().is_empty());
        assert!(record.auxiliary_data().is_empty());
        assert_eq!(record.try_compile()?, bytes);

        Ok(())
    }

    #[test]
    fn igmp_group_record_decode_with_tail_preserves_remaining_bytes() -> crate::Result<()> {
        let bytes = [
            0x05, 0x00, 0x00, 0x01, 233, 252, 0, 80, 192, 0, 2, 10, 0xfa, 0xce,
        ];

        let (record, tail) = IgmpGroupRecord::decode_with_tail(&bytes)?;

        assert_eq!(record.record_type(), IgmpRecordType::AllowNewSources);
        assert_eq!(record.number_of_sources_value(), 1);
        assert_eq!(record.source_addresses(), &[doc_source_a()]);
        assert_eq!(tail, &[0xfa, 0xce]);
        assert_eq!(
            record.try_compile()?,
            [0x05, 0x00, 0x00, 0x01, 233, 252, 0, 80, 192, 0, 2, 10]
        );

        Ok(())
    }

    #[test]
    fn igmp_group_record_decode_short_header_returns_structured_error() {
        let error = IgmpGroupRecord::decode(&[0x01, 0x00, 0x00]).expect_err("short header");

        assert_eq!(
            error,
            CrafterError::buffer_too_short("igmp.group_record", IGMP_V3_GROUP_RECORD_HEADER_LEN, 3)
        );
    }

    #[test]
    fn igmp_group_record_decode_truncated_source_list_returns_structured_error() {
        let bytes = [0x01, 0x00, 0x00, 0x02, 233, 252, 0, 80, 192, 0, 2, 10, 198];

        let error = IgmpGroupRecord::decode(&bytes).expect_err("truncated source list");

        assert_eq!(
            error,
            CrafterError::buffer_too_short("igmp.group_record.source_addresses", 16, bytes.len())
        );
    }

    #[test]
    fn igmp_group_record_decode_truncated_auxiliary_data_returns_structured_error() {
        let bytes = [
            0x06, 0x02, 0x00, 0x01, 233, 252, 0, 80, 192, 0, 2, 10, 0xde, 0xad, 0xbe, 0xef, 0x00,
        ];

        let error = IgmpGroupRecord::decode(&bytes).expect_err("truncated auxiliary data");

        assert_eq!(
            error,
            CrafterError::buffer_too_short("igmp.group_record.auxiliary_data", 20, bytes.len())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_RECORD_TYPES: &[(u8, IgmpRecordType, &str, &str)] = &[
        (
            IGMP_RECORD_TYPE_MODE_IS_INCLUDE,
            IgmpRecordType::ModeIsInclude,
            "MODE_IS_INCLUDE",
            "Current-State Record: MODE_IS_INCLUDE",
        ),
        (
            IGMP_RECORD_TYPE_MODE_IS_EXCLUDE,
            IgmpRecordType::ModeIsExclude,
            "MODE_IS_EXCLUDE",
            "Current-State Record: MODE_IS_EXCLUDE",
        ),
        (
            IGMP_RECORD_TYPE_CHANGE_TO_INCLUDE_MODE,
            IgmpRecordType::ChangeToIncludeMode,
            "CHANGE_TO_INCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_INCLUDE_MODE",
        ),
        (
            IGMP_RECORD_TYPE_CHANGE_TO_EXCLUDE_MODE,
            IgmpRecordType::ChangeToExcludeMode,
            "CHANGE_TO_EXCLUDE_MODE",
            "Filter-Mode-Change Record: CHANGE_TO_EXCLUDE_MODE",
        ),
        (
            IGMP_RECORD_TYPE_ALLOW_NEW_SOURCES,
            IgmpRecordType::AllowNewSources,
            "ALLOW_NEW_SOURCES",
            "Source-List-Change Record: ALLOW_NEW_SOURCES",
        ),
        (
            IGMP_RECORD_TYPE_BLOCK_OLD_SOURCES,
            IgmpRecordType::BlockOldSources,
            "BLOCK_OLD_SOURCES",
            "Source-List-Change Record: BLOCK_OLD_SOURCES",
        ),
    ];

    #[test]
    fn igmp_record_type_classifies_every_known_type() {
        for &(code, record_type, name, summary) in KNOWN_RECORD_TYPES {
            let meta = igmp_record_type_meta(code);

            assert_eq!(igmp_record_type(code), record_type);
            assert_eq!(IgmpRecordType::from_u8(code), record_type);
            assert_eq!(record_type.code(), code);
            assert_eq!(record_type.raw(), code);
            assert_eq!(record_type.to_u8(), code);
            assert_eq!(record_type.meta(), meta);
            assert_eq!(meta.code, code);
            assert_eq!(meta.record_type, record_type);
            assert_eq!(meta.name, name);
            assert_eq!(meta.summary, summary);
            assert_eq!(meta.status, IgmpRecordTypeStatus::Assigned);
            assert_eq!(
                igmp_record_type_status(code),
                IgmpRecordTypeStatus::Assigned
            );
            assert_eq!(igmp_record_type_name(code), Some(name));
            assert_eq!(igmp_record_type_summary(code), summary);
            assert_eq!(record_type.to_string(), name);
        }
    }

    #[test]
    fn igmp_record_type_preserves_reserved_zero() {
        let meta = igmp_record_type_meta(0);

        assert_eq!(igmp_record_type(0), IgmpRecordType::Reserved);
        assert_eq!(IgmpRecordType::Reserved.code(), 0);
        assert_eq!(IgmpRecordType::Reserved.raw(), 0);
        assert_eq!(meta.code, 0);
        assert_eq!(meta.record_type, IgmpRecordType::Reserved);
        assert_eq!(meta.name, "Reserved");
        assert_eq!(meta.summary, "Reserved Record Type");
        assert_eq!(meta.status, IgmpRecordTypeStatus::Reserved);
        assert_eq!(igmp_record_type_status(0), IgmpRecordTypeStatus::Reserved);
        assert_eq!(igmp_record_type_name(0), Some("Reserved"));
        assert_eq!(igmp_record_type_summary(0), "Reserved Record Type");
        assert_eq!(IgmpRecordType::Reserved.to_string(), "Reserved");
    }

    #[test]
    fn igmp_record_type_preserves_unknown_values() {
        for code in [7, 200, u8::MAX] {
            let record_type = IgmpRecordType::Unknown(code);
            let meta = igmp_record_type_meta(code);

            assert_eq!(igmp_record_type(code), record_type);
            assert_eq!(IgmpRecordType::from_u8(code), record_type);
            assert_eq!(record_type.code(), code);
            assert_eq!(record_type.raw(), code);
            assert_eq!(record_type.to_u8(), code);
            assert_eq!(record_type.meta(), meta);
            assert_eq!(meta.code, code);
            assert_eq!(meta.record_type, record_type);
            assert_eq!(meta.name, "Unassigned");
            assert_eq!(meta.summary, "Unknown Record Type");
            assert_eq!(meta.status, IgmpRecordTypeStatus::Unassigned);
            assert_eq!(
                igmp_record_type_status(code),
                IgmpRecordTypeStatus::Unassigned
            );
            assert_eq!(igmp_record_type_name(code), None);
            assert_eq!(igmp_record_type_summary(code), "Unknown Record Type");
            assert_eq!(record_type.to_string(), format!("Unknown({code})"));
        }
    }

    #[test]
    fn igmp_record_type_metadata_covers_all_raw_values() {
        for code in 0u8..=u8::MAX {
            let meta = igmp_record_type_meta(code);

            assert_eq!(meta.code, code);
            assert_eq!(meta.record_type.code(), code);
            assert!(!meta.name.is_empty());
            assert!(!meta.summary.is_empty());
        }
    }
}
