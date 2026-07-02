//! NTP registry metadata.
//!
//! Labels and status classes are sourced from `.agents/docs/ntp-rfc-manifest.md`
//! and `.agents/docs/ntp-codepoints.md`. Registry metadata is inspectability
//! only: unknown but structurally valid packet values are preserved.

use super::constants::*;

/// Source-backed assignment status for an NTP codepoint or packet category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtpRegistryStatus {
    /// Value has a current source-backed assignment or defined packet meaning.
    Assigned,
    /// Value is reserved by the current registry or RFC text.
    Reserved,
    /// Value is reserved for private or experimental use.
    PrivateOrExperimental,
    /// Value has no current registry assignment.
    Unassigned,
    /// Value is outside the source-backed value space for that field.
    Unknown,
}

impl NtpRegistryStatus {
    /// Return true when the value has an assigned or otherwise defined meaning.
    pub const fn is_assigned(self) -> bool {
        matches!(self, Self::Assigned)
    }

    /// Stable status label for summaries and show output.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Reserved => "reserved",
            Self::PrivateOrExperimental => "private-or-experimental",
            Self::Unassigned => "unassigned",
            Self::Unknown => "unknown",
        }
    }
}

/// Source-backed category for NTP Extension Field Type inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtpExtensionFieldTypeCategory {
    /// Value has a current source-backed assignment.
    Assigned,
    /// Value is reserved for private or experimental use.
    PrivateOrExperimental,
    /// Value has no current registry assignment.
    UnknownOrUnassigned,
    /// Value is reserved because of obsolete or historic registry use.
    ObsoleteOrHistoric,
    /// Value is reserved without a narrower source-backed category.
    Reserved,
}

impl NtpExtensionFieldTypeCategory {
    /// Stable category label for extension type inspection.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::PrivateOrExperimental => "private-or-experimental",
            Self::UnknownOrUnassigned => "unknown-or-unassigned",
            Self::ObsoleteOrHistoric => "obsolete-or-historic",
            Self::Reserved => "reserved",
        }
    }
}

/// Source-backed metadata for an NTP Extension Field Type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtpExtensionFieldType {
    /// Raw 16-bit extension field type.
    pub value: u16,
    /// Stable display label.
    pub label: String,
    /// Extension-specific source category.
    pub category: NtpExtensionFieldTypeCategory,
    /// Compatibility status for the generic registry metadata API.
    pub status: NtpRegistryStatus,
}

impl NtpExtensionFieldType {
    /// Build extension type metadata from a raw field type value.
    pub fn new(value: u16) -> Self {
        ntp_extension_type(value)
    }

    /// Raw 16-bit extension field type.
    pub const fn value(&self) -> u16 {
        self.value
    }

    /// Raw 16-bit value for serialization.
    pub const fn wire_value(&self) -> u16 {
        self.value
    }

    /// Stable display label.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Extension-specific source category.
    pub const fn category(&self) -> NtpExtensionFieldTypeCategory {
        self.category
    }

    /// Compatibility status for the generic registry metadata API.
    pub const fn status(&self) -> NtpRegistryStatus {
        self.status
    }

    /// Return true when this field type is one of the registry-listed Autokey rows.
    pub const fn is_autokey_related(&self) -> bool {
        ntp_extension_field_type_is_autokey_related(self.value)
    }

    /// Convert to the older generic registry metadata shape.
    pub fn registry_meta(&self) -> NtpRegistryMeta {
        NtpRegistryMeta {
            value: self.value.into(),
            label: self.label.clone(),
            status: self.status,
        }
    }
}

impl From<u16> for NtpExtensionFieldType {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<NtpExtensionFieldType> for u16 {
    fn from(value: NtpExtensionFieldType) -> Self {
        value.value
    }
}

/// Metadata for numeric NTP codepoints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtpRegistryMeta {
    /// Raw numeric value supplied by the caller or parsed from the packet.
    pub value: u32,
    /// Stable display label.
    pub label: String,
    /// Source-backed assignment status.
    pub status: NtpRegistryStatus,
}

/// Metadata for four-octet NTP Reference ID and Kiss-o'-Death codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtpReferenceCodeMeta {
    /// Raw four-octet packet value.
    pub bytes: [u8; NTP_REFERENCE_ID_LEN],
    /// Stable display label.
    pub label: String,
    /// Source-backed assignment status.
    pub status: NtpRegistryStatus,
}

impl NtpReferenceCodeMeta {
    /// ASCII registry code when the raw bytes are uppercase alphanumeric and
    /// right-padded with NUL bytes.
    pub fn ascii_label(&self) -> Option<String> {
        ntp_reference_code_ascii_label(self.bytes)
    }
}

/// Return registry metadata for an NTP Leap Indicator value.
pub fn ntp_leap_indicator_meta(value: u8) -> NtpRegistryMeta {
    match value {
        NTP_LI_NO_WARNING => numeric_meta(value, "no-warning", NtpRegistryStatus::Assigned),
        NTP_LI_LAST_MINUTE_61_SECONDS => {
            numeric_meta(value, "last-minute-61-seconds", NtpRegistryStatus::Assigned)
        }
        NTP_LI_LAST_MINUTE_59_SECONDS => {
            numeric_meta(value, "last-minute-59-seconds", NtpRegistryStatus::Assigned)
        }
        NTP_LI_ALARM_UNSYNCHRONIZED => {
            numeric_meta(value, "alarm-unsynchronized", NtpRegistryStatus::Assigned)
        }
        other => NtpRegistryMeta {
            value: other.into(),
            label: format!("leap-indicator-{other}"),
            status: NtpRegistryStatus::Unknown,
        },
    }
}

/// Return registry metadata for an NTP Mode value.
pub fn ntp_mode_meta(value: u8) -> NtpRegistryMeta {
    match value {
        NTP_MODE_RESERVED => numeric_meta(value, "reserved", NtpRegistryStatus::Reserved),
        NTP_MODE_SYMMETRIC_ACTIVE => {
            numeric_meta(value, "symmetric-active", NtpRegistryStatus::Assigned)
        }
        NTP_MODE_SYMMETRIC_PASSIVE => {
            numeric_meta(value, "symmetric-passive", NtpRegistryStatus::Assigned)
        }
        NTP_MODE_CLIENT => numeric_meta(value, "client", NtpRegistryStatus::Assigned),
        NTP_MODE_SERVER => numeric_meta(value, "server", NtpRegistryStatus::Assigned),
        NTP_MODE_BROADCAST => numeric_meta(value, "broadcast", NtpRegistryStatus::Assigned),
        NTP_MODE_CONTROL => numeric_meta(value, "control", NtpRegistryStatus::Assigned),
        NTP_MODE_PRIVATE => numeric_meta(
            value,
            "private-use",
            NtpRegistryStatus::PrivateOrExperimental,
        ),
        other => NtpRegistryMeta {
            value: other.into(),
            label: format!("mode-{other}"),
            status: NtpRegistryStatus::Unknown,
        },
    }
}

/// Return registry metadata for an NTP stratum category.
pub fn ntp_stratum_meta(value: u8) -> NtpRegistryMeta {
    match value {
        NTP_STRATUM_UNSPECIFIED => {
            numeric_meta(value, "unspecified-or-invalid", NtpRegistryStatus::Assigned)
        }
        NTP_STRATUM_PRIMARY => numeric_meta(value, "primary", NtpRegistryStatus::Assigned),
        NTP_STRATUM_SECONDARY_FIRST..=NTP_STRATUM_SECONDARY_LAST => {
            numeric_meta(value, "secondary", NtpRegistryStatus::Assigned)
        }
        NTP_STRATUM_UNSYNCHRONIZED => {
            numeric_meta(value, "unsynchronized", NtpRegistryStatus::Assigned)
        }
        NTP_STRATUM_RESERVED_FIRST..=NTP_STRATUM_RESERVED_LAST => {
            numeric_meta(value, "reserved", NtpRegistryStatus::Reserved)
        }
    }
}

/// Return registry metadata for a stratum-0 Kiss-o'-Death Reference ID code.
pub fn ntp_kiss_o_death_code_meta(code: [u8; NTP_REFERENCE_ID_LEN]) -> NtpReferenceCodeMeta {
    if let Some(label) = known_kiss_o_death_code_label(code) {
        reference_code_meta(code, label, NtpRegistryStatus::Assigned)
    } else if begins_with_private_x(code) {
        NtpReferenceCodeMeta {
            bytes: code,
            label: format!(
                "{} (private-or-experimental)",
                hex32_label("kod", code_to_u32(code))
            ),
            status: NtpRegistryStatus::PrivateOrExperimental,
        }
    } else {
        NtpReferenceCodeMeta {
            bytes: code,
            label: hex32_label("kod", code_to_u32(code)),
            status: NtpRegistryStatus::Unassigned,
        }
    }
}

/// Return registry metadata for a stratum-1 NTP Reference Identifier code.
pub fn ntp_reference_id_meta(code: [u8; NTP_REFERENCE_ID_LEN]) -> NtpReferenceCodeMeta {
    if let Some(label) = known_reference_id_label(code) {
        reference_code_meta(code, label, NtpRegistryStatus::Assigned)
    } else if begins_with_private_x(code) {
        NtpReferenceCodeMeta {
            bytes: code,
            label: format!(
                "{} (private-or-experimental)",
                hex32_label("refid", code_to_u32(code))
            ),
            status: NtpRegistryStatus::PrivateOrExperimental,
        }
    } else {
        NtpReferenceCodeMeta {
            bytes: code,
            label: hex32_label("refid", code_to_u32(code)),
            status: NtpRegistryStatus::Unassigned,
        }
    }
}

/// Return registry metadata for an NTP Extension Field Type.
pub fn ntp_extension_field_type_meta(field_type: u16) -> NtpRegistryMeta {
    ntp_extension_type(field_type).registry_meta()
}

/// Return true for Autokey-related NTP Extension Field Type rows.
///
/// RFC 5906 is blocked for cryptographic and workflow behavior in this crate;
/// the current registry rows are still useful labels for preserving packet data.
pub const fn ntp_extension_field_type_is_autokey_related(field_type: u16) -> bool {
    matches!(
        field_type,
        0x0200..=0x0209 | 0x8200..=0x8209 | 0xC200..=0xC209
    )
}

/// Return source-backed metadata for an NTP Extension Field Type.
pub fn ntp_extension_type(field_type: u16) -> NtpExtensionFieldType {
    match field_type {
        0x0000 => extension_field_type_meta(
            field_type,
            "Crypto-NAK; authentication failure",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0002 | 0x0102 | 0x0302 | 0x0402 | 0x0502 | 0x0602 | 0x0702 | 0x0802 | 0x0902 | 0x8002
        | 0x8102 | 0x8302 | 0x8402 | 0x8502 | 0x8602 | 0x8702 | 0x8802 | 0x8902 | 0xC002
        | 0xC102 | 0xC302 | 0xC402 | 0xC502 | 0xC602 | 0xC702 | 0xC802 | 0xC902 => {
            extension_field_type_meta(
                field_type,
                "Reserved for historic reasons",
                NtpRegistryStatus::Reserved,
                NtpExtensionFieldTypeCategory::ObsoleteOrHistoric,
            )
        }
        0x0104 => extension_field_type_meta(
            field_type,
            "Unique Identifier",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x010A => extension_field_type_meta(
            field_type,
            "Network Correction",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0200 => extension_field_type_meta(
            field_type,
            "No-Operation Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0201 => extension_field_type_meta(
            field_type,
            "Association Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0202 => extension_field_type_meta(
            field_type,
            "Certificate Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0203 => extension_field_type_meta(
            field_type,
            "Cookie Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0204 => extension_field_type_meta(
            field_type,
            "Autokey Message Request / NTS Cookie",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0205 => extension_field_type_meta(
            field_type,
            "Leapseconds Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0206 => extension_field_type_meta(
            field_type,
            "Sign Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0207 => extension_field_type_meta(
            field_type,
            "IFF Identity Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0208 => extension_field_type_meta(
            field_type,
            "GQ Identity Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0209 => extension_field_type_meta(
            field_type,
            "MV Identity Message Request",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0304 => extension_field_type_meta(
            field_type,
            "NTS Cookie Placeholder",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x0404 => extension_field_type_meta(
            field_type,
            "NTS Authenticator and Encrypted Extension Fields",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x2005 => extension_field_type_meta(
            field_type,
            "UDP Checksum Complement",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8200 => extension_field_type_meta(
            field_type,
            "No-Operation Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8201 => extension_field_type_meta(
            field_type,
            "Association Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8202 => extension_field_type_meta(
            field_type,
            "Certificate Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8203 => extension_field_type_meta(
            field_type,
            "Cookie Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8204 => extension_field_type_meta(
            field_type,
            "Autokey Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8205 => extension_field_type_meta(
            field_type,
            "Leapseconds Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8206 => extension_field_type_meta(
            field_type,
            "Sign Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8207 => extension_field_type_meta(
            field_type,
            "IFF Identity Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8208 => extension_field_type_meta(
            field_type,
            "GQ Identity Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0x8209 => extension_field_type_meta(
            field_type,
            "MV Identity Message Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC200 => extension_field_type_meta(
            field_type,
            "No-Operation Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC201 => extension_field_type_meta(
            field_type,
            "Association Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC202 => extension_field_type_meta(
            field_type,
            "Certificate Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC203 => extension_field_type_meta(
            field_type,
            "Cookie Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC204 => extension_field_type_meta(
            field_type,
            "Autokey Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC205 => extension_field_type_meta(
            field_type,
            "Leapseconds Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC206 => extension_field_type_meta(
            field_type,
            "Sign Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC207 => extension_field_type_meta(
            field_type,
            "IFF Identity Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC208 => extension_field_type_meta(
            field_type,
            "GQ Identity Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xC209 => extension_field_type_meta(
            field_type,
            "MV Identity Message Error Response",
            NtpRegistryStatus::Assigned,
            NtpExtensionFieldTypeCategory::Assigned,
        ),
        0xF000..=0xFFFF => NtpRegistryMeta {
            value: field_type.into(),
            label: format!(
                "{} (private-or-experimental)",
                hex16_label("extension-field", field_type)
            ),
            status: NtpRegistryStatus::PrivateOrExperimental,
        }
        .into_extension_field_type(NtpExtensionFieldTypeCategory::PrivateOrExperimental),
        other => NtpRegistryMeta {
            value: other.into(),
            label: hex16_label("extension-field", other),
            status: NtpRegistryStatus::Unassigned,
        }
        .into_extension_field_type(NtpExtensionFieldTypeCategory::UnknownOrUnassigned),
    }
}

/// Return registry metadata for NTS packet extension field types.
pub fn ntp_nts_extension_field_type_meta(field_type: u16) -> NtpRegistryMeta {
    match field_type {
        0x0104 => numeric_meta(field_type, "Unique Identifier", NtpRegistryStatus::Assigned),
        0x0204 => numeric_meta(field_type, "NTS Cookie", NtpRegistryStatus::Assigned),
        0x0304 => numeric_meta(
            field_type,
            "NTS Cookie Placeholder",
            NtpRegistryStatus::Assigned,
        ),
        0x0404 => numeric_meta(
            field_type,
            "NTS Authenticator and Encrypted Extension Fields",
            NtpRegistryStatus::Assigned,
        ),
        0xF000..=0xFFFF => NtpRegistryMeta {
            value: field_type.into(),
            label: format!(
                "{} (private-or-experimental)",
                hex16_label("nts-extension", field_type)
            ),
            status: NtpRegistryStatus::PrivateOrExperimental,
        },
        other => NtpRegistryMeta {
            value: other.into(),
            label: hex16_label("nts-extension", other),
            status: NtpRegistryStatus::Unassigned,
        },
    }
}

pub(super) fn ntp_reference_code_ascii_label(code: [u8; NTP_REFERENCE_ID_LEN]) -> Option<String> {
    let mut len = 0;
    while len < NTP_REFERENCE_ID_LEN && code[len] != 0 {
        let byte = code[len];
        if !(byte.is_ascii_uppercase() || byte.is_ascii_digit()) {
            return None;
        }
        len += 1;
    }

    if len == 0 || code[len..].iter().any(|byte| *byte != 0) {
        return None;
    }

    Some(core::str::from_utf8(&code[..len]).ok()?.to_string())
}

fn numeric_meta(value: impl Into<u32>, label: &str, status: NtpRegistryStatus) -> NtpRegistryMeta {
    NtpRegistryMeta {
        value: value.into(),
        label: label.to_string(),
        status,
    }
}

fn extension_field_type_meta(
    value: u16,
    label: &str,
    status: NtpRegistryStatus,
    category: NtpExtensionFieldTypeCategory,
) -> NtpExtensionFieldType {
    NtpExtensionFieldType {
        value,
        label: label.to_string(),
        category,
        status,
    }
}

impl NtpRegistryMeta {
    fn into_extension_field_type(
        self,
        category: NtpExtensionFieldTypeCategory,
    ) -> NtpExtensionFieldType {
        NtpExtensionFieldType {
            value: self.value as u16,
            label: self.label,
            category,
            status: self.status,
        }
    }
}

fn reference_code_meta(
    code: [u8; NTP_REFERENCE_ID_LEN],
    label: &str,
    status: NtpRegistryStatus,
) -> NtpReferenceCodeMeta {
    NtpReferenceCodeMeta {
        bytes: code,
        label: label.to_string(),
        status,
    }
}

fn known_reference_id_label(code: [u8; NTP_REFERENCE_ID_LEN]) -> Option<&'static str> {
    match code {
        [b'G', b'O', b'E', b'S'] => Some("Geosynchronous Orbit Environment Satellite"),
        [b'G', b'P', b'S', 0] => Some("Global Position System"),
        [b'G', b'A', b'L', 0] => Some("Galileo Positioning System"),
        [b'P', b'P', b'S', 0] => Some("Generic pulse-per-second"),
        [b'I', b'R', b'I', b'G'] => Some("Inter-Range Instrumentation Group"),
        [b'W', b'W', b'V', b'B'] => Some("LF Radio WWVB Ft. Collins, CO 60 kHz"),
        [b'D', b'C', b'F', 0] => Some("LF Radio DCF77 Mainflingen, DE 77.5 kHz"),
        [b'H', b'B', b'G', 0] => Some("LF Radio HBG Prangins, HB 75 kHz"),
        [b'M', b'S', b'F', 0] => Some("LF Radio MSF Anthorn, UK 60 kHz"),
        [b'J', b'J', b'Y', 0] => Some("LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz"),
        [b'L', b'O', b'R', b'C'] => Some("MF Radio LORAN C station, 100 kHz"),
        [b'T', b'D', b'F', 0] => Some("MF Radio Allouis, FR 162 kHz"),
        [b'C', b'H', b'U', 0] => Some("HF Radio CHU Ottawa, Ontario"),
        [b'W', b'W', b'V', 0] => Some("HF Radio WWV Ft. Collins, CO"),
        [b'W', b'W', b'V', b'H'] => Some("HF Radio WWVH Kauai, HI"),
        [b'N', b'I', b'S', b'T'] => Some("NIST telephone modem"),
        [b'A', b'C', b'T', b'S'] => Some("NIST telephone modem"),
        [b'U', b'S', b'N', b'O'] => Some("USNO telephone modem"),
        [b'P', b'T', b'B', 0] => Some("European telephone modem"),
        [b'D', b'F', b'M', 0] => Some("UTC(DFM)"),
        _ => None,
    }
}

fn known_kiss_o_death_code_label(code: [u8; NTP_REFERENCE_ID_LEN]) -> Option<&'static str> {
    match code {
        [b'A', b'C', b'S', b'T'] => Some("The association belongs to a unicast server"),
        [b'A', b'U', b'T', b'H'] => Some("Server authentication failed"),
        [b'A', b'U', b'T', b'O'] => Some("Autokey sequence failed"),
        [b'B', b'C', b'S', b'T'] => Some("The association belongs to a broadcast server"),
        [b'C', b'R', b'Y', b'P'] => Some("Cryptographic authentication or identification failed"),
        [b'D', b'E', b'N', b'Y'] => Some("Access denied by remote server"),
        [b'D', b'R', b'O', b'P'] => Some("Lost peer in symmetric mode"),
        [b'R', b'S', b'T', b'R'] => Some("Access denied due to local policy"),
        [b'I', b'N', b'I', b'T'] => {
            Some("The association has not yet synchronized for the first time")
        }
        [b'M', b'C', b'S', b'T'] => {
            Some("The association belongs to a dynamically discovered server")
        }
        [b'N', b'K', b'E', b'Y'] => Some("No key found or not trusted"),
        [b'N', b'T', b'S', b'N'] => Some("Network Time Security negative acknowledgment"),
        [b'R', b'A', b'T', b'E'] => Some("Rate exceeded"),
        [b'R', b'M', b'O', b'T'] => {
            Some("Alteration of association from a remote host running ntpdc")
        }
        [b'S', b'T', b'E', b'P'] => Some("Step change in system time before resynchronization"),
        _ => None,
    }
}

fn begins_with_private_x(code: [u8; NTP_REFERENCE_ID_LEN]) -> bool {
    code[0] == b'X'
}

fn code_to_u32(code: [u8; NTP_REFERENCE_ID_LEN]) -> u32 {
    u32::from_be_bytes(code)
}

fn hex16_label(prefix: &str, value: u16) -> String {
    format!("{prefix}-0x{value:04X}")
}

fn hex32_label(prefix: &str, value: u32) -> String {
    format!("{prefix}-0x{value:08X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_registry_labels_leap_modes_and_strata() {
        let leap = ntp_leap_indicator_meta(NTP_LI_ALARM_UNSYNCHRONIZED);
        assert_eq!(leap.value, 3);
        assert_eq!(leap.label, "alarm-unsynchronized");
        assert_eq!(leap.status, NtpRegistryStatus::Assigned);

        let mode = ntp_mode_meta(NTP_MODE_CLIENT);
        assert_eq!(mode.value, 3);
        assert_eq!(mode.label, "client");
        assert_eq!(mode.status, NtpRegistryStatus::Assigned);

        let private_mode = ntp_mode_meta(NTP_MODE_PRIVATE);
        assert_eq!(private_mode.label, "private-use");
        assert_eq!(
            private_mode.status,
            NtpRegistryStatus::PrivateOrExperimental
        );

        let unknown_mode = ntp_mode_meta(9);
        assert_eq!(unknown_mode.value, 9);
        assert_eq!(unknown_mode.label, "mode-9");
        assert_eq!(unknown_mode.status, NtpRegistryStatus::Unknown);

        let secondary = ntp_stratum_meta(12);
        assert_eq!(secondary.label, "secondary");
        assert_eq!(secondary.status, NtpRegistryStatus::Assigned);

        let reserved = ntp_stratum_meta(42);
        assert_eq!(reserved.value, 42);
        assert_eq!(reserved.label, "reserved");
        assert_eq!(reserved.status, NtpRegistryStatus::Reserved);
    }

    #[test]
    fn ntp_registry_labels_reference_and_kod_codes() {
        let gps = ntp_reference_id_meta([b'G', b'P', b'S', 0]);
        assert_eq!(gps.bytes, [b'G', b'P', b'S', 0]);
        assert_eq!(gps.label, "Global Position System");
        assert_eq!(gps.status, NtpRegistryStatus::Assigned);

        let private_refid = ntp_reference_id_meta([b'X', b'L', b'A', b'B']);
        assert_eq!(
            private_refid.label,
            "refid-0x584C4142 (private-or-experimental)"
        );
        assert_eq!(
            private_refid.status,
            NtpRegistryStatus::PrivateOrExperimental
        );

        let unknown_refid = ntp_reference_id_meta([0x80, 0, 0, 1]);
        assert_eq!(unknown_refid.label, "refid-0x80000001");
        assert_eq!(unknown_refid.status, NtpRegistryStatus::Unassigned);

        let rate = ntp_kiss_o_death_code_meta([b'R', b'A', b'T', b'E']);
        assert_eq!(rate.label, "Rate exceeded");
        assert_eq!(rate.status, NtpRegistryStatus::Assigned);

        let unknown_kod = ntp_kiss_o_death_code_meta([b'N', b'O', b'P', b'E']);
        assert_eq!(unknown_kod.label, "kod-0x4E4F5045");
        assert_eq!(unknown_kod.status, NtpRegistryStatus::Unassigned);
    }

    #[test]
    fn ntp_stratum_refid_registry_ascii_labels_are_valid_uppercase_codes() {
        let gps = ntp_reference_id_meta([b'G', b'P', b'S', 0]);
        assert_eq!(gps.ascii_label().as_deref(), Some("GPS"));

        let rate = ntp_kiss_o_death_code_meta([b'R', b'A', b'T', b'E']);
        assert_eq!(rate.ascii_label().as_deref(), Some("RATE"));

        assert_eq!(
            ntp_reference_code_ascii_label([b'X', b'L', b'A', b'B']).as_deref(),
            Some("XLAB")
        );
        assert_eq!(ntp_reference_code_ascii_label([0, 0, 0, 0]), None);
        assert_eq!(ntp_reference_code_ascii_label([b'G', 0, b'P', 0]), None);
        assert_eq!(ntp_reference_code_ascii_label([b'g', b'P', b'S', 0]), None);
        assert_eq!(ntp_reference_code_ascii_label([0x80, 0, 0, 1]), None);
    }

    #[test]
    fn ntp_extension_registry_extension_type_labels_categories_and_statuses() {
        let nts_cookie = ntp_extension_type(0x0204);
        assert_eq!(nts_cookie.value, 0x0204);
        assert_eq!(nts_cookie.label, "Autokey Message Request / NTS Cookie");
        assert_eq!(nts_cookie.category, NtpExtensionFieldTypeCategory::Assigned);
        assert_eq!(nts_cookie.status, NtpRegistryStatus::Assigned);
        assert_eq!(
            nts_cookie.registry_meta(),
            ntp_extension_field_type_meta(0x0204)
        );
        assert_eq!(u16::from(nts_cookie.clone()), 0x0204);

        let reserved = ntp_extension_type(0x0302);
        assert_eq!(reserved.label, "Reserved for historic reasons");
        assert_eq!(
            reserved.category,
            NtpExtensionFieldTypeCategory::ObsoleteOrHistoric
        );
        assert_eq!(reserved.status, NtpRegistryStatus::Reserved);

        let checksum = ntp_extension_type(0x2005);
        assert_eq!(checksum.label, "UDP Checksum Complement");
        assert_eq!(checksum.category, NtpExtensionFieldTypeCategory::Assigned);
        assert_eq!(checksum.status, NtpRegistryStatus::Assigned);

        let unknown = ntp_extension_type(0x2222);
        assert_eq!(unknown.value, 0x2222);
        assert_eq!(unknown.label, "extension-field-0x2222");
        assert_eq!(
            unknown.category,
            NtpExtensionFieldTypeCategory::UnknownOrUnassigned
        );
        assert_eq!(unknown.status, NtpRegistryStatus::Unassigned);

        let private = NtpExtensionFieldType::new(0xF123);
        assert_eq!(
            private.label,
            "extension-field-0xF123 (private-or-experimental)"
        );
        assert_eq!(
            private.category,
            NtpExtensionFieldTypeCategory::PrivateOrExperimental
        );
        assert_eq!(private.status, NtpRegistryStatus::PrivateOrExperimental);
        assert_eq!(NtpExtensionFieldTypeCategory::Reserved.label(), "reserved");

        let crypto_nak = NtpExtensionFieldType::from(0x0000);
        assert_eq!(crypto_nak.value(), 0x0000);
        assert_eq!(crypto_nak.wire_value(), 0x0000);
        assert_eq!(crypto_nak.label(), "Crypto-NAK; authentication failure");
        assert_eq!(
            crypto_nak.category(),
            NtpExtensionFieldTypeCategory::Assigned
        );
        assert_eq!(crypto_nak.status(), NtpRegistryStatus::Assigned);
    }

    #[test]
    fn ntp_extension_registry_nts_packet_extension_labels_stay_scoped() {
        let nts_auth = ntp_nts_extension_field_type_meta(0x0404);
        assert_eq!(
            nts_auth.label,
            "NTS Authenticator and Encrypted Extension Fields"
        );
        assert_eq!(nts_auth.status, NtpRegistryStatus::Assigned);

        let unknown_nts = ntp_nts_extension_field_type_meta(0x1111);
        assert_eq!(unknown_nts.label, "nts-extension-0x1111");
        assert_eq!(unknown_nts.status, NtpRegistryStatus::Unassigned);
    }

    #[test]
    fn ntp_autokey_raw_extensions_registry_recognizes_manifest_rows() {
        for field_type in [
            0x0200, 0x0204, 0x0209, 0x8200, 0x8204, 0x8209, 0xC200, 0xC204, 0xC209,
        ] {
            let extension_type = ntp_extension_type(field_type);

            assert!(ntp_extension_field_type_is_autokey_related(field_type));
            assert!(extension_type.is_autokey_related());
            assert_eq!(extension_type.status(), NtpRegistryStatus::Assigned);
            assert_eq!(
                extension_type.category(),
                NtpExtensionFieldTypeCategory::Assigned
            );
        }

        let duplicate = ntp_extension_type(0x0204);
        assert_eq!(duplicate.label(), "Autokey Message Request / NTS Cookie");
        assert!(duplicate.is_autokey_related());
        assert_eq!(
            ntp_nts_extension_field_type_meta(0x0204).label,
            "NTS Cookie"
        );

        for field_type in [0x0104, 0x0304, 0x0404, 0x2005, 0x2222] {
            assert!(!ntp_extension_field_type_is_autokey_related(field_type));
            assert!(!ntp_extension_type(field_type).is_autokey_related());
        }
    }
}
