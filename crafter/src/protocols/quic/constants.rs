//! Stable QUIC constants.
//!
//! These version constants are the default-eligible QUIC Versions rows recorded
//! in `.agents/docs/quic-codepoints.md` and
//! `.agents/docs/quic-version-extension-matrix.md`.

/// Reserved QUIC version value used by Version Negotiation packets.
pub const QUIC_VERSION_NEGOTIATION: u32 = 0x0000_0000;

/// QUIC version 1, defined by RFC 9000.
pub const QUIC_VERSION_1: u32 = 0x0000_0001;

/// QUIC version 2, defined by RFC 9369.
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;

/// Google QUIC Q043 provisional experiment version.
pub const QUIC_VERSION_GOOGLE_Q043: u32 = 0x5130_3433;
/// Google QUIC Q046 provisional experiment version.
pub const QUIC_VERSION_GOOGLE_Q046: u32 = 0x5130_3436;
/// Google QUIC Q050 provisional experiment version.
pub const QUIC_VERSION_GOOGLE_Q050: u32 = 0x5130_3530;
/// QUIC version 2 draft codepoint retained as a non-default provisional row.
pub const QUIC_VERSION_2_DRAFT: u32 = 0x709a_50c4;
/// SCONE even-signal provisional draft version.
pub const QUIC_VERSION_SCONE_EVEN_SIGNAL: u32 = 0x6f7d_c0fd;
/// SCONE odd-signal provisional draft version.
pub const QUIC_VERSION_SCONE_ODD_SIGNAL: u32 = 0xef7d_c0fd;

/// QUIC version registry status used for labels and conservative defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicVersionStatus {
    /// Reserved value used only by Version Negotiation packets.
    VersionNegotiation,
    /// Permanent IETF version selected for default packet support.
    Permanent,
    /// Version reserved by the QUIC grease pattern.
    ReservedGrease,
    /// Provisional IANA row, exposed for inspection but not default behavior.
    Provisional,
    /// Unknown numeric value.
    Unknown,
}

/// Return true when a version follows the reserved grease pattern from the
/// IANA QUIC Versions registry: `(value & 0x0f0f0f0f) == 0x0a0a0a0a`.
pub const fn is_quic_grease_version(version: u32) -> bool {
    (version & 0x0f0f_0f0f) == 0x0a0a_0a0a
}

/// Return true when this version is one of the default-eligible permanent QUIC
/// transport versions implemented by this packet layer.
pub const fn is_quic_default_version(version: u32) -> bool {
    matches!(version, QUIC_VERSION_1 | QUIC_VERSION_2)
}

/// Classify a QUIC version value using the source-backed registry notes.
pub const fn quic_version_status(version: u32) -> QuicVersionStatus {
    match version {
        QUIC_VERSION_NEGOTIATION => QuicVersionStatus::VersionNegotiation,
        QUIC_VERSION_1 | QUIC_VERSION_2 => QuicVersionStatus::Permanent,
        QUIC_VERSION_GOOGLE_Q043
        | QUIC_VERSION_GOOGLE_Q046
        | QUIC_VERSION_GOOGLE_Q050
        | QUIC_VERSION_2_DRAFT
        | QUIC_VERSION_SCONE_EVEN_SIGNAL
        | QUIC_VERSION_SCONE_ODD_SIGNAL => QuicVersionStatus::Provisional,
        _ if is_quic_grease_version(version) => QuicVersionStatus::ReservedGrease,
        _ => QuicVersionStatus::Unknown,
    }
}

/// Stable human-readable name for known QUIC version rows.
pub const fn quic_version_name(version: u32) -> Option<&'static str> {
    match version {
        QUIC_VERSION_NEGOTIATION => Some("Version Negotiation"),
        QUIC_VERSION_1 => Some("QUIC v1"),
        QUIC_VERSION_2 => Some("QUIC v2"),
        QUIC_VERSION_GOOGLE_Q043 => Some("Google QUIC Q043"),
        QUIC_VERSION_GOOGLE_Q046 => Some("Google QUIC Q046"),
        QUIC_VERSION_GOOGLE_Q050 => Some("Google QUIC Q050"),
        QUIC_VERSION_2_DRAFT => Some("QUIC v2 draft"),
        QUIC_VERSION_SCONE_EVEN_SIGNAL => Some("SCONE even signal"),
        QUIC_VERSION_SCONE_ODD_SIGNAL => Some("SCONE odd signal"),
        _ => None,
    }
}

/// Human-readable QUIC version label that preserves unknown values as numeric
/// hex strings.
pub fn quic_version_label(version: u32) -> String {
    if let Some(name) = quic_version_name(version) {
        return name.to_string();
    }
    if is_quic_grease_version(version) {
        return format!("reserved grease version 0x{version:08x}");
    }
    format!("unknown version 0x{version:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_version_constants_classify_default_versions() {
        assert_eq!(
            quic_version_status(QUIC_VERSION_NEGOTIATION),
            QuicVersionStatus::VersionNegotiation
        );
        assert_eq!(
            quic_version_status(QUIC_VERSION_1),
            QuicVersionStatus::Permanent
        );
        assert_eq!(
            quic_version_status(QUIC_VERSION_2),
            QuicVersionStatus::Permanent
        );
        assert!(is_quic_default_version(QUIC_VERSION_1));
        assert!(is_quic_default_version(QUIC_VERSION_2));
        assert!(!is_quic_default_version(QUIC_VERSION_NEGOTIATION));
    }

    #[test]
    fn quic_version_constants_classify_provisional_rows() {
        for version in [
            QUIC_VERSION_GOOGLE_Q043,
            QUIC_VERSION_GOOGLE_Q046,
            QUIC_VERSION_GOOGLE_Q050,
            QUIC_VERSION_2_DRAFT,
            QUIC_VERSION_SCONE_EVEN_SIGNAL,
            QUIC_VERSION_SCONE_ODD_SIGNAL,
        ] {
            assert_eq!(quic_version_status(version), QuicVersionStatus::Provisional);
            assert!(!is_quic_default_version(version));
        }
    }

    #[test]
    fn quic_version_constants_classify_grease_and_unknown_values() {
        assert!(is_quic_grease_version(0x0a0a_0a0a));
        assert!(is_quic_grease_version(0x1a2a_3a4a));
        assert_eq!(
            quic_version_status(0x0a0a_0a0a),
            QuicVersionStatus::ReservedGrease
        );
        assert_eq!(quic_version_status(0xface_feed), QuicVersionStatus::Unknown);
    }

    #[test]
    fn quic_version_constants_labels_known_and_numeric_values() {
        assert_eq!(quic_version_name(QUIC_VERSION_1), Some("QUIC v1"));
        assert_eq!(quic_version_label(QUIC_VERSION_2), "QUIC v2");
        assert_eq!(
            quic_version_label(0x0a0a_0a0a),
            "reserved grease version 0x0a0a0a0a"
        );
        assert_eq!(
            quic_version_label(0xface_feed),
            "unknown version 0xfacefeed"
        );
    }
}
