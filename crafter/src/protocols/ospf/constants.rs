//! OSPFv2 (RFC 2328) wire constants.
//!
//! Codepoints and fixed lengths taken from RFC 2328 (OSPF Version 2). Each
//! constant cites its defining RFC section in a line comment. These values are
//! the codepoints the OSPF builder, decode, and spec steps consume.

// ---------------------------------------------------------------------------
// Version (RFC 2328 §A.3.1)
// ---------------------------------------------------------------------------

/// OSPF protocol version carried in the common header. RFC 2328 §A.3.1.
pub const OSPF_VERSION_2: u8 = 2;

// ---------------------------------------------------------------------------
// Packet types (RFC 2328 §A.3.1)
// ---------------------------------------------------------------------------

/// Hello packet type. RFC 2328 §A.3.1 / §A.3.2.
pub const OSPF_TYPE_HELLO: u8 = 1;
/// Database Description packet type. RFC 2328 §A.3.1 / §A.3.3.
pub const OSPF_TYPE_DATABASE_DESCRIPTION: u8 = 2;
/// Link State Request packet type. RFC 2328 §A.3.1 / §A.3.4.
pub const OSPF_TYPE_LINK_STATE_REQUEST: u8 = 3;
/// Link State Update packet type. RFC 2328 §A.3.1 / §A.3.5.
pub const OSPF_TYPE_LINK_STATE_UPDATE: u8 = 4;
/// Link State Acknowledgment packet type. RFC 2328 §A.3.1 / §A.3.6.
pub const OSPF_TYPE_LINK_STATE_ACK: u8 = 5;

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 2328 §A.3.1)
// ---------------------------------------------------------------------------

/// OSPF common header length, in octets. RFC 2328 §A.3.1.
pub const OSPF_HEADER_LEN: usize = 24;
/// OSPF Authentication field length, in octets. RFC 2328 §A.3.1.
pub const OSPF_AUTH_LEN: usize = 8;

// ---------------------------------------------------------------------------
// Options field bits (RFC 2328 §A.2, extended by RFC 3101, RFC 5250, et al.)
// ---------------------------------------------------------------------------
//
// The OSPFv2 Options field is a single octet that appears in the Hello,
// Database Description, and LSA-header (RFC 2328 §A.4.1) records and advertises
// each router's optional capabilities. The bit values below are the canonical
// definitions consumed everywhere in the OSPF module; the NSSA-LSA P-bit
// (`OSPF_OPTIONS_NP`) is re-exported through `lsa::nssa` for backward
// compatibility.

/// T/MT-bit (0x01) of the OSPFv2 Options field: historical TOS-routing /
/// multi-topology capability (RFC 2328 §A.2; the original RFC 1583 T-bit, later
/// repurposed as the MT-bit by RFC 4915).
pub const OSPF_OPTIONS_MT: u8 = 0x01;
/// E-bit (0x02) of the OSPFv2 Options field: the router accepts and forwards
/// AS-External-LSAs (RFC 2328 §A.2). Cleared inside a stub area.
pub const OSPF_OPTIONS_E: u8 = 0x02;
/// MC-bit (0x04) of the OSPFv2 Options field: the router forwards IP multicast
/// datagrams per the MOSPF specification (RFC 2328 §A.2, RFC 1584).
pub const OSPF_OPTIONS_MC: u8 = 0x04;
/// N/P-bit (0x08) of the OSPFv2 Options field. In a Hello/DD header this is the
/// N-bit signalling NSSA support (RFC 3101 §2.4); in a Type-7 NSSA-LSA header
/// it is the P-bit requesting Type-7-to-Type-5 translation (RFC 3101 §2.5).
pub const OSPF_OPTIONS_NP: u8 = 0x08;
/// L/EA-bit (0x10) of the OSPFv2 Options field: the router supports the
/// link-local signalling / external-attributes extension (RFC 2328 §A.2,
/// RFC 5613 / the historical RFC 1793 EA-bit position).
pub const OSPF_OPTIONS_L: u8 = 0x10;
/// DC-bit (0x20) of the OSPFv2 Options field: the router supports OSPF over
/// demand circuits (RFC 2328 §A.2, RFC 1793).
pub const OSPF_OPTIONS_DC: u8 = 0x20;
/// O-bit (0x40) of the OSPFv2 Options field: the router is opaque-LSA capable
/// (RFC 5250 §2.1; advertised in Database Description packets only).
pub const OSPF_OPTIONS_O: u8 = 0x40;
/// DN-bit (0x80) of the OSPFv2 Options field: the down-bit used for BGP/OSPF VPN
/// loop avoidance (RFC 2328 §A.2 reserved position, RFC 4576).
pub const OSPF_OPTIONS_DN: u8 = 0x80;

// ---------------------------------------------------------------------------
// Authentication types (RFC 2328 §A.3.1, §D)
// ---------------------------------------------------------------------------

/// Null authentication (AuType 0). RFC 2328 §D.1.
pub const OSPF_AUTYPE_NULL: u16 = 0;
/// Simple password authentication (AuType 1). RFC 2328 §D.2.
pub const OSPF_AUTYPE_SIMPLE: u16 = 1;
/// Cryptographic authentication (AuType 2). RFC 2328 §D.3.
pub const OSPF_AUTYPE_CRYPTOGRAPHIC: u16 = 2;

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Short human-readable name for an OSPF packet Type code (RFC 2328 §A.3.1),
/// used by `summary()` and `inspection_fields()`. Unrecognized codes map to
/// `"Unknown"`.
pub fn ospf_type_name(packet_type: u8) -> &'static str {
    match packet_type {
        OSPF_TYPE_HELLO => "Hello",
        OSPF_TYPE_DATABASE_DESCRIPTION => "DBDesc",
        OSPF_TYPE_LINK_STATE_REQUEST => "LSRequest",
        OSPF_TYPE_LINK_STATE_UPDATE => "LSUpdate",
        OSPF_TYPE_LINK_STATE_ACK => "LSAck",
        _ => "Unknown",
    }
}

/// Render the set bits of an OSPFv2 Options octet (RFC 2328 §A.2) as a
/// `|`-joined label list, used by `summary()` and `inspection_fields()`.
///
/// Bits are emitted in ascending bit-value order (`MT|E|MC|NP|L|DC|O|DN`), so a
/// value of `0x42` renders as `"E|O"`. A value with no recognized bits set
/// (including `0x00`) renders as the empty string, letting callers fall back to
/// the raw hex value.
pub fn ospf_options_summary(options: u8) -> String {
    const LABELS: [(u8, &str); 8] = [
        (OSPF_OPTIONS_MT, "MT"),
        (OSPF_OPTIONS_E, "E"),
        (OSPF_OPTIONS_MC, "MC"),
        (OSPF_OPTIONS_NP, "NP"),
        (OSPF_OPTIONS_L, "L"),
        (OSPF_OPTIONS_DC, "DC"),
        (OSPF_OPTIONS_O, "O"),
        (OSPF_OPTIONS_DN, "DN"),
    ];

    LABELS
        .iter()
        .filter(|(bit, _)| options & bit != 0)
        .map(|(_, label)| *label)
        .collect::<Vec<_>>()
        .join("|")
}

/// Short human-readable name for an OSPF Authentication Type (AuType) code
/// (RFC 2328 §A.3.1, §D), used by `inspection_fields()`. Unrecognized codes map
/// to `"Unknown"`.
pub fn ospf_autype_name(autype: u16) -> &'static str {
    match autype {
        OSPF_AUTYPE_NULL => "Null",
        OSPF_AUTYPE_SIMPLE => "Simple",
        OSPF_AUTYPE_CRYPTOGRAPHIC => "Cryptographic",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ospf_options_summary` renders the set OSPFv2 Options bits (RFC 2328
    /// §A.2) as a `|`-joined label list in ascending bit-value order, leaves a
    /// value with no recognized bits (including zero) as the empty string, and
    /// names each individual bit with its canonical label.
    #[test]
    fn ospf_options_summary_renders_set_bits_as_labels() {
        // No bits set (including the all-clear octet) renders empty so callers
        // can fall back to the raw hex value.
        assert_eq!(ospf_options_summary(0x00), "");

        // Each single bit renders its canonical label.
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_MT), "MT");
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_E), "E");
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_MC), "MC");
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_NP), "NP");
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_L), "L");
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_DC), "DC");
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_O), "O");
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_DN), "DN");

        // Multiple bits join in ascending bit-value order regardless of the
        // order the bits were OR-ed together.
        assert_eq!(ospf_options_summary(OSPF_OPTIONS_O | OSPF_OPTIONS_E), "E|O");
        assert_eq!(ospf_options_summary(0xff), "MT|E|MC|NP|L|DC|O|DN");
    }

    /// The OSPFv2 Options bit constants carry the canonical RFC 2328 §A.2 bit
    /// positions, and `OSPF_OPTIONS_NP` is the single 0x08 NSSA bit shared with
    /// the `lsa::nssa` re-export (consolidated to one definition).
    #[test]
    fn ospf_options_bit_values_match_the_rfc() {
        assert_eq!(OSPF_OPTIONS_MT, 0x01);
        assert_eq!(OSPF_OPTIONS_E, 0x02);
        assert_eq!(OSPF_OPTIONS_MC, 0x04);
        assert_eq!(OSPF_OPTIONS_NP, 0x08);
        assert_eq!(OSPF_OPTIONS_L, 0x10);
        assert_eq!(OSPF_OPTIONS_DC, 0x20);
        assert_eq!(OSPF_OPTIONS_O, 0x40);
        assert_eq!(OSPF_OPTIONS_DN, 0x80);

        // The lsa::nssa re-export resolves to the same single definition.
        assert_eq!(
            OSPF_OPTIONS_NP,
            crate::protocols::ospf::lsa::OSPF_OPTIONS_NP
        );
    }
}
