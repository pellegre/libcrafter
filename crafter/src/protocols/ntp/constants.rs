//! NTP constants and wire-level codepoints.
//!
//! Values are sourced from `.agents/docs/ntp-rfc-manifest.md`,
//! `.agents/docs/ntp-wire-grammar.md`, and `.agents/docs/ntp-codepoints.md`.
//! These constants describe packet bytes only; they do not authorize live
//! traffic or add a clock synchronization workflow.

/// IANA service name for Network Time Protocol.
pub const NTP_SERVICE_NAME: &str = "ntp";

/// UDP service port for NTP. IANA ntp/udp service registry row and RFC 5905.
pub const NTP_PORT: u16 = 123;
/// Explicit UDP alias for the NTP service port.
pub const NTP_UDP_PORT: u16 = NTP_PORT;
/// IANA ntp/tcp service registry row. This is not a TCP stream parser binding.
pub const NTP_TCP_PORT: u16 = 123;

/// Fixed NTP header length, in octets. RFC 5905 section 7.3.
pub const NTP_FIXED_HEADER_LEN: usize = 48;
/// NTP timestamp field length, in octets. RFC 5905 section 6.
pub const NTP_TIMESTAMP_LEN: usize = 8;
/// NTP short-format field length, in octets. RFC 5905 section 6.
pub const NTP_SHORT_FORMAT_LEN: usize = 4;
/// NTP reference identifier length, in octets. RFC 5905 section 7.3.
pub const NTP_REFERENCE_ID_LEN: usize = 4;
/// RFC 7822 extension-field envelope header length, in octets.
pub const NTP_EXTENSION_FIELD_HEADER_LEN: usize = 4;
/// Minimum structurally valid RFC 7822 extension-field length, in octets.
pub const NTP_EXTENSION_FIELD_MIN_LEN: usize = 16;
/// Minimum final extension-field length when no MAC follows, in octets.
pub const NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN: usize = 28;
/// Legacy MAC key identifier length, in octets. RFC 5905 section 7.3.
pub const NTP_LEGACY_MAC_KEY_ID_LEN: usize = 4;

/// Wire mask for the leap-indicator bits in the first NTP octet.
pub const NTP_FIRST_OCTET_LI_MASK: u8 = 0b1100_0000;
/// Wire mask for the version bits in the first NTP octet.
pub const NTP_FIRST_OCTET_VERSION_MASK: u8 = 0b0011_1000;
/// Wire mask for the mode bits in the first NTP octet.
pub const NTP_FIRST_OCTET_MODE_MASK: u8 = 0b0000_0111;
/// Shift for the leap-indicator value in the first NTP octet.
pub const NTP_FIRST_OCTET_LI_SHIFT: u8 = 6;
/// Shift for the version value in the first NTP octet.
pub const NTP_FIRST_OCTET_VERSION_SHIFT: u8 = 3;
/// Shift for the mode value in the first NTP octet.
pub const NTP_FIRST_OCTET_MODE_SHIFT: u8 = 0;
/// Unshifted leap-indicator value mask.
pub const NTP_LI_VALUE_MASK: u8 = 0x03;
/// Unshifted version value mask.
pub const NTP_VERSION_VALUE_MASK: u8 = 0x07;
/// Unshifted mode value mask.
pub const NTP_MODE_VALUE_MASK: u8 = 0x07;

/// Leap Indicator: no warning.
pub const NTP_LI_NO_WARNING: u8 = 0;
/// Leap Indicator: last minute of the day has 61 seconds.
pub const NTP_LI_LAST_MINUTE_61_SECONDS: u8 = 1;
/// Leap Indicator: last minute of the day has 59 seconds.
pub const NTP_LI_LAST_MINUTE_59_SECONDS: u8 = 2;
/// Leap Indicator: alarm condition / clock unsynchronized.
pub const NTP_LI_ALARM_UNSYNCHRONIZED: u8 = 3;

/// Lowest representable NTP version value in the first-octet bit field.
pub const NTP_VERSION_MIN: u8 = 0;
/// NTP version 1 value, preserved for legacy-shaped packets.
pub const NTP_VERSION_1: u8 = 1;
/// NTP version 2 value, preserved for legacy-shaped packets.
pub const NTP_VERSION_2: u8 = 2;
/// NTP version 3 value, preserved for NTPv3/SNTP-compatible packets.
pub const NTP_VERSION_3: u8 = 3;
/// NTP version 4 value from RFC 5905.
pub const NTP_VERSION_4: u8 = 4;
/// Current default NTP packet version.
pub const NTP_VERSION_CURRENT: u8 = NTP_VERSION_4;
/// Highest representable NTP version value in the first-octet bit field.
pub const NTP_VERSION_MAX: u8 = 7;

/// Reserved NTP mode value.
pub const NTP_MODE_RESERVED: u8 = 0;
/// Symmetric active NTP mode value.
pub const NTP_MODE_SYMMETRIC_ACTIVE: u8 = 1;
/// Symmetric passive NTP mode value.
pub const NTP_MODE_SYMMETRIC_PASSIVE: u8 = 2;
/// Client NTP mode value.
pub const NTP_MODE_CLIENT: u8 = 3;
/// Server NTP mode value.
pub const NTP_MODE_SERVER: u8 = 4;
/// Broadcast NTP mode value.
pub const NTP_MODE_BROADCAST: u8 = 5;
/// Control NTP mode value.
pub const NTP_MODE_CONTROL: u8 = 6;
/// Private-use NTP mode value.
pub const NTP_MODE_PRIVATE: u8 = 7;

/// Stratum 0: unspecified or invalid, including Kiss-o'-Death packets.
pub const NTP_STRATUM_UNSPECIFIED: u8 = 0;
/// Stratum 1: primary server or reference clock.
pub const NTP_STRATUM_PRIMARY: u8 = 1;
/// First secondary-server stratum value.
pub const NTP_STRATUM_SECONDARY_FIRST: u8 = 2;
/// Last secondary-server stratum value.
pub const NTP_STRATUM_SECONDARY_LAST: u8 = 15;
/// Stratum 16: unsynchronized.
pub const NTP_STRATUM_UNSYNCHRONIZED: u8 = 16;
/// First RFC 5905 reserved stratum value.
pub const NTP_STRATUM_RESERVED_FIRST: u8 = 17;
/// Last RFC 5905 reserved stratum value.
pub const NTP_STRATUM_RESERVED_LAST: u8 = u8::MAX;

/// Documentation-safe default Leap Indicator.
pub const NTP_DEFAULT_LEAP_INDICATOR: u8 = NTP_LI_NO_WARNING;
/// Documentation-safe default version.
pub const NTP_DEFAULT_VERSION: u8 = NTP_VERSION_CURRENT;
/// Documentation-safe default mode for constructed NTP packets.
pub const NTP_DEFAULT_MODE: u8 = NTP_MODE_CLIENT;
/// Documentation-safe default stratum for client-shaped packets.
pub const NTP_DEFAULT_STRATUM: u8 = NTP_STRATUM_UNSPECIFIED;
/// Documentation-safe default Poll exponent.
pub const NTP_DEFAULT_POLL: i8 = 0;
/// Documentation-safe default Precision exponent.
pub const NTP_DEFAULT_PRECISION: i8 = 0;
/// Documentation-safe default Root Delay short-format value.
pub const NTP_DEFAULT_ROOT_DELAY: u32 = 0;
/// Documentation-safe default Root Dispersion short-format value.
pub const NTP_DEFAULT_ROOT_DISPERSION: u32 = 0;
/// Documentation-safe default Reference ID bytes.
pub const NTP_DEFAULT_REFERENCE_ID: [u8; NTP_REFERENCE_ID_LEN] = [0; NTP_REFERENCE_ID_LEN];
/// Documentation-safe default timestamp value.
pub const NTP_DEFAULT_TIMESTAMP: u64 = 0;
/// Documentation-safe default Reference Timestamp.
pub const NTP_DEFAULT_REFERENCE_TIMESTAMP: u64 = NTP_DEFAULT_TIMESTAMP;
/// Documentation-safe default Origin Timestamp.
pub const NTP_DEFAULT_ORIGIN_TIMESTAMP: u64 = NTP_DEFAULT_TIMESTAMP;
/// Documentation-safe default Receive Timestamp.
pub const NTP_DEFAULT_RECEIVE_TIMESTAMP: u64 = NTP_DEFAULT_TIMESTAMP;
/// Documentation-safe default Transmit Timestamp.
pub const NTP_DEFAULT_TRANSMIT_TIMESTAMP: u64 = NTP_DEFAULT_TIMESTAMP;
/// Packed first octet for the documentation-safe default NTP client shape.
pub const NTP_DEFAULT_FIRST_OCTET: u8 = (NTP_DEFAULT_LEAP_INDICATOR << NTP_FIRST_OCTET_LI_SHIFT)
    | (NTP_DEFAULT_VERSION << NTP_FIRST_OCTET_VERSION_SHIFT)
    | (NTP_DEFAULT_MODE << NTP_FIRST_OCTET_MODE_SHIFT);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_constants_match_source_backed_lengths_and_ports() {
        assert_eq!(NTP_SERVICE_NAME, "ntp");
        assert_eq!(NTP_PORT, 123);
        assert_eq!(NTP_UDP_PORT, NTP_PORT);
        assert_eq!(NTP_TCP_PORT, 123);

        assert_eq!(NTP_FIXED_HEADER_LEN, 48);
        assert_eq!(NTP_TIMESTAMP_LEN, 8);
        assert_eq!(NTP_SHORT_FORMAT_LEN, 4);
        assert_eq!(NTP_REFERENCE_ID_LEN, 4);
        assert_eq!(NTP_EXTENSION_FIELD_HEADER_LEN, 4);
        assert_eq!(NTP_EXTENSION_FIELD_MIN_LEN, 16);
        assert_eq!(NTP_EXTENSION_FIELD_MIN_LAST_WITHOUT_MAC_LEN, 28);
        assert_eq!(NTP_LEGACY_MAC_KEY_ID_LEN, 4);
    }

    #[test]
    fn ntp_constants_cover_first_octet_value_spaces() {
        assert_eq!(NTP_FIRST_OCTET_LI_MASK, 0xc0);
        assert_eq!(NTP_FIRST_OCTET_VERSION_MASK, 0x38);
        assert_eq!(NTP_FIRST_OCTET_MODE_MASK, 0x07);
        assert_eq!(NTP_FIRST_OCTET_LI_SHIFT, 6);
        assert_eq!(NTP_FIRST_OCTET_VERSION_SHIFT, 3);
        assert_eq!(NTP_FIRST_OCTET_MODE_SHIFT, 0);
        assert_eq!(NTP_LI_VALUE_MASK, 0x03);
        assert_eq!(NTP_VERSION_VALUE_MASK, 0x07);
        assert_eq!(NTP_MODE_VALUE_MASK, 0x07);

        assert_eq!(NTP_LI_NO_WARNING, 0);
        assert_eq!(NTP_LI_LAST_MINUTE_61_SECONDS, 1);
        assert_eq!(NTP_LI_LAST_MINUTE_59_SECONDS, 2);
        assert_eq!(NTP_LI_ALARM_UNSYNCHRONIZED, 3);

        assert_eq!(NTP_VERSION_MIN, 0);
        assert_eq!(NTP_VERSION_1, 1);
        assert_eq!(NTP_VERSION_2, 2);
        assert_eq!(NTP_VERSION_3, 3);
        assert_eq!(NTP_VERSION_4, 4);
        assert_eq!(NTP_VERSION_CURRENT, NTP_VERSION_4);
        assert_eq!(NTP_VERSION_MAX, 7);

        assert_eq!(NTP_MODE_RESERVED, 0);
        assert_eq!(NTP_MODE_SYMMETRIC_ACTIVE, 1);
        assert_eq!(NTP_MODE_SYMMETRIC_PASSIVE, 2);
        assert_eq!(NTP_MODE_CLIENT, 3);
        assert_eq!(NTP_MODE_SERVER, 4);
        assert_eq!(NTP_MODE_BROADCAST, 5);
        assert_eq!(NTP_MODE_CONTROL, 6);
        assert_eq!(NTP_MODE_PRIVATE, 7);
    }

    #[test]
    fn ntp_constants_default_to_documentation_safe_client_shape() {
        assert_eq!(NTP_STRATUM_UNSPECIFIED, 0);
        assert_eq!(NTP_STRATUM_PRIMARY, 1);
        assert_eq!(NTP_STRATUM_SECONDARY_FIRST, 2);
        assert_eq!(NTP_STRATUM_SECONDARY_LAST, 15);
        assert_eq!(NTP_STRATUM_UNSYNCHRONIZED, 16);
        assert_eq!(NTP_STRATUM_RESERVED_FIRST, 17);
        assert_eq!(NTP_STRATUM_RESERVED_LAST, 255);

        assert_eq!(NTP_DEFAULT_LEAP_INDICATOR, NTP_LI_NO_WARNING);
        assert_eq!(NTP_DEFAULT_VERSION, NTP_VERSION_CURRENT);
        assert_eq!(NTP_DEFAULT_MODE, NTP_MODE_CLIENT);
        assert_eq!(NTP_DEFAULT_STRATUM, NTP_STRATUM_UNSPECIFIED);
        assert_eq!(NTP_DEFAULT_POLL, 0);
        assert_eq!(NTP_DEFAULT_PRECISION, 0);
        assert_eq!(NTP_DEFAULT_ROOT_DELAY, 0);
        assert_eq!(NTP_DEFAULT_ROOT_DISPERSION, 0);
        assert_eq!(NTP_DEFAULT_REFERENCE_ID, [0; 4]);
        assert_eq!(NTP_DEFAULT_TIMESTAMP, 0);
        assert_eq!(NTP_DEFAULT_REFERENCE_TIMESTAMP, 0);
        assert_eq!(NTP_DEFAULT_ORIGIN_TIMESTAMP, 0);
        assert_eq!(NTP_DEFAULT_RECEIVE_TIMESTAMP, 0);
        assert_eq!(NTP_DEFAULT_TRANSMIT_TIMESTAMP, 0);
        assert_eq!(NTP_DEFAULT_FIRST_OCTET, 0x23);
    }
}
