//! NTP time and fixed-point field helpers.

/// NTP short-format 16.16 fixed-point field used by root delay and root dispersion.
///
/// The helper preserves the raw 32-bit wire value. Human-readable conversion is
/// available through [`NtpShortFormat::as_seconds`] when inspection code wants it,
/// but packet construction and decoding can work entirely from raw bits.
pub type NtpShortFormat = super::message::NtpShortFormat;

/// NTP 64-bit timestamp field.
///
/// The helper preserves the raw seconds and fractional halves from the wire.
/// Era interpretation depends on caller context, so conversion to civil time is
/// display/helper behavior rather than a reason for packet decode rejection.
pub type NtpTimestamp = super::message::NtpTimestamp;

impl NtpTimestamp {
    /// Build the all-zero unspecified timestamp value.
    pub const fn zero() -> Self {
        Self::from_raw(0)
    }
}

#[cfg(test)]
mod tests {
    use super::{NtpShortFormat, NtpTimestamp};

    #[test]
    fn ntp_fixed_point_short_format_preserves_raw_wire_value() {
        let value = NtpShortFormat::from_raw(0x0001_8000);

        assert_eq!(value.raw(), 0x0001_8000);
        assert_eq!(value.integer(), 1);
        assert_eq!(value.fraction(), 0x8000);
    }

    #[test]
    fn ntp_fixed_point_short_format_supports_optional_seconds_view() {
        let value = NtpShortFormat::from_parts(2, 0x4000);

        assert_eq!(value.raw(), 0x0002_4000);
        assert_eq!(value.as_seconds(), 2.25);
    }

    #[test]
    fn ntp_timestamp_preserves_raw_wire_value() {
        let value = NtpTimestamp::from_raw(0x83aa_7e80_8000_0000);

        assert_eq!(value.raw(), 0x83aa_7e80_8000_0000);
        assert_eq!(value.seconds(), 0x83aa_7e80);
        assert_eq!(value.fraction(), 0x8000_0000);
    }

    #[test]
    fn ntp_timestamp_zero_constructor_is_unspecified_value() {
        let value = NtpTimestamp::zero();

        assert_eq!(value.raw(), 0);
        assert_eq!(value.seconds(), 0);
        assert_eq!(value.fraction(), 0);
        assert!(value.is_zero());
    }

    #[test]
    fn ntp_timestamp_seconds_view_is_helper_behavior() {
        let value = NtpTimestamp::from_parts(1, 0x8000_0000);

        assert_eq!(value.raw(), 0x0000_0001_8000_0000);
        assert_eq!(value.as_seconds(), 1.5);
    }
}
