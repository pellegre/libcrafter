//! NTP time and fixed-point field helpers.

/// NTP short-format 16.16 fixed-point field used by root delay and root dispersion.
///
/// The helper preserves the raw 32-bit wire value. Human-readable conversion is
/// available through [`NtpShortFormat::as_seconds`] when inspection code wants it,
/// but packet construction and decoding can work entirely from raw bits.
pub type NtpShortFormat = super::message::NtpShortFormat;

#[cfg(test)]
mod tests {
    use super::NtpShortFormat;

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
}
