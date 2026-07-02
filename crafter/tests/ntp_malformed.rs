use crafter::prelude::*;

#[test]
fn ntp_short_header_reports_buffer_too_short_for_every_truncated_length() {
    for len in 0..NTP_FIXED_HEADER_LEN {
        let payload = vec![0; len];

        match Ntp::decode(&payload).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ntp.header");
                assert_eq!(required, NTP_FIXED_HEADER_LEN);
                assert_eq!(available, len);
            }
            other => panic!("length {len} expected BufferTooShort, got {other:?}"),
        }
    }
}
