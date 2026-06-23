//! IEEE 802.15.4 MAC Frame Check Sequence (16-bit FCS).
//!
//! Per `.agents/docs/dot15d4-manifest.md` (IEEE Std 802.15.4-2020, Clause
//! 7.2.10), the FCS is a 16-bit ITU-T CRC computed over the MAC header (MHR)
//! and MAC payload, using the generator polynomial
//! x^16 + x^12 + x^5 + 1 (the ITU-T / CRC-CCITT polynomial, 0x1021), and
//! transmitted as the trailing 2 octets of the frame.
//!
//! The 802.15.4 PHY transmits each octet least-significant bit first, so the
//! CRC is computed in its *reflected* form: the polynomial 0x1021 reflected to
//! 0x8408, with reflected input and output and an initial value of 0x0000.
//! This is the CRC-16/CCITT variant the reference backend implements as
//! `Dot15d4FCS`/`makeFCS`; the caller serializes the returned `u16`
//! little-endian (low byte first) as the on-air FCS.

/// Reflected form of the ITU-T / CRC-CCITT generator polynomial 0x1021.
///
/// IEEE Std 802.15.4-2020, Clause 7.2.10; see `.agents/docs/dot15d4-manifest.md`.
const DOT15D4_FCS_POLY_REFLECTED: u16 = 0x8408;

/// Compute the IEEE 802.15.4 16-bit MAC Frame Check Sequence over `bytes`.
///
/// `bytes` is the MAC header followed by the MAC payload (everything that
/// precedes the FCS field). The returned value is the FCS; the caller writes
/// it little-endian (low byte first) as the trailing 2 octets of the frame,
/// per IEEE Std 802.15.4-2020, Clause 7.2.10 (see
/// `.agents/docs/dot15d4-manifest.md`).
///
/// Reflected CRC-16/CCITT: polynomial 0x1021 reflected to 0x8408, initial
/// value 0x0000, reflected input and output, no final XOR.
pub(crate) fn dot15d4_fcs(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ DOT15D4_FCS_POLY_REFLECTED;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot15d4_fcs_ack_frame_matches_reference() {
        // Canonical 802.15.4 Acknowledgment frame: FCF = 0x0200 (Ack, no
        // addressing), sequence number 0x53. The MHR+payload bytes are
        // 02 00 53 and the FCS is 0xD5A6 (serialized on air as A6 D5).
        //
        // Cross-checked against the reference backend's `Dot15d4FCS`/`makeFCS`
        // algorithm, which yields 0xD5A6 for these bytes.
        let mhr_and_payload = [0x02u8, 0x00, 0x53];
        assert_eq!(dot15d4_fcs(&mhr_and_payload), 0xD5A6);
    }

    #[test]
    fn dot15d4_fcs_data_header_matches_reference() {
        // A data frame header: FCF = 0x8841 (Data frame, PAN ID compression,
        // dest short address present), sequence number 0x01, dest PAN ID
        // 0xFFFF, dest short address 0xFFFF -> bytes 41 88 01 FF FF FF FF.
        // The reference `makeFCS` yields 0x84F4 for these bytes.
        let mhr = [0x41u8, 0x88, 0x01, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(dot15d4_fcs(&mhr), 0x84F4);
    }

    #[test]
    fn dot15d4_fcs_empty_input_is_zero() {
        // Reflected CRC-16/CCITT with init 0x0000 and no XOR-out yields 0x0000
        // over an empty input.
        assert_eq!(dot15d4_fcs(&[]), 0x0000);
    }

    #[test]
    fn dot15d4_fcs_appended_fcs_self_checks() {
        // A frame with its correct FCS appended (little-endian) re-CRCs to the
        // CRC-16/CCITT residue 0x0000, confirming the FCS validates the whole
        // frame as on the wire.
        let mhr_and_payload = [0x02u8, 0x00, 0x53];
        let fcs = dot15d4_fcs(&mhr_and_payload);
        let mut full = mhr_and_payload.to_vec();
        full.extend_from_slice(&fcs.to_le_bytes());
        assert_eq!(dot15d4_fcs(&full), 0x0000);
    }
}
