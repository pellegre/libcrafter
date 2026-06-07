//! CCMP protected-frame parsing and decrypt helpers.
//!
//! Later steps will construct nonces and AAD, then authenticate/decrypt
//! protected payloads here.

use super::metadata::WpaKeyKind;
use crate::{CrafterError, Dot11, MacAddr, Result};

const CCMP_HEADER_LEN: usize = 8;
const CCMP_EXTENDED_IV_BIT: u8 = 0x20;
const CCMP_KEY_ID_SHIFT: u8 = 6;
const CCMP_KEY_ID_MASK: u8 = 0x03;

/// Parsed 8-octet CCMP header plus the encrypted payload that follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CcmpHeader<'a> {
    header: [u8; CCMP_HEADER_LEN],
    encrypted_payload: &'a [u8],
}

impl<'a> CcmpHeader<'a> {
    /// Parse a CCMP-protected body.
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < CCMP_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ccmp.header",
                CCMP_HEADER_LEN,
                bytes.len(),
            ));
        }

        let mut header = [0u8; CCMP_HEADER_LEN];
        header.copy_from_slice(&bytes[..CCMP_HEADER_LEN]);
        let parsed = Self {
            header,
            encrypted_payload: &bytes[CCMP_HEADER_LEN..],
        };

        if !parsed.extended_iv() {
            return Err(CrafterError::invalid_field_value(
                "ccmp.extended_iv",
                "extended IV bit must be set",
            ));
        }

        Ok(parsed)
    }

    /// Return the raw 8-octet CCMP header.
    pub(crate) const fn header_bytes(&self) -> [u8; CCMP_HEADER_LEN] {
        self.header
    }

    /// Return the 48-bit packet number as a monotonic integer.
    pub(crate) fn packet_number(&self) -> u64 {
        u64::from(self.header[0])
            | (u64::from(self.header[1]) << 8)
            | (u64::from(self.header[4]) << 16)
            | (u64::from(self.header[5]) << 24)
            | (u64::from(self.header[6]) << 32)
            | (u64::from(self.header[7]) << 40)
    }

    /// Return the packet-number octets in CCMP nonce order, PN5 through PN0.
    pub(crate) const fn packet_number_nonce_bytes(&self) -> [u8; 6] {
        [
            self.header[7],
            self.header[6],
            self.header[5],
            self.header[4],
            self.header[1],
            self.header[0],
        ]
    }

    /// Return the two-bit key id from the CCMP key-id octet.
    pub(crate) const fn key_id(&self) -> u8 {
        (self.header[3] >> CCMP_KEY_ID_SHIFT) & CCMP_KEY_ID_MASK
    }

    /// Return true when the CCMP header advertises the extended-IV format.
    pub(crate) const fn extended_iv(&self) -> bool {
        self.header[3] & CCMP_EXTENDED_IV_BIT != 0
    }

    /// Borrow the encrypted payload bytes that follow the CCMP header.
    pub(crate) const fn encrypted_payload(&self) -> &'a [u8] {
        self.encrypted_payload
    }

    /// Classify the key type needed to decrypt this frame.
    pub(crate) fn key_kind_for_dot11(&self, dot11: &Dot11) -> Option<WpaKeyKind> {
        key_kind_for_dot11(dot11)
    }
}

/// Classify the key type needed for a protected data frame.
pub(crate) fn key_kind_for_dot11(dot11: &Dot11) -> Option<WpaKeyKind> {
    dot11.destination().map(key_kind_for_destination)
}

/// Classify pairwise or group key use from the logical frame destination.
pub(crate) const fn key_kind_for_destination(destination: MacAddr) -> WpaKeyKind {
    if destination.is_multicast() {
        WpaKeyKind::Group
    } else {
        WpaKeyKind::Pairwise
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dot11, MacAddr};

    fn ccmp_body(key_id: u8, pn: [u8; 6], encrypted_payload: &[u8]) -> Vec<u8> {
        let mut body = vec![
            pn[0],
            pn[1],
            0x00,
            CCMP_EXTENDED_IV_BIT | ((key_id & CCMP_KEY_ID_MASK) << CCMP_KEY_ID_SHIFT),
            pn[2],
            pn[3],
            pn[4],
            pn[5],
        ];
        body.extend_from_slice(encrypted_payload);
        body
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x11, 0x00, last])
    }

    #[test]
    fn header_rejects_short_encrypted_bodies() {
        let error = CcmpHeader::parse(&[0; CCMP_HEADER_LEN - 1]).unwrap_err();

        assert_eq!(
            error,
            CrafterError::BufferTooShort {
                context: "ccmp.header",
                required: CCMP_HEADER_LEN,
                available: CCMP_HEADER_LEN - 1,
            }
        );
    }

    #[test]
    fn header_rejects_missing_extended_iv_bit() {
        let body = [0x01, 0x02, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06];
        let error = CcmpHeader::parse(&body).unwrap_err();

        assert_eq!(
            error,
            CrafterError::InvalidFieldValue {
                field: "ccmp.extended_iv",
                reason: "extended IV bit must be set",
            }
        );
    }

    #[test]
    fn header_extracts_key_id_and_payload() {
        let body = ccmp_body(2, [1, 2, 3, 4, 5, 6], &[0xaa, 0xbb, 0xcc]);
        let header = CcmpHeader::parse(&body).unwrap();

        assert_eq!(header.key_id(), 2);
        assert!(header.extended_iv());
        assert_eq!(header.header_bytes(), [1, 2, 0, 0xa0, 3, 4, 5, 6]);
        assert_eq!(header.encrypted_payload(), [0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn header_orders_packet_number_from_low_to_high_octets() {
        let low_body = ccmp_body(0, [0x01, 0, 0, 0, 0, 0], &[]);
        let high_body = ccmp_body(0, [0, 0x01, 0, 0, 0, 0], &[]);
        let mixed_body = ccmp_body(0, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], &[]);
        let low = CcmpHeader::parse(&low_body).unwrap();
        let high = CcmpHeader::parse(&high_body).unwrap();
        let mixed = CcmpHeader::parse(&mixed_body).unwrap();

        assert!(low.packet_number() < high.packet_number());
        assert_eq!(high.packet_number(), 0x0100);
        assert_eq!(mixed.packet_number(), 0x0605_0403_0201);
        assert_eq!(
            mixed.packet_number_nonce_bytes(),
            [0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn header_classifies_unicast_and_group_destinations() {
        let body = ccmp_body(0, [1, 0, 0, 0, 0, 0], &[0]);
        let header = CcmpHeader::parse(&body).unwrap();
        let bssid = mac(1);
        let station = mac(2);
        let peer = mac(3);
        let group = MacAddr::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);

        let unicast = Dot11::data().addr1(peer).addr2(station).addr3(bssid);
        assert_eq!(
            header.key_kind_for_dot11(&unicast),
            Some(WpaKeyKind::Pairwise)
        );

        let group_from_ap = Dot11::data()
            .frame_control(Dot11::data().frame_control_value().with_from_ds(true))
            .addr1(group)
            .addr2(bssid)
            .addr3(station);
        assert_eq!(
            header.key_kind_for_dot11(&group_from_ap),
            Some(WpaKeyKind::Group)
        );

        let group_to_ds = Dot11::data()
            .frame_control(Dot11::data().frame_control_value().with_to_ds(true))
            .addr1(bssid)
            .addr2(station)
            .addr3(MacAddr::BROADCAST);
        assert_eq!(
            header.key_kind_for_dot11(&group_to_ds),
            Some(WpaKeyKind::Group)
        );
    }
}
