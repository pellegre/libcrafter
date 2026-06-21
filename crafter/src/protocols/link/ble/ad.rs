//! GAP Advertising Data structures.

use crate::error::{CrafterError, Result};

use super::consts::{
    AD_COMPLETE_16_BIT_SERVICE_UUIDS, AD_COMPLETE_LOCAL_NAME, AD_FLAGS,
    AD_INCOMPLETE_16_BIT_SERVICE_UUIDS, AD_SHORTENED_LOCAL_NAME,
};

/// Flags AD structure bit values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BleAdvFlags;

impl BleAdvFlags {
    pub const LE_LIMITED_DISC: u8 = 0x01;
    pub const LE_GENERAL_DISC: u8 = 0x02;
    pub const BR_EDR_NOT_SUPPORTED: u8 = 0x04;
    pub const GENERAL_DISC: u8 = Self::LE_GENERAL_DISC | Self::BR_EDR_NOT_SUPPORTED;
}

/// One GAP Advertising Data length/type/value structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdStructure {
    pub ad_type: u8,
    pub data: Vec<u8>,
    pub length_override: Option<u8>,
}

impl AdStructure {
    pub fn new(ad_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            ad_type,
            data: data.into(),
            length_override: None,
        }
    }

    pub fn raw(ad_type: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::new(ad_type, data)
    }

    pub fn flags(value: u8) -> Self {
        Self::new(AD_FLAGS, [value])
    }

    pub fn flags_general_disc() -> Self {
        Self::flags(BleAdvFlags::GENERAL_DISC)
    }

    pub fn complete_local_name(name: &str) -> Self {
        Self::new(AD_COMPLETE_LOCAL_NAME, name.as_bytes())
    }

    pub fn shortened_local_name(name: &str) -> Self {
        Self::new(AD_SHORTENED_LOCAL_NAME, name.as_bytes())
    }

    pub fn complete_service_uuids16(uuids: &[u16]) -> Self {
        Self::from_service_uuids16(AD_COMPLETE_16_BIT_SERVICE_UUIDS, uuids)
    }

    pub fn incomplete_service_uuids16(uuids: &[u16]) -> Self {
        Self::from_service_uuids16(AD_INCOMPLETE_16_BIT_SERVICE_UUIDS, uuids)
    }

    fn from_service_uuids16(ad_type: u8, uuids: &[u16]) -> Self {
        let mut data = Vec::with_capacity(uuids.len() * 2);
        for uuid in uuids {
            data.extend_from_slice(&uuid.to_le_bytes());
        }
        Self::new(ad_type, data)
    }

    pub fn flags_value(&self) -> Option<u8> {
        if self.ad_type == AD_FLAGS && self.data.len() == 1 {
            Some(self.data[0])
        } else {
            None
        }
    }

    pub fn local_name(&self) -> Option<String> {
        if matches!(
            self.ad_type,
            AD_COMPLETE_LOCAL_NAME | AD_SHORTENED_LOCAL_NAME
        ) {
            Some(String::from_utf8_lossy(&self.data).into_owned())
        } else {
            None
        }
    }

    pub fn service_uuids16(&self) -> Option<Vec<u16>> {
        if !matches!(
            self.ad_type,
            AD_COMPLETE_16_BIT_SERVICE_UUIDS | AD_INCOMPLETE_16_BIT_SERVICE_UUIDS
        ) || self.data.len() % 2 != 0
        {
            return None;
        }

        Some(
            self.data
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect(),
        )
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let length = self.length_override.unwrap_or_else(|| {
            self.data
                .len()
                .saturating_add(1)
                .min(u8::MAX as usize) as u8
        });

        out.push(length);
        out.push(self.ad_type);
        out.extend_from_slice(&self.data);
    }

    pub(crate) fn encoded_len(&self) -> usize {
        1 + 1 + self.data.len()
    }
}

/// A concatenated GAP Advertising Data payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdList(pub Vec<AdStructure>);

impl AdList {
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        for structure in &self.0 {
            structure.encode(out);
        }
    }

    pub(crate) fn encoded_len(&self) -> usize {
        self.0.iter().map(AdStructure::encoded_len).sum()
    }

    pub fn push(&mut self, structure: AdStructure) {
        self.0.push(structure);
    }
}

pub(crate) fn decode_ad_list(bytes: &[u8]) -> Result<AdList> {
    let mut structures = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        let length = bytes[offset] as usize;
        offset += 1;

        if length == 0 {
            break;
        }

        if offset >= bytes.len() {
            return Err(CrafterError::buffer_too_short(
                "ble.ad.structure",
                1,
                0,
            ));
        }

        let ad_type = bytes[offset];
        offset += 1;

        let data_len = length - 1;
        let available = bytes.len() - offset;
        if available < data_len {
            return Err(CrafterError::buffer_too_short(
                "ble.ad.structure",
                data_len,
                available,
            ));
        }

        let data_end = offset + data_len;
        structures.push(AdStructure {
            ad_type,
            data: bytes[offset..data_end].to_vec(),
            length_override: None,
        });
        offset = data_end;
    }

    Ok(AdList(structures))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_ad_encode_derives_length() {
        let structure = AdStructure::new(0x01, vec![0x06]);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x02, 0x01, 0x06]);
        assert_eq!(structure.encoded_len(), 3);
    }

    #[test]
    fn ble_ad_encode_honors_length_override() {
        let mut structure = AdStructure::new(0x01, vec![0x06]);
        structure.length_override = Some(0x7f);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x7f, 0x01, 0x06]);
    }

    #[test]
    fn ble_ad_flags_general_disc_encodes_and_reads_flags() {
        let structure = AdStructure::flags_general_disc();
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x02, 0x01, 0x06]);
        assert_eq!(structure.flags_value(), Some(0x06));
    }

    #[test]
    fn ble_ad_local_name_complete_encodes_and_reads_name() {
        let structure = AdStructure::complete_local_name("libcrafter-nrf");
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                0x0f, 0x09, b'l', b'i', b'b', b'c', b'r', b'a', b'f', b't', b'e', b'r', b'-',
                b'n', b'r', b'f',
            ]
        );
        assert_eq!(structure.local_name().as_deref(), Some("libcrafter-nrf"));
    }

    #[test]
    fn ble_ad_local_name_shortened_reads_name() {
        let structure = AdStructure::shortened_local_name("crafter");

        assert_eq!(structure.ad_type, AD_SHORTENED_LOCAL_NAME);
        assert_eq!(structure.data, b"crafter");
        assert_eq!(structure.local_name().as_deref(), Some("crafter"));
        assert_eq!(AdStructure::flags_general_disc().local_name(), None);
    }

    #[test]
    fn ble_ad_uuid16_complete_encodes_little_endian_and_reads() {
        let uuids = [0x180f];
        let structure = AdStructure::complete_service_uuids16(&uuids);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x03, 0x03, 0x0f, 0x18]);
        assert_eq!(structure.service_uuids16(), Some(uuids.to_vec()));
    }

    #[test]
    fn ble_ad_uuid16_incomplete_encodes_and_reads() {
        let uuids = [0x180d, 0x180f];
        let structure = AdStructure::incomplete_service_uuids16(&uuids);

        assert_eq!(structure.ad_type, AD_INCOMPLETE_16_BIT_SERVICE_UUIDS);
        assert_eq!(structure.data, [0x0d, 0x18, 0x0f, 0x18]);
        assert_eq!(structure.service_uuids16(), Some(uuids.to_vec()));
        assert_eq!(AdStructure::complete_local_name("x").service_uuids16(), None);
        assert_eq!(
            AdStructure::raw(AD_COMPLETE_16_BIT_SERVICE_UUIDS, [0x0f]).service_uuids16(),
            None
        );
    }

    #[test]
    fn ble_ad_decode_preserves_unknown_types() {
        let ad_list = decode_ad_list(&[0x02, 0x01, 0x06, 0x03, 0xff, 0xaa, 0xbb])
            .expect("decode AD list");

        assert_eq!(
            ad_list,
            AdList(vec![
                AdStructure::new(0x01, [0x06]),
                AdStructure::new(0xff, [0xaa, 0xbb]),
            ])
        );
    }

    #[test]
    fn ble_ad_decode_truncated_structure_is_structured_error() {
        let err = decode_ad_list(&[0x05, 0x09, 0x41])
            .expect_err("must reject over-long AD structure");

        assert_eq!(
            err,
            CrafterError::buffer_too_short("ble.ad.structure", 4, 1)
        );
    }

    #[test]
    fn ble_ad_decode_zero_terminator_stops_cleanly() {
        let ad_list = decode_ad_list(&[0x02, 0x01, 0x06, 0x00, 0x03, 0xff, 0xaa, 0xbb])
            .expect("decode terminated AD list");

        assert_eq!(ad_list, AdList(vec![AdStructure::new(0x01, [0x06])]));
    }
}
