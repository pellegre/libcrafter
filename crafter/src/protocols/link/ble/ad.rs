//! GAP Advertising Data structures.

use crate::error::{CrafterError, Result};

use super::consts::{
    AD_APPEARANCE, AD_COMPLETE_128_BIT_SERVICE_UUIDS, AD_COMPLETE_16_BIT_SERVICE_UUIDS,
    AD_COMPLETE_32_BIT_SERVICE_UUIDS, AD_COMPLETE_LOCAL_NAME, AD_FLAGS,
    AD_INCOMPLETE_128_BIT_SERVICE_UUIDS, AD_INCOMPLETE_16_BIT_SERVICE_UUIDS,
    AD_INCOMPLETE_32_BIT_SERVICE_UUIDS, AD_MANUFACTURER_SPECIFIC_DATA,
    AD_SERVICE_DATA_128_BIT_UUID, AD_SERVICE_DATA_16_BIT_UUID, AD_SERVICE_DATA_32_BIT_UUID,
    AD_SHORTENED_LOCAL_NAME, AD_TX_POWER_LEVEL,
};

/// Flags AD structure bit values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BleAdvFlags;

impl BleAdvFlags {
    #[cfg(test)]
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

    pub fn complete_service_uuids32(uuids: &[u32]) -> Self {
        Self::from_service_uuids32(AD_COMPLETE_32_BIT_SERVICE_UUIDS, uuids)
    }

    pub fn incomplete_service_uuids32(uuids: &[u32]) -> Self {
        Self::from_service_uuids32(AD_INCOMPLETE_32_BIT_SERVICE_UUIDS, uuids)
    }

    /// Builds a Complete List of 128-bit Service UUIDs AD structure.
    ///
    /// Input UUID arrays use canonical/MSB-first byte order; BLE AD encodes
    /// each UUID on the wire in little-endian order.
    pub fn complete_service_uuids128(uuids: &[[u8; 16]]) -> Self {
        Self::from_service_uuids128(AD_COMPLETE_128_BIT_SERVICE_UUIDS, uuids)
    }

    /// Builds an Incomplete List of 128-bit Service UUIDs AD structure.
    ///
    /// Input UUID arrays use canonical/MSB-first byte order; BLE AD encodes
    /// each UUID on the wire in little-endian order.
    pub fn incomplete_service_uuids128(uuids: &[[u8; 16]]) -> Self {
        Self::from_service_uuids128(AD_INCOMPLETE_128_BIT_SERVICE_UUIDS, uuids)
    }

    pub fn tx_power_level(dbm: i8) -> Self {
        Self::new(AD_TX_POWER_LEVEL, [dbm as u8])
    }

    pub fn appearance(value: u16) -> Self {
        Self::new(AD_APPEARANCE, value.to_le_bytes())
    }

    pub fn manufacturer_data(company_id: u16, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(2 + data.len());
        payload.extend_from_slice(&company_id.to_le_bytes());
        payload.extend_from_slice(data);
        Self::new(AD_MANUFACTURER_SPECIFIC_DATA, payload)
    }

    pub fn service_data_uuid16(uuid: u16, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(2 + data.len());
        payload.extend_from_slice(&uuid.to_le_bytes());
        payload.extend_from_slice(data);
        Self::new(AD_SERVICE_DATA_16_BIT_UUID, payload)
    }

    pub fn service_data_uuid32(uuid: u32, data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(4 + data.len());
        payload.extend_from_slice(&uuid.to_le_bytes());
        payload.extend_from_slice(data);
        Self::new(AD_SERVICE_DATA_32_BIT_UUID, payload)
    }

    /// Builds a Service Data - 128-bit UUID AD structure.
    ///
    /// Input UUID arrays use canonical/MSB-first byte order; BLE AD encodes
    /// the UUID on the wire in little-endian order before service data.
    pub fn service_data_uuid128(uuid: [u8; 16], data: &[u8]) -> Self {
        let mut payload = Vec::with_capacity(16 + data.len());
        payload.extend(uuid.iter().rev().copied());
        payload.extend_from_slice(data);
        Self::new(AD_SERVICE_DATA_128_BIT_UUID, payload)
    }

    fn from_service_uuids16(ad_type: u8, uuids: &[u16]) -> Self {
        let mut data = Vec::with_capacity(uuids.len() * 2);
        for uuid in uuids {
            data.extend_from_slice(&uuid.to_le_bytes());
        }
        Self::new(ad_type, data)
    }

    fn from_service_uuids32(ad_type: u8, uuids: &[u32]) -> Self {
        let mut data = Vec::with_capacity(uuids.len() * 4);
        for uuid in uuids {
            data.extend_from_slice(&uuid.to_le_bytes());
        }
        Self::new(ad_type, data)
    }

    fn from_service_uuids128(ad_type: u8, uuids: &[[u8; 16]]) -> Self {
        let mut data = Vec::with_capacity(uuids.len() * 16);
        for uuid in uuids {
            data.extend(uuid.iter().rev().copied());
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

    pub fn service_uuids32(&self) -> Option<Vec<u32>> {
        if !matches!(
            self.ad_type,
            AD_COMPLETE_32_BIT_SERVICE_UUIDS | AD_INCOMPLETE_32_BIT_SERVICE_UUIDS
        ) || self.data.len() % 4 != 0
        {
            return None;
        }

        Some(
            self.data
                .chunks_exact(4)
                .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect(),
        )
    }

    pub fn service_uuids128(&self) -> Option<Vec<[u8; 16]>> {
        if !matches!(
            self.ad_type,
            AD_COMPLETE_128_BIT_SERVICE_UUIDS | AD_INCOMPLETE_128_BIT_SERVICE_UUIDS
        ) || self.data.len() % 16 != 0
        {
            return None;
        }

        Some(
            self.data
                .chunks_exact(16)
                .map(|chunk| {
                    let mut uuid = [0u8; 16];
                    for (dst, src) in uuid.iter_mut().zip(chunk.iter().rev()) {
                        *dst = *src;
                    }
                    uuid
                })
                .collect(),
        )
    }

    pub fn tx_power_level_value(&self) -> Option<i8> {
        if self.ad_type == AD_TX_POWER_LEVEL && self.data.len() == 1 {
            Some(self.data[0] as i8)
        } else {
            None
        }
    }

    pub fn appearance_value(&self) -> Option<u16> {
        if self.ad_type == AD_APPEARANCE && self.data.len() == 2 {
            Some(u16::from_le_bytes([self.data[0], self.data[1]]))
        } else {
            None
        }
    }

    pub fn manufacturer_data_value(&self) -> Option<(u16, Vec<u8>)> {
        if self.ad_type != AD_MANUFACTURER_SPECIFIC_DATA || self.data.len() < 2 {
            return None;
        }

        Some((
            u16::from_le_bytes([self.data[0], self.data[1]]),
            self.data[2..].to_vec(),
        ))
    }

    pub fn service_data_uuid16_value(&self) -> Option<(u16, Vec<u8>)> {
        if self.ad_type != AD_SERVICE_DATA_16_BIT_UUID || self.data.len() < 2 {
            return None;
        }

        Some((
            u16::from_le_bytes([self.data[0], self.data[1]]),
            self.data[2..].to_vec(),
        ))
    }

    pub fn service_data_uuid32_value(&self) -> Option<(u32, Vec<u8>)> {
        if self.ad_type != AD_SERVICE_DATA_32_BIT_UUID || self.data.len() < 4 {
            return None;
        }

        Some((
            u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]),
            self.data[4..].to_vec(),
        ))
    }

    pub fn service_data_uuid128_value(&self) -> Option<([u8; 16], Vec<u8>)> {
        if self.ad_type != AD_SERVICE_DATA_128_BIT_UUID || self.data.len() < 16 {
            return None;
        }

        let mut uuid = [0u8; 16];
        for (dst, src) in uuid.iter_mut().zip(self.data[..16].iter().rev()) {
            *dst = *src;
        }

        Some((uuid, self.data[16..].to_vec()))
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let length = self
            .length_override
            .unwrap_or_else(|| self.data.len().saturating_add(1).min(u8::MAX as usize) as u8);

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
            return Err(CrafterError::buffer_too_short("ble.ad.structure", 1, 0));
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
        assert_eq!(BleAdvFlags::LE_LIMITED_DISC, 0x01);
    }

    #[test]
    fn ble_ad_local_name_complete_encodes_and_reads_name() {
        let structure = AdStructure::complete_local_name("libcrafter-nrf");
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                0x0f, 0x09, b'l', b'i', b'b', b'c', b'r', b'a', b'f', b't', b'e', b'r', b'-', b'n',
                b'r', b'f',
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
        assert_eq!(
            AdStructure::complete_local_name("x").service_uuids16(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_COMPLETE_16_BIT_SERVICE_UUIDS, [0x0f]).service_uuids16(),
            None
        );
    }

    #[test]
    fn ble_ad_uuid32_complete_encodes_little_endian_and_reads() {
        let uuids = [0x0000_1234];
        let structure = AdStructure::complete_service_uuids32(&uuids);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x05, 0x05, 0x34, 0x12, 0x00, 0x00]);
        assert_eq!(structure.service_uuids32(), Some(uuids.to_vec()));
    }

    #[test]
    fn ble_ad_uuid32_incomplete_encodes_and_reads() {
        let uuids = [0x0000_180d, 0x0000_180f];
        let structure = AdStructure::incomplete_service_uuids32(&uuids);

        assert_eq!(structure.ad_type, AD_INCOMPLETE_32_BIT_SERVICE_UUIDS);
        assert_eq!(
            structure.data,
            [0x0d, 0x18, 0x00, 0x00, 0x0f, 0x18, 0x00, 0x00]
        );
        assert_eq!(structure.service_uuids32(), Some(uuids.to_vec()));
        assert_eq!(
            AdStructure::complete_local_name("x").service_uuids32(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_COMPLETE_32_BIT_SERVICE_UUIDS, [0x34, 0x12, 0x00])
                .service_uuids32(),
            None
        );
    }

    #[test]
    fn ble_ad_uuid128_complete_encodes_little_endian_and_reads() {
        let uuid = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let structure = AdStructure::complete_service_uuids128(&[uuid]);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                0x11, 0x07, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
                0x33, 0x22, 0x11, 0x00,
            ]
        );
        assert_eq!(structure.service_uuids128(), Some(vec![uuid]));
    }

    #[test]
    fn ble_ad_uuid128_incomplete_encodes_and_rejects_wrong_types_or_lengths() {
        let uuid = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
            0x1e, 0x0f,
        ];
        let structure = AdStructure::incomplete_service_uuids128(&[uuid]);

        assert_eq!(structure.ad_type, AD_INCOMPLETE_128_BIT_SERVICE_UUIDS);
        assert_eq!(
            structure.data,
            [
                0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
                0xe1, 0xf0,
            ]
        );
        assert_eq!(structure.service_uuids128(), Some(vec![uuid]));
        assert_eq!(
            AdStructure::complete_local_name("x").service_uuids128(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_COMPLETE_128_BIT_SERVICE_UUIDS, [0x00; 15]).service_uuids128(),
            None
        );
    }

    #[test]
    fn ble_ad_tx_power_level_encodes_and_reads_signed_dbm() {
        let structure = AdStructure::tx_power_level(-4);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x02, 0x0a, 0xfc]);
        assert_eq!(structure.tx_power_level_value(), Some(-4));
        assert_eq!(
            AdStructure::complete_local_name("x").tx_power_level_value(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_TX_POWER_LEVEL, [0xfc, 0x00]).tx_power_level_value(),
            None
        );
    }

    #[test]
    fn ble_ad_appearance_encodes_and_reads_value() {
        let structure = AdStructure::appearance(0x03c0);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x03, 0x19, 0xc0, 0x03]);
        assert_eq!(structure.appearance_value(), Some(0x03c0));
        assert_eq!(
            AdStructure::complete_local_name("x").appearance_value(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_APPEARANCE, [0xc0]).appearance_value(),
            None
        );
    }

    #[test]
    fn ble_ad_manufacturer_data_encodes_and_reads_company_payload() {
        let vendor_data = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let structure = AdStructure::manufacturer_data(0xffff, &vendor_data);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(
            encoded,
            [0x09, 0xff, 0xff, 0xff, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]
        );
        assert_eq!(
            structure.manufacturer_data_value(),
            Some((0xffff, vendor_data.to_vec()))
        );
        assert_eq!(
            AdStructure::complete_local_name("x").manufacturer_data_value(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_MANUFACTURER_SPECIFIC_DATA, [0xff]).manufacturer_data_value(),
            None
        );
    }

    #[test]
    fn ble_ad_service_data_uuid16_encodes_and_reads_payload() {
        let service_data = [0x01, 0x02];
        let structure = AdStructure::service_data_uuid16(0xfef3, &service_data);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(encoded, [0x05, 0x16, 0xf3, 0xfe, 0x01, 0x02]);
        assert_eq!(
            structure.service_data_uuid16_value(),
            Some((0xfef3, service_data.to_vec()))
        );
    }

    #[test]
    fn ble_ad_service_data_uuid32_encodes_and_reads_payload() {
        let service_data = [0xaa, 0xbb, 0xcc];
        let structure = AdStructure::service_data_uuid32(0x1234_5678, &service_data);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(
            encoded,
            [0x08, 0x20, 0x78, 0x56, 0x34, 0x12, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(
            structure.service_data_uuid32_value(),
            Some((0x1234_5678, service_data.to_vec()))
        );
    }

    #[test]
    fn ble_ad_service_data_uuid128_encodes_and_reads_canonical_uuid() {
        let uuid = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let service_data = [0x01, 0x02, 0x03];
        let structure = AdStructure::service_data_uuid128(uuid, &service_data);
        let mut encoded = Vec::new();

        structure.encode(&mut encoded);

        assert_eq!(
            encoded,
            [
                0x14, 0x21, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44,
                0x33, 0x22, 0x11, 0x00, 0x01, 0x02, 0x03,
            ]
        );
        assert_eq!(
            structure.service_data_uuid128_value(),
            Some((uuid, service_data.to_vec()))
        );
    }

    #[test]
    fn ble_ad_service_data_rejects_wrong_type_or_short_payloads() {
        assert_eq!(
            AdStructure::complete_local_name("x").service_data_uuid16_value(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_SERVICE_DATA_16_BIT_UUID, [0xff]).service_data_uuid16_value(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_SERVICE_DATA_32_BIT_UUID, [0x78, 0x56, 0x34])
                .service_data_uuid32_value(),
            None
        );
        assert_eq!(
            AdStructure::raw(AD_SERVICE_DATA_128_BIT_UUID, [0x00; 15]).service_data_uuid128_value(),
            None
        );
    }

    #[test]
    fn ble_ad_decode_preserves_unknown_types() {
        let ad_list =
            decode_ad_list(&[0x02, 0x01, 0x06, 0x03, 0xff, 0xaa, 0xbb]).expect("decode AD list");

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
        let err =
            decode_ad_list(&[0x05, 0x09, 0x41]).expect_err("must reject over-long AD structure");

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

    #[test]
    fn ble_ad_roundtrip_all_modeled_types_unknown_and_truncation() {
        let uuid128 = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let service_uuid128 = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
            0x1e, 0x0f,
        ];
        let list = AdList(vec![
            AdStructure::flags(BleAdvFlags::GENERAL_DISC),
            AdStructure::complete_local_name("crafter-ble"),
            AdStructure::complete_service_uuids16(&[0x180f, 0x180d]),
            AdStructure::complete_service_uuids32(&[0x0000_1234]),
            AdStructure::complete_service_uuids128(&[uuid128]),
            AdStructure::tx_power_level(-8),
            AdStructure::manufacturer_data(0xffff, &[0x01, 0x02, 0x03]),
            AdStructure::service_data_uuid16(0xfef3, &[0x04, 0x05]),
            AdStructure::service_data_uuid32(0x1234_5678, &[0x06, 0x07]),
            AdStructure::service_data_uuid128(service_uuid128, &[0x08, 0x09]),
            AdStructure::appearance(0x03c0),
            AdStructure::raw(0x2a, [0xde, 0xad, 0xbe, 0xef]),
        ]);
        let mut encoded = Vec::new();

        list.encode(&mut encoded);
        let decoded = decode_ad_list(&encoded).expect("decode AD list");

        assert_eq!(decoded.0.len(), 12);
        assert_eq!(decoded.0[0].ad_type, AD_FLAGS);
        assert_eq!(decoded.0[0].flags_value(), Some(BleAdvFlags::GENERAL_DISC));
        assert_eq!(decoded.0[1].ad_type, AD_COMPLETE_LOCAL_NAME);
        assert_eq!(decoded.0[1].local_name().as_deref(), Some("crafter-ble"));
        assert_eq!(decoded.0[2].ad_type, AD_COMPLETE_16_BIT_SERVICE_UUIDS);
        assert_eq!(decoded.0[2].service_uuids16(), Some(vec![0x180f, 0x180d]));
        assert_eq!(decoded.0[3].ad_type, AD_COMPLETE_32_BIT_SERVICE_UUIDS);
        assert_eq!(decoded.0[3].service_uuids32(), Some(vec![0x0000_1234]));
        assert_eq!(decoded.0[4].ad_type, AD_COMPLETE_128_BIT_SERVICE_UUIDS);
        assert_eq!(decoded.0[4].service_uuids128(), Some(vec![uuid128]));
        assert_eq!(decoded.0[5].ad_type, AD_TX_POWER_LEVEL);
        assert_eq!(decoded.0[5].tx_power_level_value(), Some(-8));
        assert_eq!(decoded.0[6].ad_type, AD_MANUFACTURER_SPECIFIC_DATA);
        assert_eq!(
            decoded.0[6].manufacturer_data_value(),
            Some((0xffff, vec![0x01, 0x02, 0x03]))
        );
        assert_eq!(decoded.0[7].ad_type, AD_SERVICE_DATA_16_BIT_UUID);
        assert_eq!(
            decoded.0[7].service_data_uuid16_value(),
            Some((0xfef3, vec![0x04, 0x05]))
        );
        assert_eq!(decoded.0[8].ad_type, AD_SERVICE_DATA_32_BIT_UUID);
        assert_eq!(
            decoded.0[8].service_data_uuid32_value(),
            Some((0x1234_5678, vec![0x06, 0x07]))
        );
        assert_eq!(decoded.0[9].ad_type, AD_SERVICE_DATA_128_BIT_UUID);
        assert_eq!(
            decoded.0[9].service_data_uuid128_value(),
            Some((service_uuid128, vec![0x08, 0x09]))
        );
        assert_eq!(decoded.0[10].ad_type, AD_APPEARANCE);
        assert_eq!(decoded.0[10].appearance_value(), Some(0x03c0));
        assert_eq!(decoded.0[11].ad_type, 0x2a);
        assert_eq!(
            decoded.0[11],
            AdStructure::raw(0x2a, [0xde, 0xad, 0xbe, 0xef])
        );

        let mut malformed = encoded;
        malformed.extend_from_slice(&[0x03, AD_COMPLETE_LOCAL_NAME, b'x']);
        assert!(decode_ad_list(&malformed).is_err());
    }
}
