//! BLE advertising-channel constants and codepoints.

/// Advertising physical channel access address.
pub const ADVERTISING_ACCESS_ADDRESS: u32 = 0x8E89_BED6;
/// CRCInit used by non-periodic advertising physical channel PDUs.
pub const ADV_CRC_INIT: u32 = 0x55_5555;

/// Primary advertising channel index 37.
pub const ADV_CHANNEL_37: u8 = 37;
/// Primary advertising channel index 38.
#[cfg(test)]
pub const ADV_CHANNEL_38: u8 = 38;
/// Primary advertising channel index 39.
#[cfg(test)]
pub const ADV_CHANNEL_39: u8 = 39;

/// Center frequency for advertising channel 37, in MHz.
#[cfg(test)]
pub const ADV_CHANNEL_37_FREQUENCY_MHZ: u16 = 2402;
/// Center frequency for advertising channel 38, in MHz.
#[cfg(test)]
pub const ADV_CHANNEL_38_FREQUENCY_MHZ: u16 = 2426;
/// Center frequency for advertising channel 39, in MHz.
#[cfg(test)]
pub const ADV_CHANNEL_39_FREQUENCY_MHZ: u16 = 2480;

/// Primary advertising channels.
#[cfg(test)]
pub const ADVERTISING_CHANNELS: [u8; 3] = [ADV_CHANNEL_37, ADV_CHANNEL_38, ADV_CHANNEL_39];

/// Return the center frequency, in MHz, for a primary advertising channel.
#[cfg(test)]
pub const fn advertising_channel_frequency_mhz(channel: u8) -> Option<u16> {
    match channel {
        ADV_CHANNEL_37 => Some(ADV_CHANNEL_37_FREQUENCY_MHZ),
        ADV_CHANNEL_38 => Some(ADV_CHANNEL_38_FREQUENCY_MHZ),
        ADV_CHANNEL_39 => Some(ADV_CHANNEL_39_FREQUENCY_MHZ),
        _ => None,
    }
}

/// Return the primary advertising channel for a center frequency in MHz.
#[cfg(test)]
pub const fn advertising_frequency_channel(frequency_mhz: u16) -> Option<u8> {
    match frequency_mhz {
        ADV_CHANNEL_37_FREQUENCY_MHZ => Some(ADV_CHANNEL_37),
        ADV_CHANNEL_38_FREQUENCY_MHZ => Some(ADV_CHANNEL_38),
        ADV_CHANNEL_39_FREQUENCY_MHZ => Some(ADV_CHANNEL_39),
        _ => None,
    }
}

/// BLE advertising physical-channel PDU type.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BleAdvPduType {
    AdvInd = 0x0,
    AdvDirectInd = 0x1,
    AdvNonconnInd = 0x2,
    ScanReq = 0x3,
    ScanRsp = 0x4,
    ConnectInd = 0x5,
    AdvScanInd = 0x6,
}

impl BleAdvPduType {
    /// Convert a four-bit advertising PDU type codepoint to a modeled value.
    pub const fn from_u4(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::AdvInd),
            0x1 => Some(Self::AdvDirectInd),
            0x2 => Some(Self::AdvNonconnInd),
            0x3 => Some(Self::ScanReq),
            0x4 => Some(Self::ScanRsp),
            0x5 => Some(Self::ConnectInd),
            0x6 => Some(Self::AdvScanInd),
            _ => None,
        }
    }

    /// Return the four-bit advertising PDU type codepoint.
    pub const fn as_u4(&self) -> u8 {
        *self as u8
    }
}

/// Flags AD structure.
pub const AD_FLAGS: u8 = 0x01;
/// Incomplete list of 16-bit Service UUIDs AD structure.
pub const AD_INCOMPLETE_16_BIT_SERVICE_UUIDS: u8 = 0x02;
/// Complete list of 16-bit Service UUIDs AD structure.
pub const AD_COMPLETE_16_BIT_SERVICE_UUIDS: u8 = 0x03;
/// Incomplete list of 32-bit Service UUIDs AD structure.
pub const AD_INCOMPLETE_32_BIT_SERVICE_UUIDS: u8 = 0x04;
/// Complete list of 32-bit Service UUIDs AD structure.
pub const AD_COMPLETE_32_BIT_SERVICE_UUIDS: u8 = 0x05;
/// Incomplete list of 128-bit Service UUIDs AD structure.
pub const AD_INCOMPLETE_128_BIT_SERVICE_UUIDS: u8 = 0x06;
/// Complete list of 128-bit Service UUIDs AD structure.
pub const AD_COMPLETE_128_BIT_SERVICE_UUIDS: u8 = 0x07;
/// Shortened Local Name AD structure.
pub const AD_SHORTENED_LOCAL_NAME: u8 = 0x08;
/// Complete Local Name AD structure.
pub const AD_COMPLETE_LOCAL_NAME: u8 = 0x09;
/// TX Power Level AD structure.
pub const AD_TX_POWER_LEVEL: u8 = 0x0A;
/// Service Data - 16-bit UUID AD structure.
pub const AD_SERVICE_DATA_16_BIT_UUID: u8 = 0x16;
/// Appearance AD structure.
pub const AD_APPEARANCE: u8 = 0x19;
/// Service Data - 32-bit UUID AD structure.
pub const AD_SERVICE_DATA_32_BIT_UUID: u8 = 0x20;
/// Service Data - 128-bit UUID AD structure.
pub const AD_SERVICE_DATA_128_BIT_UUID: u8 = 0x21;
/// Manufacturer Specific Data AD structure.
pub const AD_MANUFACTURER_SPECIFIC_DATA: u8 = 0xFF;

/// GAP Advertising Data type codepoint.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg(test)]
pub struct AdType(u8);

#[cfg(test)]
impl AdType {
    pub const FLAGS: Self = Self(AD_FLAGS);
    pub const INCOMPLETE_16_BIT_SERVICE_UUIDS: Self = Self(AD_INCOMPLETE_16_BIT_SERVICE_UUIDS);
    pub const COMPLETE_16_BIT_SERVICE_UUIDS: Self = Self(AD_COMPLETE_16_BIT_SERVICE_UUIDS);
    pub const INCOMPLETE_32_BIT_SERVICE_UUIDS: Self = Self(AD_INCOMPLETE_32_BIT_SERVICE_UUIDS);
    pub const COMPLETE_32_BIT_SERVICE_UUIDS: Self = Self(AD_COMPLETE_32_BIT_SERVICE_UUIDS);
    pub const INCOMPLETE_128_BIT_SERVICE_UUIDS: Self = Self(AD_INCOMPLETE_128_BIT_SERVICE_UUIDS);
    pub const COMPLETE_128_BIT_SERVICE_UUIDS: Self = Self(AD_COMPLETE_128_BIT_SERVICE_UUIDS);
    pub const SHORTENED_LOCAL_NAME: Self = Self(AD_SHORTENED_LOCAL_NAME);
    pub const COMPLETE_LOCAL_NAME: Self = Self(AD_COMPLETE_LOCAL_NAME);
    pub const TX_POWER_LEVEL: Self = Self(AD_TX_POWER_LEVEL);
    pub const SERVICE_DATA_16_BIT_UUID: Self = Self(AD_SERVICE_DATA_16_BIT_UUID);
    pub const APPEARANCE: Self = Self(AD_APPEARANCE);
    pub const SERVICE_DATA_32_BIT_UUID: Self = Self(AD_SERVICE_DATA_32_BIT_UUID);
    pub const SERVICE_DATA_128_BIT_UUID: Self = Self(AD_SERVICE_DATA_128_BIT_UUID);
    pub const MANUFACTURER_SPECIFIC_DATA: Self = Self(AD_MANUFACTURER_SPECIFIC_DATA);

    /// Preserve any AD type codepoint, including values not modeled by this crate.
    pub const fn from_u8(value: u8) -> Self {
        Self(value)
    }

    /// Return the raw AD type codepoint.
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_consts_advertising_values_match_manifest() {
        assert_eq!(ADVERTISING_ACCESS_ADDRESS, 0x8E89_BED6);
        assert_eq!(ADV_CRC_INIT, 0x55_5555);
        assert_eq!(ADVERTISING_CHANNELS, [37, 38, 39]);
        assert_eq!(advertising_channel_frequency_mhz(37), Some(2402));
        assert_eq!(advertising_channel_frequency_mhz(38), Some(2426));
        assert_eq!(advertising_channel_frequency_mhz(39), Some(2480));
        assert_eq!(advertising_channel_frequency_mhz(36), None);
        assert_eq!(advertising_frequency_channel(2402), Some(37));
        assert_eq!(advertising_frequency_channel(2426), Some(38));
        assert_eq!(advertising_frequency_channel(2480), Some(39));
        assert_eq!(advertising_frequency_channel(2404), None);
    }

    #[test]
    fn ble_consts_pdu_type_round_trips() {
        let pdu_types = [
            (0x0, BleAdvPduType::AdvInd),
            (0x1, BleAdvPduType::AdvDirectInd),
            (0x2, BleAdvPduType::AdvNonconnInd),
            (0x3, BleAdvPduType::ScanReq),
            (0x4, BleAdvPduType::ScanRsp),
            (0x5, BleAdvPduType::ConnectInd),
            (0x6, BleAdvPduType::AdvScanInd),
        ];

        for (raw, pdu_type) in pdu_types {
            assert_eq!(BleAdvPduType::from_u4(raw), Some(pdu_type));
            assert_eq!(pdu_type.as_u4(), raw);
        }

        assert_eq!(BleAdvPduType::from_u4(0x7), None);
        assert_eq!(BleAdvPduType::from_u4(0xF), None);
    }

    #[test]
    fn ble_consts_ad_type_values_and_unknown_round_trip() {
        assert_eq!(AdType::FLAGS.as_u8(), 0x01);
        assert_eq!(AdType::INCOMPLETE_16_BIT_SERVICE_UUIDS.as_u8(), 0x02);
        assert_eq!(AdType::COMPLETE_16_BIT_SERVICE_UUIDS.as_u8(), 0x03);
        assert_eq!(AdType::INCOMPLETE_32_BIT_SERVICE_UUIDS.as_u8(), 0x04);
        assert_eq!(AdType::COMPLETE_32_BIT_SERVICE_UUIDS.as_u8(), 0x05);
        assert_eq!(AdType::INCOMPLETE_128_BIT_SERVICE_UUIDS.as_u8(), 0x06);
        assert_eq!(AdType::COMPLETE_128_BIT_SERVICE_UUIDS.as_u8(), 0x07);
        assert_eq!(AdType::SHORTENED_LOCAL_NAME.as_u8(), 0x08);
        assert_eq!(AdType::COMPLETE_LOCAL_NAME.as_u8(), 0x09);
        assert_eq!(AdType::TX_POWER_LEVEL.as_u8(), 0x0A);
        assert_eq!(AdType::SERVICE_DATA_16_BIT_UUID.as_u8(), 0x16);
        assert_eq!(AdType::APPEARANCE.as_u8(), 0x19);
        assert_eq!(AdType::SERVICE_DATA_32_BIT_UUID.as_u8(), 0x20);
        assert_eq!(AdType::SERVICE_DATA_128_BIT_UUID.as_u8(), 0x21);
        assert_eq!(AdType::MANUFACTURER_SPECIFIC_DATA.as_u8(), 0xFF);
        assert_eq!(AdType::from_u8(0x7F).as_u8(), 0x7F);
    }
}
