//! BLE advertising-channel Link Layer PDU scaffolding.

use core::any::Any;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::ad::{decode_ad_list, AdList, AdStructure};
pub use super::consts::BleAdvPduType;

/// BLE advertising-channel Link Layer PDU.
///
/// Address fields use `MacAddr` as the crate's existing six-octet address
/// type. Builder methods accept normal MSB-first display order and store the
/// bytes in BLE little-endian on-air order for later encoder/decoder steps.
#[derive(Debug)]
pub struct BleLlAdv {
    /// Advertising PDU type stored in header bits 0..=3.
    pdu_type: Field<BleAdvPduType>,
    /// Channel Selection bit.
    ch_sel: Field<bool>,
    /// Transmitter address type bit.
    tx_add: Field<bool>,
    /// Receiver address type bit.
    rx_add: Field<bool>,
    /// Advertising payload length octet; auto-filled during compile.
    length: Field<u8>,
    /// Advertiser address (`AdvA`) for advertising PDUs.
    adv_a: Field<MacAddr>,
    /// Target address (`TargetA`) for directed, scan, and connect PDUs.
    target_a: Field<MacAddr>,
    /// Typed GAP Advertising Data structures carried after `AdvA`.
    ad: AdList,
    /// Raw trailing payload when no typed Advertising Data list is used.
    payload: Vec<u8>,
}

impl Clone for BleLlAdv {
    fn clone(&self) -> Self {
        Self {
            pdu_type: self.pdu_type.clone(),
            ch_sel: self.ch_sel.clone(),
            tx_add: self.tx_add.clone(),
            rx_add: self.rx_add.clone(),
            length: self.length.clone(),
            adv_a: self.adv_a.clone(),
            target_a: self.target_a.clone(),
            ad: self.ad.clone(),
            payload: self.payload.clone(),
        }
    }
}

impl BleLlAdv {
    /// Create a BLE advertising PDU with advertising-channel defaults.
    pub fn new() -> Self {
        Self {
            pdu_type: Field::defaulted(BleAdvPduType::AdvInd),
            ch_sel: Field::defaulted(false),
            tx_add: Field::defaulted(true),
            rx_add: Field::defaulted(false),
            length: Field::unset(),
            adv_a: Field::unset(),
            target_a: Field::unset(),
            ad: AdList(Vec::new()),
            payload: Vec::new(),
        }
    }

    /// Create an ADV_IND advertising PDU.
    pub fn adv_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvInd)
    }

    /// Create an ADV_NONCONN_IND advertising PDU.
    pub fn adv_nonconn_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvNonconnInd)
    }

    /// Create an ADV_SCAN_IND advertising PDU.
    pub fn adv_scan_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvScanInd)
    }

    /// Create a SCAN_RSP advertising PDU.
    pub fn scan_rsp() -> Self {
        Self::new().pdu_type(BleAdvPduType::ScanRsp)
    }

    /// Create a SCAN_REQ advertising PDU.
    pub fn scan_req() -> Self {
        Self::new().pdu_type(BleAdvPduType::ScanReq)
    }

    /// Create a CONNECT_IND advertising PDU.
    pub fn connect_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::ConnectInd)
    }

    /// Create an ADV_DIRECT_IND advertising PDU.
    pub fn adv_direct_ind() -> Self {
        Self::new().pdu_type(BleAdvPduType::AdvDirectInd)
    }

    /// Set the advertising PDU type.
    pub fn pdu_type(mut self, pdu_type: BleAdvPduType) -> Self {
        self.pdu_type.set_user(pdu_type);
        self
    }

    /// Set or clear the Channel Selection bit.
    pub fn ch_sel(mut self, ch_sel: bool) -> Self {
        self.ch_sel.set_user(ch_sel);
        self
    }

    /// Set the transmitter address type bit.
    pub fn tx_add(mut self, tx_add: bool) -> Self {
        self.tx_add.set_user(tx_add);
        self
    }

    /// Set the receiver address type bit.
    pub fn rx_add(mut self, rx_add: bool) -> Self {
        self.rx_add.set_user(rx_add);
        self
    }

    /// Set the advertising payload length octet.
    pub fn length(mut self, length: u8) -> Self {
        self.length.set_user(length);
        self
    }

    /// Set the advertiser address (`AdvA`).
    pub fn adv_a(mut self, adv_a: impl Into<MacAddr>) -> Self {
        self.adv_a.set_user(display_to_on_air_address(adv_a.into()));
        self
    }

    /// Set the advertiser address (`AdvA`) from text in MSB-first display order.
    pub fn adv_a_str(self, adv_a: &str) -> Result<Self> {
        Ok(self.adv_a(adv_a.parse::<MacAddr>()?))
    }

    /// Set the target address (`TargetA`).
    pub fn target_a(mut self, target_a: impl Into<MacAddr>) -> Self {
        self.target_a
            .set_user(display_to_on_air_address(target_a.into()));
        self
    }

    /// Set the target address (`TargetA`) from text in MSB-first display order.
    pub fn target_a_str(self, target_a: &str) -> Result<Self> {
        Ok(self.target_a(target_a.parse::<MacAddr>()?))
    }

    /// Set raw trailing payload bytes.
    pub fn payload(mut self, payload: impl Into<Vec<u8>>) -> Self {
        self.payload = payload.into();
        self
    }

    /// Set a typed GAP Advertising Data list.
    pub fn ad(mut self, ad: AdList) -> Self {
        self.ad = ad;
        self
    }

    /// Append one typed GAP Advertising Data structure.
    pub fn push_ad(mut self, structure: AdStructure) -> Self {
        self.ad.push(structure);
        self
    }

    /// Current advertiser address (`AdvA`) in MSB-first display order.
    pub fn adv_a_value(&self) -> Option<MacAddr> {
        self.adv_a.value().copied().map(on_air_to_display_address)
    }

    /// Current target address (`TargetA`) in MSB-first display order.
    pub fn target_a_value(&self) -> Option<MacAddr> {
        self.target_a
            .value()
            .copied()
            .map(on_air_to_display_address)
    }

    /// Encoded advertising PDU length including the two-octet LL header.
    pub(crate) fn encoded_len(&self) -> usize {
        2 + self.payload_len()
    }

    /// Encode the BLE advertising-channel Link Layer PDU.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::with_capacity(self.payload_len());
        self.encode_payload(&mut payload);

        let byte0 = self.effective_pdu_type().as_u4()
            | (u8::from(self.effective_ch_sel()) << 5)
            | (u8::from(self.effective_tx_add()) << 6)
            | (u8::from(self.effective_rx_add()) << 7);
        let length = self.effective_length();

        out.push(byte0);
        out.push(length);
        out.extend_from_slice(&payload);
    }

    fn payload_len(&self) -> usize {
        let adv_a_len = self
            .adv_a
            .value()
            .map(|_| core::mem::size_of::<MacAddr>())
            .unwrap_or(0);
        let target_a_len = if self.requires_target_address() {
            self.target_a
                .value()
                .map(|_| core::mem::size_of::<MacAddr>())
                .unwrap_or(0)
        } else {
            0
        };

        adv_a_len + target_a_len + self.trailing_payload_len()
    }

    fn encode_payload(&self, out: &mut Vec<u8>) {
        if let Some(adv_a) = self.adv_a.value() {
            out.extend_from_slice(&adv_a.octets());
        }

        if self.requires_target_address() {
            if let Some(target_a) = self.target_a.value() {
                out.extend_from_slice(&target_a.octets());
            }
        }

        if self.ad.0.is_empty() {
            out.extend_from_slice(&self.payload);
        } else {
            self.ad.encode(out);
        }
    }

    fn trailing_payload_len(&self) -> usize {
        if self.ad.0.is_empty() {
            self.payload.len()
        } else {
            self.ad.encoded_len()
        }
    }

    fn requires_target_address(&self) -> bool {
        matches!(
            self.effective_pdu_type(),
            BleAdvPduType::AdvDirectInd | BleAdvPduType::ScanReq | BleAdvPduType::ConnectInd
        )
    }

    fn effective_pdu_type(&self) -> BleAdvPduType {
        self.pdu_type
            .value()
            .copied()
            .unwrap_or(BleAdvPduType::AdvInd)
    }

    fn effective_ch_sel(&self) -> bool {
        self.ch_sel.value().copied().unwrap_or(false)
    }

    fn effective_tx_add(&self) -> bool {
        self.tx_add.value().copied().unwrap_or(true)
    }

    fn effective_rx_add(&self) -> bool {
        self.rx_add.value().copied().unwrap_or(false)
    }

    fn effective_length(&self) -> u8 {
        if self.length.is_user_set() {
            self.length
                .value()
                .copied()
                .unwrap_or(self.payload_len() as u8)
        } else {
            self.payload_len() as u8
        }
    }
}

impl Default for BleLlAdv {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for BleLlAdv {
    fn name(&self) -> &'static str {
        "BleLlAdv"
    }

    fn summary(&self) -> String {
        let mut fields = vec![ble_adv_pdu_type_label(self.effective_pdu_type()).to_string()];

        if let Some(adv_a) = self.adv_a_value() {
            fields.push(format!("AdvA={}", format!("{adv_a}").to_uppercase()));
        }

        fields.push(format!("len={}", self.effective_length()));

        format!("BleLlAdv({})", fields.join(", "))
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "pdu_type",
                ble_adv_pdu_type_label(self.effective_pdu_type()).to_string(),
            ),
            ("tx_add", self.effective_tx_add().to_string()),
            ("length", self.effective_length().to_string()),
        ];

        if let Some(adv_a) = self.adv_a_value() {
            fields.push(("adv_a", format!("{adv_a}").to_uppercase()));
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        BleLlAdv::encoded_len(self)
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.encode(out);
        Ok(())
    }

    fn clone_layer(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl<R: IntoPacket> core::ops::Div<R> for BleLlAdv {
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

/// Decode a BLE advertising-channel Link Layer PDU header and address fields.
pub(crate) fn decode_ble_adv(bytes: &[u8]) -> Result<(BleLlAdv, &[u8])> {
    if bytes.len() < 2 {
        return Err(CrafterError::buffer_too_short(
            "ble.adv.header",
            2,
            bytes.len(),
        ));
    }

    let header0 = bytes[0];
    let pdu_type = BleAdvPduType::from_u4(header0 & 0x0f).ok_or_else(|| {
        CrafterError::invalid_field_value("ble.adv.pdu_type", "unknown advertising PDU type")
    })?;
    let length = bytes[1] as usize;
    let available_payload = bytes.len() - 2;
    if available_payload < length {
        return Err(CrafterError::buffer_too_short(
            "ble.adv.payload",
            length,
            available_payload,
        ));
    }

    let payload = &bytes[2..2 + length];
    let mut offset = 0;
    let adv_a = read_ble_adv_address(payload, &mut offset, "ble.adv.adv_a")?;
    let target_a = if ble_adv_pdu_type_has_target_address(pdu_type) {
        read_ble_adv_address(payload, &mut offset, "ble.adv.target_a")?
    } else {
        Field::unset()
    };

    let tail = &payload[offset..];
    let (ad, payload) = if ble_adv_pdu_type_has_ad(pdu_type) {
        (decode_ad_list(tail)?, Vec::new())
    } else {
        (AdList(Vec::new()), tail.to_vec())
    };

    let adv = BleLlAdv {
        pdu_type: Field::user(pdu_type),
        ch_sel: Field::user((header0 & 0x20) != 0),
        tx_add: Field::user((header0 & 0x40) != 0),
        rx_add: Field::user((header0 & 0x80) != 0),
        length: Field::user(bytes[1]),
        adv_a,
        target_a,
        ad,
        payload,
    };

    Ok((adv, &bytes[2 + length..]))
}

fn read_ble_adv_address(
    payload: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<Field<MacAddr>> {
    let required = *offset + core::mem::size_of::<MacAddr>();
    if payload.len() < required {
        return Err(CrafterError::buffer_too_short(
            context,
            required,
            payload.len(),
        ));
    }

    let address = MacAddr::new([
        payload[*offset],
        payload[*offset + 1],
        payload[*offset + 2],
        payload[*offset + 3],
        payload[*offset + 4],
        payload[*offset + 5],
    ]);
    *offset = required;
    Ok(Field::user(address))
}

fn ble_adv_pdu_type_has_target_address(pdu_type: BleAdvPduType) -> bool {
    matches!(
        pdu_type,
        BleAdvPduType::AdvDirectInd | BleAdvPduType::ScanReq | BleAdvPduType::ConnectInd
    )
}

fn ble_adv_pdu_type_has_ad(pdu_type: BleAdvPduType) -> bool {
    matches!(
        pdu_type,
        BleAdvPduType::AdvInd
            | BleAdvPduType::AdvNonconnInd
            | BleAdvPduType::ScanRsp
            | BleAdvPduType::AdvScanInd
    )
}

fn display_to_on_air_address(address: MacAddr) -> MacAddr {
    reverse_address(address)
}

fn on_air_to_display_address(address: MacAddr) -> MacAddr {
    reverse_address(address)
}

fn reverse_address(address: MacAddr) -> MacAddr {
    let [a, b, c, d, e, f] = address.octets();
    MacAddr::new([f, e, d, c, b, a])
}

fn ble_adv_pdu_type_label(pdu_type: BleAdvPduType) -> &'static str {
    match pdu_type {
        BleAdvPduType::AdvInd => "ADV_IND",
        BleAdvPduType::AdvDirectInd => "ADV_DIRECT_IND",
        BleAdvPduType::AdvNonconnInd => "ADV_NONCONN_IND",
        BleAdvPduType::ScanReq => "SCAN_REQ",
        BleAdvPduType::ScanRsp => "SCAN_RSP",
        BleAdvPduType::ConnectInd => "CONNECT_IND",
        BleAdvPduType::AdvScanInd => "ADV_SCAN_IND",
    }
}

#[cfg(test)]
mod tests {
    use crate::field::FieldState;

    use super::super::BleRadio;
    use super::*;

    #[test]
    fn ble_adv_builder_adv_ind_sets_pdu_type_user() {
        let adv = BleLlAdv::adv_ind();

        assert_eq!(adv.pdu_type.state(), FieldState::User);
        assert_eq!(adv.pdu_type.value(), Some(&BleAdvPduType::AdvInd));
    }

    #[test]
    fn ble_adv_builder_tx_add_setter_marks_field_user() {
        let adv = BleLlAdv::new().tx_add(false);

        assert_eq!(adv.tx_add.state(), FieldState::User);
        assert_eq!(adv.tx_add.value(), Some(&false));
    }

    #[test]
    fn ble_adv_builder_default_tx_add_is_random_address() {
        let adv = BleLlAdv::new();

        assert_eq!(adv.tx_add.state(), FieldState::Defaulted);
        assert_eq!(adv.tx_add.value(), Some(&true));
    }

    #[test]
    fn ble_adv_address_adv_a_str_stores_little_endian_and_gets_display_order() {
        let adv = BleLlAdv::new().adv_a_str("C0:FF:EE:11:22:33").unwrap();

        assert_eq!(
            adv.adv_a.value().copied().unwrap().octets(),
            [0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]
        );
        assert_eq!(
            adv.adv_a_value().unwrap(),
            MacAddr::new([0xc0, 0xff, 0xee, 0x11, 0x22, 0x33])
        );
        assert_eq!(adv.adv_a_value().unwrap().to_string(), "c0:ff:ee:11:22:33");
    }

    #[test]
    fn ble_adv_address_target_a_str_stores_little_endian_and_gets_display_order() {
        let adv = BleLlAdv::new().target_a_str("C0:FF:EE:11:22:33").unwrap();

        assert_eq!(
            adv.target_a.value().copied().unwrap().octets(),
            [0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]
        );
        assert_eq!(
            adv.target_a_value().unwrap(),
            MacAddr::new([0xc0, 0xff, 0xee, 0x11, 0x22, 0x33])
        );
    }

    #[test]
    fn ble_adv_encode_auto_fills_payload_length() {
        let adv = BleLlAdv::adv_ind()
            .adv_a(MacAddr::new([0xc0, 0xff, 0xee, 0x11, 0x22, 0x33]))
            .payload([0x02, 0x01, 0x06]);
        let mut out = Vec::new();

        adv.encode(&mut out);

        assert_eq!(adv.encoded_len(), 11);
        assert_eq!(
            out,
            vec![0x40, 0x09, 0x33, 0x22, 0x11, 0xee, 0xff, 0xc0, 0x02, 0x01, 0x06,]
        );
    }

    #[test]
    fn ble_adv_encode_honors_user_length_override() {
        let adv = BleLlAdv::adv_ind()
            .adv_a(MacAddr::new([0xc0, 0xff, 0xee, 0x11, 0x22, 0x33]))
            .payload([0x02, 0x01, 0x06])
            .length(0xff);
        let mut out = Vec::new();

        adv.encode(&mut out);

        assert_eq!(out[1], 0xff);
        assert_eq!(
            &out[2..],
            &[0x33, 0x22, 0x11, 0xee, 0xff, 0xc0, 0x02, 0x01, 0x06]
        );
    }

    #[test]
    fn ble_adv_ad_list_build_decode_roundtrip() {
        let packet = Packet::from_layer(
            BleLlAdv::adv_ind()
                .adv_a_str("C0:FF:EE:11:22:33")
                .unwrap()
                .push_ad(AdStructure::flags_general_disc())
                .push_ad(AdStructure::complete_local_name("libcrafter-nrf")),
        );

        let bytes = packet.compile().expect("compile BLE advertising PDU");
        let pdu = bytes.as_bytes();

        assert_eq!(pdu[0], 0x40);
        assert_eq!(pdu[1], 25);
        assert_eq!(&pdu[2..8], &[0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]);
        assert_eq!(
            &pdu[8..],
            &[
                0x02, 0x01, 0x06, 0x0f, 0x09, b'l', b'i', b'b', b'c', b'r', b'a', b'f', b't', b'e',
                b'r', b'-', b'n', b'r', b'f',
            ]
        );

        let (adv, tail) = decode_ble_adv(pdu).expect("decode compiled ADV_IND with AD list");

        assert!(tail.is_empty());
        assert_eq!(
            adv.ad,
            AdList(vec![
                AdStructure::flags_general_disc(),
                AdStructure::complete_local_name("libcrafter-nrf"),
            ])
        );
    }

    #[test]
    fn ble_adv_layer_compiles_beneath_ble_radio() {
        let packet =
            BleRadio::advertising(37) / BleLlAdv::adv_ind().adv_a_str("C0:FF:EE:11:22:33").unwrap();
        let bytes = packet.compile().expect("compile BLE advertising packet");

        assert_eq!(bytes.len(), 18);
        assert_eq!(
            &bytes.as_bytes()[..10],
            &[37, 0, 0, 0, 0xd6, 0xbe, 0x89, 0x8e, 0x11, 0x04]
        );
        assert_eq!(
            &bytes.as_bytes()[10..],
            &[0x40, 0x06, 0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]
        );
    }

    #[test]
    fn ble_adv_layer_summary_and_inspection_fields_expose_header_values() {
        let adv = BleLlAdv::adv_ind().adv_a_str("C0:FF:EE:11:22:33").unwrap();

        assert_eq!(
            adv.summary(),
            "BleLlAdv(ADV_IND, AdvA=C0:FF:EE:11:22:33, len=6)"
        );
        assert_eq!(
            adv.inspection_fields(),
            vec![
                ("pdu_type", "ADV_IND".to_string()),
                ("tx_add", "true".to_string()),
                ("length", "6".to_string()),
                ("adv_a", "C0:FF:EE:11:22:33".to_string()),
            ]
        );
    }

    #[test]
    fn ble_adv_decode_adv_ind_returns_layer_and_ad_list() {
        let bytes = [
            0x40, 0x09, 0x33, 0x22, 0x11, 0xee, 0xff, 0xc0, 0x02, 0x01, 0x06,
        ];

        let (adv, tail) = decode_ble_adv(&bytes).expect("decode ADV_IND");

        assert_eq!(adv.pdu_type.state(), FieldState::User);
        assert_eq!(adv.pdu_type.value(), Some(&BleAdvPduType::AdvInd));
        assert_eq!(adv.ch_sel.value(), Some(&false));
        assert_eq!(adv.tx_add.value(), Some(&true));
        assert_eq!(adv.rx_add.value(), Some(&false));
        assert_eq!(adv.length.value(), Some(&9));
        assert_eq!(
            adv.adv_a.value().copied().unwrap().octets(),
            [0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]
        );
        assert_eq!(
            adv.adv_a_value().unwrap(),
            MacAddr::new([0xc0, 0xff, 0xee, 0x11, 0x22, 0x33])
        );
        assert_eq!(adv.ad, AdList(vec![AdStructure::flags_general_disc()]));
        assert!(tail.is_empty());
    }

    #[test]
    fn ble_adv_roundtrip_build_decode_reproduces_fields_and_ad_list() {
        let ad_tail = [0x02, 0x01, 0x06];
        let packet = Packet::from_layer(
            BleLlAdv::adv_ind()
                .adv_a_str("C0:FF:EE:11:22:33")
                .unwrap()
                .payload(ad_tail),
        );

        let bytes = packet.compile().expect("compile BLE advertising PDU");
        let pdu = bytes.as_bytes();

        assert_eq!(pdu[0], 0x40);
        assert_eq!(pdu[1], 9);
        assert_eq!(&pdu[2..8], &[0x33, 0x22, 0x11, 0xee, 0xff, 0xc0]);

        let (adv, tail) = decode_ble_adv(pdu).expect("decode compiled ADV_IND");

        assert_eq!(adv.pdu_type.value(), Some(&BleAdvPduType::AdvInd));
        assert_eq!(adv.tx_add.value(), Some(&true));
        assert_eq!(
            adv.adv_a_value().unwrap().to_string().to_uppercase(),
            "C0:FF:EE:11:22:33"
        );
        assert_eq!(adv.ad, AdList(vec![AdStructure::flags_general_disc()]));
        assert!(tail.is_empty());
    }

    #[test]
    fn ble_adv_decode_truncated_header_is_structured_error() {
        let err = decode_ble_adv(&[0x40]).expect_err("must reject truncated header");

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: "ble.adv.header",
                required: 2,
                available: 1,
            }
        );
    }

    #[test]
    fn ble_adv_decode_overlong_length_is_structured_error() {
        let err = decode_ble_adv(&[0x40, 0x09, 0x33, 0x22, 0x11])
            .expect_err("must reject over-long payload length");

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: "ble.adv.payload",
                required: 9,
                available: 3,
            }
        );
    }

    #[test]
    fn ble_adv_decode_unknown_pdu_type_is_invalid_field_value() {
        let err = decode_ble_adv(&[0x07, 0x00]).expect_err("must reject unknown PDU type");

        assert_eq!(
            err,
            CrafterError::InvalidFieldValue {
                field: "ble.adv.pdu_type",
                reason: "unknown advertising PDU type",
            }
        );
    }
}
