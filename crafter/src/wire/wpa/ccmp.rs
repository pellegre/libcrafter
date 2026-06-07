//! CCMP protected-frame parsing and decrypt helpers.
//!
use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};

use super::crypto::WPA_PTK_TEMPORAL_KEY_LEN;
use super::metadata::{WpaDecryptReason, WpaKeyKind};
use crate::{
    CrafterError, Dot11, Dot11DataSubtype, Dot11FrameControl, Dot11FrameType, MacAddr, Result,
    DOT11_FC_ORDER,
};

const CCMP_HEADER_LEN: usize = 8;
const CCMP_MIC_LEN: usize = 8;
const CCMP_NONCE_LEN: usize = 13;
const CCMP_AAD_BASE_LEN: usize = 22;
const CCMP_EXTENDED_IV_BIT: u8 = 0x20;
const CCMP_KEY_ID_SHIFT: u8 = 6;
const CCMP_KEY_ID_MASK: u8 = 0x03;
const CCMP_AAD_FRAME_CONTROL_MASK: u16 = 0xc38f;
const CCMP_AAD_SEQUENCE_CONTROL_MASK: u16 = 0x000f;
const CCMP_AAD_QOS_CONTROL_MASK: u16 = 0x000f;
const CCMP_NONCE_QOS_PRIORITY_MASK: u16 = 0x000f;

type Aes128Ccmp = Ccm<Aes128, U8, U13>;

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

/// Result of attempting to decrypt one CCMP-protected unicast data frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CcmpDecryptResult {
    plaintext: Option<Vec<u8>>,
    packet_number: Option<u64>,
    key_id: Option<u8>,
    key_kind: Option<WpaKeyKind>,
    failure_reason: Option<WpaDecryptReason>,
}

impl CcmpDecryptResult {
    fn decrypted(plaintext: Vec<u8>, packet_number: u64, key_id: u8, key_kind: WpaKeyKind) -> Self {
        Self {
            plaintext: Some(plaintext),
            packet_number: Some(packet_number),
            key_id: Some(key_id),
            key_kind: Some(key_kind),
            failure_reason: None,
        }
    }

    fn failed(
        packet_number: Option<u64>,
        key_id: Option<u8>,
        key_kind: Option<WpaKeyKind>,
        failure_reason: WpaDecryptReason,
    ) -> Self {
        Self {
            plaintext: None,
            packet_number,
            key_id,
            key_kind,
            failure_reason: Some(failure_reason),
        }
    }

    /// Decrypted plaintext bytes, when authentication succeeded.
    pub(crate) fn plaintext(&self) -> Option<&[u8]> {
        self.plaintext.as_deref()
    }

    /// CCMP packet number parsed from the protected frame.
    pub(crate) const fn packet_number(&self) -> Option<u64> {
        self.packet_number
    }

    /// CCMP key identifier parsed from the protected frame.
    pub(crate) const fn key_id(&self) -> Option<u8> {
        self.key_id
    }

    /// Pairwise or group key class inferred from the 802.11 destination.
    pub(crate) const fn key_kind(&self) -> Option<WpaKeyKind> {
        self.key_kind
    }

    /// Failure reason when decryption did not produce plaintext.
    pub(crate) const fn failure_reason(&self) -> Option<WpaDecryptReason> {
        self.failure_reason
    }

    /// Return true when plaintext was authenticated and decrypted.
    pub(crate) const fn is_decrypted(&self) -> bool {
        self.failure_reason.is_none() && self.plaintext.is_some()
    }
}

/// Decrypt one WPA2-PSK CCMP-128 protected unicast data frame.
pub(crate) fn decrypt_unicast(
    dot11: &Dot11,
    encrypted_body: &[u8],
    temporal_key: &[u8; WPA_PTK_TEMPORAL_KEY_LEN],
    last_packet_number: Option<u64>,
) -> CcmpDecryptResult {
    let ccmp = match CcmpHeader::parse(encrypted_body) {
        Ok(ccmp) => ccmp,
        Err(_) => {
            return CcmpDecryptResult::failed(None, None, None, WpaDecryptReason::MalformedFrame);
        }
    };

    let packet_number = ccmp.packet_number();
    let key_id = ccmp.key_id();
    let key_kind = ccmp
        .key_kind_for_dot11(dot11)
        .unwrap_or(WpaKeyKind::Unknown);

    if key_kind != WpaKeyKind::Pairwise {
        return CcmpDecryptResult::failed(
            Some(packet_number),
            Some(key_id),
            Some(key_kind),
            WpaDecryptReason::MissingKeyMaterial,
        );
    }

    if last_packet_number
        .map(|last| packet_number <= last)
        .unwrap_or(false)
    {
        return CcmpDecryptResult::failed(
            Some(packet_number),
            Some(key_id),
            Some(key_kind),
            WpaDecryptReason::ReplayDetected,
        );
    }

    let nonce = match ccmp_nonce(dot11, &ccmp) {
        Ok(nonce) => nonce,
        Err(_) => {
            return CcmpDecryptResult::failed(
                Some(packet_number),
                Some(key_id),
                Some(key_kind),
                WpaDecryptReason::MalformedFrame,
            );
        }
    };
    let aad = match ccmp_aad(dot11) {
        Ok(aad) => aad,
        Err(_) => {
            return CcmpDecryptResult::failed(
                Some(packet_number),
                Some(key_id),
                Some(key_kind),
                WpaDecryptReason::MalformedFrame,
            );
        }
    };

    let encrypted_payload = ccmp.encrypted_payload();
    if encrypted_payload.len() < CCMP_MIC_LEN {
        return CcmpDecryptResult::failed(
            Some(packet_number),
            Some(key_id),
            Some(key_kind),
            WpaDecryptReason::MalformedFrame,
        );
    }

    let tag_offset = encrypted_payload.len() - CCMP_MIC_LEN;
    let (ciphertext, tag) = encrypted_payload.split_at(tag_offset);
    let mut plaintext = ciphertext.to_vec();
    let cipher = Aes128Ccmp::new_from_slice(temporal_key)
        .expect("WPA2-PSK CCMP temporal key length is AES-128");

    if cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            &aad,
            &mut plaintext,
            GenericArray::from_slice(tag),
        )
        .is_err()
    {
        return CcmpDecryptResult::failed(
            Some(packet_number),
            Some(key_id),
            Some(key_kind),
            WpaDecryptReason::AuthenticationFailed,
        );
    }

    CcmpDecryptResult::decrypted(plaintext, packet_number, key_id, key_kind)
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

/// Build the 13-octet CCMP nonce from the QoS priority, transmitter, and PN.
pub(crate) fn ccmp_nonce(dot11: &Dot11, ccmp: &CcmpHeader<'_>) -> Result<[u8; CCMP_NONCE_LEN]> {
    let fields = ccmp_frame_fields(dot11, "ccmp.nonce.frame")?;
    let mut nonce = [0u8; CCMP_NONCE_LEN];

    nonce[0] = fields
        .qos_control
        .map(|qos| (qos & CCMP_NONCE_QOS_PRIORITY_MASK) as u8)
        .unwrap_or_default();
    nonce[1..7].copy_from_slice(&fields.transmitter.octets());
    nonce[7..].copy_from_slice(&ccmp.packet_number_nonce_bytes());

    Ok(nonce)
}

/// Build CCMP additional authenticated data for supported protected data frames.
pub(crate) fn ccmp_aad(dot11: &Dot11) -> Result<Vec<u8>> {
    let fields = ccmp_frame_fields(dot11, "ccmp.aad.frame")?;
    let mut frame_control = fields.frame_control.bits() & CCMP_AAD_FRAME_CONTROL_MASK;

    if fields.qos_control.is_some() {
        frame_control &= !DOT11_FC_ORDER;
    }

    let sequence_control = fields.sequence_control & CCMP_AAD_SEQUENCE_CONTROL_MASK;
    let mut aad = Vec::with_capacity(
        CCMP_AAD_BASE_LEN
            + fields.addr4.map(|_| 6).unwrap_or_default()
            + fields.qos_control.map(|_| 2).unwrap_or_default(),
    );

    aad.extend_from_slice(&frame_control.to_le_bytes());
    aad.extend_from_slice(&fields.addr1.octets());
    aad.extend_from_slice(&fields.addr2.octets());
    aad.extend_from_slice(&fields.addr3.octets());
    aad.extend_from_slice(&sequence_control.to_le_bytes());
    if let Some(addr4) = fields.addr4 {
        aad.extend_from_slice(&addr4.octets());
    }
    if let Some(qos_control) = fields.qos_control {
        aad.extend_from_slice(&(qos_control & CCMP_AAD_QOS_CONTROL_MASK).to_le_bytes());
    }

    Ok(aad)
}

#[derive(Debug, Clone, Copy)]
struct CcmpFrameFields {
    frame_control: Dot11FrameControl,
    addr1: MacAddr,
    addr2: MacAddr,
    addr3: MacAddr,
    addr4: Option<MacAddr>,
    transmitter: MacAddr,
    sequence_control: u16,
    qos_control: Option<u16>,
}

fn ccmp_frame_fields(dot11: &Dot11, field: &'static str) -> Result<CcmpFrameFields> {
    let frame_control = dot11.frame_control_value();

    if frame_control.frame_type_value() != Dot11FrameType::Data {
        return Err(CrafterError::invalid_field_value(
            field,
            "only data frames are supported",
        ));
    }
    if !frame_control.protected() {
        return Err(CrafterError::invalid_field_value(
            field,
            "only protected data frames are supported",
        ));
    }
    if dot11.is_fragmented() {
        return Err(CrafterError::invalid_field_value(
            field,
            "fragmented data frames are not supported",
        ));
    }

    let subtype = frame_control
        .data_subtype_value()
        .ok_or_else(|| CrafterError::invalid_field_value(field, "missing data subtype"))?;
    if !ccmp_data_subtype_carries_payload(subtype) {
        return Err(CrafterError::invalid_field_value(
            field,
            "data subtype does not carry a payload",
        ));
    }

    let qos_control = if ccmp_data_subtype_has_qos(subtype) {
        Some(
            dot11
                .qos_control_value()
                .ok_or_else(|| CrafterError::invalid_field_value(field, "missing QoS control"))?,
        )
    } else {
        if frame_control.order() {
            return Err(CrafterError::invalid_field_value(
                field,
                "HT control without QoS data is not supported",
            ));
        }
        None
    };

    let addr4 = if frame_control.to_ds() && frame_control.from_ds() {
        Some(
            dot11
                .fourth_address()
                .ok_or_else(|| CrafterError::invalid_field_value(field, "missing address 4"))?,
        )
    } else {
        None
    };

    Ok(CcmpFrameFields {
        frame_control,
        addr1: dot11
            .addr1_value()
            .ok_or_else(|| CrafterError::invalid_field_value(field, "missing address 1"))?,
        addr2: dot11
            .addr2_value()
            .ok_or_else(|| CrafterError::invalid_field_value(field, "missing address 2"))?,
        addr3: dot11
            .addr3_value()
            .ok_or_else(|| CrafterError::invalid_field_value(field, "missing address 3"))?,
        addr4,
        transmitter: dot11
            .transmitter()
            .ok_or_else(|| CrafterError::invalid_field_value(field, "missing transmitter"))?,
        sequence_control: dot11
            .sequence_control_value()
            .ok_or_else(|| CrafterError::invalid_field_value(field, "missing sequence control"))?
            .bits(),
        qos_control,
    })
}

const fn ccmp_data_subtype_carries_payload(subtype: Dot11DataSubtype) -> bool {
    matches!(
        subtype,
        Dot11DataSubtype::Data
            | Dot11DataSubtype::DataCfAck
            | Dot11DataSubtype::DataCfPoll
            | Dot11DataSubtype::DataCfAckCfPoll
            | Dot11DataSubtype::QosData
            | Dot11DataSubtype::QosDataCfAck
            | Dot11DataSubtype::QosDataCfPoll
            | Dot11DataSubtype::QosDataCfAckCfPoll
    )
}

const fn ccmp_data_subtype_has_qos(subtype: Dot11DataSubtype) -> bool {
    matches!(
        subtype,
        Dot11DataSubtype::QosData
            | Dot11DataSubtype::QosDataCfAck
            | Dot11DataSubtype::QosDataCfPoll
            | Dot11DataSubtype::QosDataCfAckCfPoll
    )
}

#[cfg(test)]
pub(crate) fn ccmp_body_for_tests(key_id: u8, pn: [u8; 6], encrypted_payload: &[u8]) -> Vec<u8> {
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

#[cfg(test)]
pub(crate) fn encrypt_unicast_for_tests(
    dot11: &Dot11,
    temporal_key: &[u8; WPA_PTK_TEMPORAL_KEY_LEN],
    key_id: u8,
    pn: [u8; 6],
    plaintext: &[u8],
) -> Vec<u8> {
    let header_body = ccmp_body_for_tests(key_id, pn, &[]);
    let ccmp = CcmpHeader::parse(&header_body).unwrap();
    let nonce = ccmp_nonce(dot11, &ccmp).unwrap();
    let aad = ccmp_aad(dot11).unwrap();
    let cipher = Aes128Ccmp::new_from_slice(temporal_key)
        .expect("WPA2-PSK CCMP temporal key length is AES-128");
    let mut encrypted = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut encrypted)
        .unwrap();
    encrypted.extend_from_slice(&tag);
    ccmp_body_for_tests(key_id, pn, &encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dot11, Dot11QosControl, Dot11SequenceControl, MacAddr};

    fn ccmp_body(key_id: u8, pn: [u8; 6], encrypted_payload: &[u8]) -> Vec<u8> {
        ccmp_body_for_tests(key_id, pn, encrypted_payload)
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x11, 0x00, last])
    }

    fn protected(dot11: Dot11) -> Dot11 {
        let frame_control = dot11.frame_control_value().with_protected(true);
        dot11.frame_control(frame_control)
    }

    fn data_frame() -> Dot11 {
        protected(Dot11::data())
            .addr1(mac(1))
            .addr2(mac(2))
            .addr3(mac(3))
            .sequence_control(Dot11SequenceControl::new().with_sequence_number(0xabc))
    }

    fn qos_data_frame() -> Dot11 {
        protected(Dot11::qos_data())
            .addr1(mac(1))
            .addr2(mac(2))
            .addr3(mac(3))
            .sequence_control(Dot11SequenceControl::new().with_sequence_number(0xabc))
            .with_qos_control_fields(Dot11QosControl::from_bits(0xabcd))
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

    #[test]
    fn nonce_uses_zero_priority_for_plain_data() {
        let body = ccmp_body(0, [1, 2, 3, 4, 5, 6], &[0xaa]);
        let header = CcmpHeader::parse(&body).unwrap();
        let nonce = ccmp_nonce(&data_frame(), &header).unwrap();

        assert_eq!(
            nonce,
            [0, 0x02, 0x00, 0x5e, 0x11, 0x00, 0x02, 6, 5, 4, 3, 2, 1]
        );
    }

    #[test]
    fn nonce_uses_qos_tid_as_priority() {
        let body = ccmp_body(0, [1, 2, 3, 4, 5, 6], &[0xaa]);
        let header = CcmpHeader::parse(&body).unwrap();
        let nonce = ccmp_nonce(&qos_data_frame(), &header).unwrap();

        assert_eq!(nonce[0], 0x0d);
        assert_eq!(&nonce[1..7], &mac(2).octets());
        assert_eq!(&nonce[7..], &[6, 5, 4, 3, 2, 1]);
    }

    #[test]
    fn nonce_rejects_unprotected_data() {
        let body = ccmp_body(0, [1, 2, 3, 4, 5, 6], &[]);
        let header = CcmpHeader::parse(&body).unwrap();
        let error = ccmp_nonce(&Dot11::data(), &header).unwrap_err();

        assert_eq!(
            error,
            CrafterError::InvalidFieldValue {
                field: "ccmp.nonce.frame",
                reason: "only protected data frames are supported",
            }
        );
    }

    #[test]
    fn aad_builds_plain_data_header_fields() {
        let aad = ccmp_aad(&data_frame()).unwrap();

        assert_eq!(aad.len(), CCMP_AAD_BASE_LEN);
        assert_eq!(&aad[0..2], &0x4008u16.to_le_bytes());
        assert_eq!(&aad[2..8], &mac(1).octets());
        assert_eq!(&aad[8..14], &mac(2).octets());
        assert_eq!(&aad[14..20], &mac(3).octets());
        assert_eq!(&aad[20..22], &[0, 0]);
    }

    #[test]
    fn aad_builds_qos_data_with_masked_qos_control() {
        let mut dot11 = qos_data_frame();
        let frame_control = dot11.frame_control_value().with_order(true);
        dot11 = dot11.frame_control(frame_control).ht_control(0x1234_5678);
        let aad = ccmp_aad(&dot11).unwrap();

        assert_eq!(aad.len(), CCMP_AAD_BASE_LEN + 2);
        assert_eq!(&aad[0..2], &0x4088u16.to_le_bytes());
        assert_eq!(&aad[20..22], &[0, 0]);
        assert_eq!(&aad[22..24], &[0x0d, 0x00]);
    }

    #[test]
    fn aad_preserves_to_ds_address_fields() {
        let mut dot11 = data_frame().addr1(mac(10)).addr2(mac(11)).addr3(mac(12));
        let frame_control = dot11.frame_control_value().with_to_ds(true);
        dot11 = dot11.frame_control(frame_control);
        let aad = ccmp_aad(&dot11).unwrap();

        assert_eq!(&aad[0..2], &0x4108u16.to_le_bytes());
        assert_eq!(&aad[2..8], &mac(10).octets());
        assert_eq!(&aad[8..14], &mac(11).octets());
        assert_eq!(&aad[14..20], &mac(12).octets());
    }

    #[test]
    fn aad_preserves_from_ds_address_fields() {
        let mut dot11 = data_frame().addr1(mac(20)).addr2(mac(21)).addr3(mac(22));
        let frame_control = dot11.frame_control_value().with_from_ds(true);
        dot11 = dot11.frame_control(frame_control);
        let aad = ccmp_aad(&dot11).unwrap();

        assert_eq!(&aad[0..2], &0x4208u16.to_le_bytes());
        assert_eq!(&aad[2..8], &mac(20).octets());
        assert_eq!(&aad[8..14], &mac(21).octets());
        assert_eq!(&aad[14..20], &mac(22).octets());
    }

    #[test]
    fn aad_includes_four_address_fields_where_supported() {
        let mut dot11 = qos_data_frame()
            .addr1(mac(30))
            .addr2(mac(31))
            .addr3(mac(32))
            .addr4(mac(33));
        let frame_control = dot11
            .frame_control_value()
            .with_to_ds(true)
            .with_from_ds(true);
        dot11 = dot11.frame_control(frame_control);
        let aad = ccmp_aad(&dot11).unwrap();

        assert_eq!(aad.len(), CCMP_AAD_BASE_LEN + 6 + 2);
        assert_eq!(&aad[0..2], &0x4388u16.to_le_bytes());
        assert_eq!(&aad[2..8], &mac(30).octets());
        assert_eq!(&aad[8..14], &mac(31).octets());
        assert_eq!(&aad[14..20], &mac(32).octets());
        assert_eq!(&aad[22..28], &mac(33).octets());
        assert_eq!(&aad[28..30], &[0x0d, 0x00]);
    }

    #[test]
    fn aad_masks_sequence_number_and_mutable_frame_control_bits() {
        let mut dot11 =
            data_frame().sequence_control(Dot11SequenceControl::new().with_sequence_number(0xfff));
        let frame_control = dot11
            .frame_control_value()
            .with_retry(true)
            .with_power_management(true)
            .with_more_data(true);
        dot11 = dot11.frame_control(frame_control);
        let aad = ccmp_aad(&dot11).unwrap();

        assert_eq!(&aad[0..2], &0x4008u16.to_le_bytes());
        assert_eq!(&aad[20..22], &[0, 0]);
    }

    #[test]
    fn aad_rejects_unsupported_fragmented_data() {
        let error = ccmp_aad(&data_frame().fragment_number(1)).unwrap_err();

        assert_eq!(
            error,
            CrafterError::InvalidFieldValue {
                field: "ccmp.aad.frame",
                reason: "fragmented data frames are not supported",
            }
        );

        let error = ccmp_aad(&data_frame().more_fragments(true)).unwrap_err();
        assert_eq!(
            error,
            CrafterError::InvalidFieldValue {
                field: "ccmp.aad.frame",
                reason: "fragmented data frames are not supported",
            }
        );
    }

    #[test]
    fn decrypt_unicast_authenticates_and_returns_plaintext_metadata() {
        let dot11 = data_frame();
        let key = [0x41; WPA_PTK_TEMPORAL_KEY_LEN];
        let plaintext = b"\xaa\xaa\x03\x00\x00\x00\x08\x00payload";
        let body = encrypt_unicast_for_tests(&dot11, &key, 1, [1, 2, 3, 4, 5, 6], plaintext);

        let decrypted = decrypt_unicast(&dot11, &body, &key, None);

        assert!(decrypted.is_decrypted());
        assert_eq!(decrypted.plaintext(), Some(plaintext.as_slice()));
        assert_eq!(decrypted.packet_number(), Some(0x0605_0403_0201));
        assert_eq!(decrypted.key_id(), Some(1));
        assert_eq!(decrypted.key_kind(), Some(WpaKeyKind::Pairwise));
        assert_eq!(decrypted.failure_reason(), None);
    }

    #[test]
    fn decrypt_unicast_rejects_wrong_key_modified_ciphertext_and_modified_aad() {
        let dot11 = data_frame();
        let key = [0x42; WPA_PTK_TEMPORAL_KEY_LEN];
        let plaintext = b"plaintext";
        let body = encrypt_unicast_for_tests(&dot11, &key, 0, [1, 0, 0, 0, 0, 0], plaintext);

        let wrong_key = [0x24; WPA_PTK_TEMPORAL_KEY_LEN];
        let failed = decrypt_unicast(&dot11, &body, &wrong_key, None);
        assert_eq!(
            failed.failure_reason(),
            Some(WpaDecryptReason::AuthenticationFailed)
        );
        assert_eq!(failed.plaintext(), None);

        let mut modified_body = body.clone();
        modified_body[CCMP_HEADER_LEN] ^= 0x80;
        let failed = decrypt_unicast(&dot11, &modified_body, &key, None);
        assert_eq!(
            failed.failure_reason(),
            Some(WpaDecryptReason::AuthenticationFailed)
        );

        let modified_aad = dot11.clone().addr1(mac(9));
        let failed = decrypt_unicast(&modified_aad, &body, &key, None);
        assert_eq!(
            failed.failure_reason(),
            Some(WpaDecryptReason::AuthenticationFailed)
        );
    }

    #[test]
    fn decrypt_unicast_rejects_replayed_packet_numbers_before_decrypting() {
        let dot11 = data_frame();
        let key = [0x43; WPA_PTK_TEMPORAL_KEY_LEN];
        let body = encrypt_unicast_for_tests(&dot11, &key, 0, [2, 0, 0, 0, 0, 0], b"payload");

        let replayed = decrypt_unicast(&dot11, &body, &key, Some(2));

        assert_eq!(
            replayed.failure_reason(),
            Some(WpaDecryptReason::ReplayDetected)
        );
        assert_eq!(replayed.packet_number(), Some(2));
        assert_eq!(replayed.plaintext(), None);
    }

    #[test]
    fn decrypt_unicast_preserves_unknown_plaintext_as_plain_bytes() {
        let dot11 = data_frame();
        let key = [0x44; WPA_PTK_TEMPORAL_KEY_LEN];
        let plaintext = b"not an llc snap frame";
        let body = encrypt_unicast_for_tests(&dot11, &key, 0, [3, 0, 0, 0, 0, 0], plaintext);

        let decrypted = decrypt_unicast(&dot11, &body, &key, None);

        assert_eq!(decrypted.plaintext(), Some(plaintext.as_slice()));
        assert_eq!(decrypted.failure_reason(), None);
    }
}
