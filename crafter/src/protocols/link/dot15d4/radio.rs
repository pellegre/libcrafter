//! IEEE 802.15.4 radio pseudo-header metadata.
//!
//! `Dot15d4Radio` is the 802.15.4 analog of the BLE `BleRadio` pseudo-header:
//! a radio descriptor carrying channel, RSSI, FCS validity, LQI, and FCS-type
//! metadata. It serializes to the `LINKTYPE_IEEE802_15_4_TAP` (DLT 283) TLV
//! pseudo-header and bridges to WHAD receive metadata. This module defines the
//! struct, builders, resolver helpers, the TAP encode/decode, and the [`Layer`]
//! implementation.

use core::any::Any;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

use super::consts::DOT15D4_CHANNEL_MIN;

/// Documented default 2.4 GHz O-QPSK PHY channel used when the caller leaves
/// the channel unset (the lowest channel, IEEE 802.15.4 channel 11).
const DOT15D4_RADIO_DEFAULT_CHANNEL: u8 = DOT15D4_CHANNEL_MIN;
/// Documented default FCS validity used when the caller leaves it unset.
///
/// Crafted frames carry a freshly auto-filled FCS, so the descriptor reports a
/// valid FCS unless a backend or caller says otherwise.
const DOT15D4_RADIO_DEFAULT_FCS_VALID: bool = true;

// IEEE 802.15.4 TAP (`LINKTYPE_IEEE802_15_4_TAP`, DLT 283) pseudo-header
// constants. Source: IEEE 802.15.4 TAP Link Type Specification v1.3 (Exegin),
// recorded in `.agents/docs/dot15d4-manifest.md` (step 01). The TAP packet is
// laid out as a fixed 4-octet header (version u8, reserved u8, length u16)
// followed by zero or more TLV records (type u16, length u16, value zero-padded
// to a 32-bit boundary). All data fields are little-endian.

/// TAP pseudo-header format version. Only version 0 is defined.
const DOT15D4_TAP_VERSION: u8 = 0;
/// TAP fixed-header length in octets (version u8 + reserved u8 + length u16).
const DOT15D4_TAP_HEADER_LEN: usize = 4;
/// TAP TLV record header length in octets (type u16 + length u16).
const DOT15D4_TAP_TLV_HEADER_LEN: usize = 4;
/// TAP TLV 32-bit value alignment, in octets (values are zero-padded to it).
const DOT15D4_TAP_TLV_ALIGN: usize = 4;

/// TAP `FCS_TYPE` TLV type identifier. Value is a single octet FCS type
/// (0 = none, 1 = 16-bit CRC, 2 = 32-bit CRC) zero-padded to 32 bits.
const DOT15D4_TAP_TLV_FCS_TYPE: u16 = 0;
/// TAP `RSS` TLV type identifier. Value is the received signal strength in dBm
/// as a 32-bit IEEE-754 float.
const DOT15D4_TAP_TLV_RSS: u16 = 1;
/// TAP `CHANNEL_ASSIGNMENT` TLV type identifier. Value is a 16-bit channel
/// number plus an 8-bit channel page, zero-padded to 32 bits.
const DOT15D4_TAP_TLV_CHANNEL_ASSIGNMENT: u16 = 3;

/// TAP `FCS_TYPE` value declaring a 16-bit CRC FCS follows the PHY payload.
const DOT15D4_TAP_FCS_TYPE_CRC16: u8 = 1;
/// TAP `FCS_TYPE` value declaring no FCS follows the PHY payload.
const DOT15D4_TAP_FCS_TYPE_NONE: u8 = 0;
/// Channel page for the 2.4 GHz O-QPSK PHY (channel page 0).
const DOT15D4_TAP_CHANNEL_PAGE_2P4_GHZ: u8 = 0;

/// IEEE 802.15.4 radio descriptor preceding a MAC frame.
///
/// Carries the radio metadata that the `LINKTYPE_IEEE802_15_4_TAP` pseudo-header
/// and the WHAD receive descriptor express: physical channel, RSSI, FCS
/// validity, LQI, and FCS type. Fields use [`Field`] so callers can override any
/// value while unset fields fall back to documented defaults at encode time.
#[derive(Debug)]
pub struct Dot15d4Radio {
    /// 2.4 GHz O-QPSK PHY channel number (11-26).
    ///
    /// This descriptor field maps to both the TAP pseudo-header and the WHAD
    /// radio descriptor fields.
    channel: Field<u8>,
    /// Receive-only RSSI metadata, in dBm, when a backend reports it.
    ///
    /// This descriptor field maps to both the TAP pseudo-header and the WHAD
    /// radio descriptor fields.
    rssi: Field<i16>,
    /// Receive-only Link Quality Indication metadata when a backend reports it.
    ///
    /// This descriptor field maps to both the TAP pseudo-header and the WHAD
    /// radio descriptor fields.
    lqi: Field<u8>,
    /// Whether the MAC Frame Check Sequence was valid for the frame.
    ///
    /// This descriptor field maps to both the TAP pseudo-header and the WHAD
    /// radio descriptor fields.
    fcs_valid: Field<bool>,
    /// FCS type carried by the frame (TAP FCS-type TLV codepoint).
    ///
    /// This descriptor field maps to both the TAP pseudo-header and the WHAD
    /// radio descriptor fields.
    fcs_type: Field<u8>,
}

impl Clone for Dot15d4Radio {
    fn clone(&self) -> Self {
        Self {
            channel: self.channel.clone(),
            rssi: self.rssi.clone(),
            lqi: self.lqi.clone(),
            fcs_valid: self.fcs_valid.clone(),
            fcs_type: self.fcs_type.clone(),
        }
    }
}

impl Dot15d4Radio {
    /// Create an 802.15.4 radio descriptor with every field unset.
    ///
    /// Unset fields resolve to documented defaults (channel 11, valid FCS) at
    /// encode time through the `effective_*` resolvers.
    pub fn new() -> Self {
        Self {
            channel: Field::unset(),
            rssi: Field::unset(),
            lqi: Field::unset(),
            fcs_valid: Field::unset(),
            fcs_type: Field::unset(),
        }
    }

    /// Create a radio descriptor pinned to a specific 2.4 GHz PHY channel.
    pub fn on_channel(channel: u8) -> Self {
        Self::new().channel(channel)
    }

    /// Set the 2.4 GHz O-QPSK PHY channel number.
    pub fn channel(mut self, channel: u8) -> Self {
        self.channel.set_user(channel);
        self
    }

    /// Set receive-only RSSI metadata, in dBm.
    pub fn rssi(mut self, rssi: i16) -> Self {
        self.rssi.set_user(rssi);
        self
    }

    /// Set receive-only Link Quality Indication metadata.
    pub fn lqi(mut self, lqi: u8) -> Self {
        self.lqi.set_user(lqi);
        self
    }

    /// Set whether the MAC Frame Check Sequence was valid.
    pub fn fcs_valid(mut self, fcs_valid: bool) -> Self {
        self.fcs_valid.set_user(fcs_valid);
        self
    }

    /// Set the FCS type codepoint carried by the frame.
    pub fn fcs_type(mut self, fcs_type: u8) -> Self {
        self.fcs_type.set_user(fcs_type);
        self
    }

    /// Resolved 2.4 GHz PHY channel number, defaulting to channel 11 when unset.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_channel(&self) -> u8 {
        self.channel
            .value()
            .copied()
            .unwrap_or(DOT15D4_RADIO_DEFAULT_CHANNEL)
    }

    /// Resolved RSSI metadata, in dBm, when present.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_rssi(&self) -> Option<i16> {
        self.rssi.value().copied()
    }

    /// Resolved Link Quality Indication metadata when present.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_lqi(&self) -> Option<u8> {
        self.lqi.value().copied()
    }

    /// Resolved FCS validity, defaulting to valid when unset.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_fcs_valid(&self) -> bool {
        self.fcs_valid
            .value()
            .copied()
            .unwrap_or(DOT15D4_RADIO_DEFAULT_FCS_VALID)
    }

    /// Resolved FCS type codepoint when present.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_fcs_type(&self) -> Option<u8> {
        self.fcs_type.value().copied()
    }

    /// Resolved 2.4 GHz PHY channel number for backend translators.
    ///
    /// The WHAD 802.15.4 sniff/inject commands carry the channel number; this
    /// bridge mirrors `BleRadio::effective_channel_for_backend` and resolves the
    /// channel (defaulting to channel 11 when unset).
    #[cfg(feature = "whad")]
    pub(crate) fn effective_channel_for_backend(&self) -> u8 {
        self.effective_channel()
    }

    /// Resolved FCS validity for backend translators.
    ///
    /// The WHAD 802.15.4 send command can request that the firmware append the
    /// FCS; this bridge resolves whether the descriptor reports a valid FCS.
    #[cfg(feature = "whad")]
    pub(crate) fn effective_fcs_valid_for_backend(&self) -> bool {
        self.effective_fcs_valid()
    }

    /// Resolved TAP `FCS_TYPE` value emitted in the pseudo-header.
    ///
    /// An explicit FCS-type codepoint is honored verbatim. Otherwise the value
    /// is derived from FCS validity: a valid FCS reports a 16-bit CRC (the only
    /// FCS this crate auto-fills), while an invalid FCS reports type none.
    fn effective_tap_fcs_type(&self) -> u8 {
        match self.effective_fcs_type() {
            Some(value) => value,
            None if self.effective_fcs_valid() => DOT15D4_TAP_FCS_TYPE_CRC16,
            None => DOT15D4_TAP_FCS_TYPE_NONE,
        }
    }

    /// Length, in octets, of the encoded TAP pseudo-header.
    ///
    /// The fixed 4-octet header plus the FCS-type, RSS, and channel-assignment
    /// TLVs, each padded to a 32-bit boundary. The descriptor always emits
    /// these three TLVs because their fields resolve to documented defaults.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn encoded_len(&self) -> usize {
        DOT15D4_TAP_HEADER_LEN
            + tap_tlv_record_len(1) // FCS_TYPE: 1-octet value
            + tap_tlv_record_len(4) // RSS: 4-octet IEEE-754 float
            + tap_tlv_record_len(3) // CHANNEL_ASSIGNMENT: 3-octet value
    }

    /// Encode the IEEE 802.15.4 TAP (`LINKTYPE_IEEE802_15_4_TAP`, DLT 283)
    /// pseudo-header for this radio descriptor.
    ///
    /// Layout (all little-endian), per the IEEE 802.15.4 TAP Link Type
    /// Specification v1.3 (Exegin), recorded in `.agents/docs/dot15d4-manifest.md`:
    ///
    /// - Fixed 4-octet header: `version` (u8, 0), `reserved` (u8, 0), `length`
    ///   (u16, total length of the header plus all TLVs, a multiple of 4).
    /// - `FCS_TYPE` TLV (type 0, length 1): one octet FCS type (0 = none,
    ///   1 = 16-bit CRC, 2 = 32-bit CRC), then 3 zero-padding octets.
    /// - `RSS` TLV (type 1, length 4): RSS in dBm as a 32-bit IEEE-754 float.
    /// - `CHANNEL_ASSIGNMENT` TLV (type 3, length 3): channel number (u16),
    ///   channel page (u8), then 1 zero-padding octet.
    ///
    /// Every field resolves through the `effective_*` resolvers so unset fields
    /// fall back to documented defaults; user-set values are emitted verbatim
    /// without clamping (a deliberately out-of-range channel is encoded as
    /// given).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let start = out.len();

        // Fixed header: version, reserved, and a length placeholder backfilled
        // once the TLVs are written.
        out.push(DOT15D4_TAP_VERSION);
        out.push(0); // reserved, must be zero
        out.extend_from_slice(&0u16.to_le_bytes()); // length placeholder

        // FCS_TYPE TLV (type 0, length 1): single-octet FCS type, 3 pad octets.
        push_tap_tlv(out, DOT15D4_TAP_TLV_FCS_TYPE, &[self.effective_tap_fcs_type()]);

        // RSS TLV (type 1, length 4): RSS in dBm as a 32-bit IEEE-754 float.
        // Unset RSS resolves to 0.0 dBm, matching the absence of a measurement.
        let rss_dbm = self.effective_rssi().unwrap_or(0) as f32;
        push_tap_tlv(out, DOT15D4_TAP_TLV_RSS, &rss_dbm.to_le_bytes());

        // CHANNEL_ASSIGNMENT TLV (type 3, length 3): channel number (u16),
        // channel page (u8). The 2.4 GHz O-QPSK PHY uses channel page 0.
        let channel = self.effective_channel();
        let mut channel_value = Vec::with_capacity(3);
        channel_value.extend_from_slice(&(channel as u16).to_le_bytes());
        channel_value.push(DOT15D4_TAP_CHANNEL_PAGE_2P4_GHZ);
        push_tap_tlv(out, DOT15D4_TAP_TLV_CHANNEL_ASSIGNMENT, &channel_value);

        // Backfill the total length (header + all TLVs) into the fixed header.
        let total_len = (out.len() - start) as u16;
        out[start + 2..start + 4].copy_from_slice(&total_len.to_le_bytes());
    }
}

/// Total octets a TAP TLV record occupies on the wire for a `value_len`-octet
/// value: the 4-octet TLV header plus the value padded up to a 32-bit boundary.
fn tap_tlv_record_len(value_len: usize) -> usize {
    DOT15D4_TAP_TLV_HEADER_LEN + value_len.div_ceil(DOT15D4_TAP_TLV_ALIGN) * DOT15D4_TAP_TLV_ALIGN
}

/// Append one TAP TLV record (type u16 LE, length u16 LE, value, zero padding to
/// a 32-bit boundary) to `out`.
///
/// `length` carries the value length in octets and does not count the trailing
/// padding, per the TAP TLV format.
fn push_tap_tlv(out: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    out.extend_from_slice(&tlv_type.to_le_bytes());
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value);

    let padding = value.len().next_multiple_of(DOT15D4_TAP_TLV_ALIGN) - value.len();
    out.extend(std::iter::repeat(0u8).take(padding));
}

impl Default for Dot15d4Radio {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode an IEEE 802.15.4 TAP (`LINKTYPE_IEEE802_15_4_TAP`, DLT 283)
/// pseudo-header back into a [`Dot15d4Radio`] descriptor.
///
/// Parses the fixed 4-octet header (validating the version and the declared
/// total length), then walks the TLV records, recovering the FCS type, RSS, and
/// channel-assignment fields. The descriptor plus the remaining bytes following
/// the pseudo-header (the bare MAC frame) are returned.
///
/// Truncation and inconsistent length fields surface as structured
/// [`CrafterError`]s with stable `context`/`field` strings and never panic.
/// Unknown TLV types are skipped, and a frame may follow the pseudo-header or
/// the buffer may end exactly at the header.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn decode_dot15d4_radio(bytes: &[u8]) -> Result<(Dot15d4Radio, &[u8])> {
    if bytes.len() < DOT15D4_TAP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "dot15d4.tap.header",
            DOT15D4_TAP_HEADER_LEN,
            bytes.len(),
        ));
    }

    if bytes[0] != DOT15D4_TAP_VERSION {
        return Err(CrafterError::invalid_field_value(
            "dot15d4.tap.header",
            "unsupported TAP version",
        ));
    }

    // Total length covers the fixed header plus all TLVs; it must be a multiple
    // of the 32-bit TLV alignment, at least the fixed header, and within the
    // available buffer.
    let total_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
    if total_len < DOT15D4_TAP_HEADER_LEN || total_len % DOT15D4_TAP_TLV_ALIGN != 0 {
        return Err(CrafterError::invalid_field_value(
            "dot15d4.tap.header",
            "invalid TAP total length",
        ));
    }
    if bytes.len() < total_len {
        return Err(CrafterError::buffer_too_short(
            "dot15d4.tap.header",
            total_len,
            bytes.len(),
        ));
    }

    let mut radio = Dot15d4Radio::new();
    let mut offset = DOT15D4_TAP_HEADER_LEN;
    while offset < total_len {
        // Each TLV needs at least its 4-octet header (type u16, length u16).
        if total_len - offset < DOT15D4_TAP_TLV_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "dot15d4.tap.tlv",
                DOT15D4_TAP_TLV_HEADER_LEN,
                total_len - offset,
            ));
        }

        let tlv_type = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let value_len = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let value_start = offset + DOT15D4_TAP_TLV_HEADER_LEN;
        // The value is zero-padded up to a 32-bit boundary; the padded record
        // must stay within the declared total length.
        let padded_value_len = value_len.next_multiple_of(DOT15D4_TAP_TLV_ALIGN);
        let record_len = DOT15D4_TAP_TLV_HEADER_LEN + padded_value_len;
        if total_len - offset < record_len {
            return Err(CrafterError::buffer_too_short(
                "dot15d4.tap.tlv",
                record_len,
                total_len - offset,
            ));
        }

        let value = &bytes[value_start..value_start + value_len];
        match tlv_type {
            DOT15D4_TAP_TLV_FCS_TYPE => {
                if value_len < 1 {
                    return Err(CrafterError::invalid_field_value(
                        "dot15d4.tap.tlv",
                        "FCS_TYPE TLV value too short",
                    ));
                }
                let fcs_type = value[0];
                radio.fcs_type.set_user(fcs_type);
                radio
                    .fcs_valid
                    .set_user(fcs_type != DOT15D4_TAP_FCS_TYPE_NONE);
            }
            DOT15D4_TAP_TLV_RSS => {
                if value_len < 4 {
                    return Err(CrafterError::invalid_field_value(
                        "dot15d4.tap.tlv",
                        "RSS TLV value too short",
                    ));
                }
                let rss = f32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                radio.rssi.set_user(rss as i16);
            }
            DOT15D4_TAP_TLV_CHANNEL_ASSIGNMENT => {
                if value_len < 2 {
                    return Err(CrafterError::invalid_field_value(
                        "dot15d4.tap.tlv",
                        "CHANNEL_ASSIGNMENT TLV value too short",
                    ));
                }
                let channel = u16::from_le_bytes([value[0], value[1]]);
                radio.channel.set_user(channel as u8);
            }
            // Unknown TLV types are preserved by skipping rather than failing.
            _ => {}
        }

        offset += record_len;
    }

    Ok((radio, &bytes[total_len..]))
}

impl Layer for Dot15d4Radio {
    fn name(&self) -> &'static str {
        "Dot15d4Radio"
    }

    fn summary(&self) -> String {
        let fcs = if self.effective_fcs_valid() {
            "fcs_ok"
        } else {
            "fcs_bad"
        };
        match self.effective_rssi() {
            Some(rssi) => format!(
                "Dot15d4Radio(ch={}, rssi={}, {})",
                self.effective_channel(),
                rssi,
                fcs
            ),
            None => format!("Dot15d4Radio(ch={}, {})", self.effective_channel(), fcs),
        }
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("channel", self.effective_channel().to_string())];

        if let Some(rssi) = self.effective_rssi() {
            fields.push(("rssi", rssi.to_string()));
        }
        if let Some(lqi) = self.effective_lqi() {
            fields.push(("lqi", lqi.to_string()));
        }
        fields.push(("fcs_valid", self.effective_fcs_valid().to_string()));

        fields
    }

    fn encoded_len(&self) -> usize {
        Dot15d4Radio::encoded_len(self)
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

impl<R: IntoPacket> core::ops::Div<R> for Dot15d4Radio {
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

#[cfg(test)]
mod tests {
    use crate::field::FieldState;
    use crate::packet::{Packet, Raw};

    use super::*;

    #[test]
    fn dot15d4_radio_builder_defaults_resolve_when_unset() {
        let radio = Dot15d4Radio::new();

        assert_eq!(radio.channel.state(), FieldState::Unset);
        assert_eq!(radio.rssi.state(), FieldState::Unset);
        assert_eq!(radio.lqi.state(), FieldState::Unset);
        assert_eq!(radio.fcs_valid.state(), FieldState::Unset);
        assert_eq!(radio.fcs_type.state(), FieldState::Unset);

        assert_eq!(radio.effective_channel(), DOT15D4_CHANNEL_MIN);
        assert_eq!(radio.effective_rssi(), None);
        assert_eq!(radio.effective_lqi(), None);
        assert!(radio.effective_fcs_valid());
        assert_eq!(radio.effective_fcs_type(), None);
    }

    #[test]
    fn dot15d4_radio_builder_setters_mark_fields_user() {
        let radio = Dot15d4Radio::new()
            .channel(15)
            .rssi(-58)
            .lqi(200)
            .fcs_valid(false)
            .fcs_type(1);

        assert_eq!(radio.channel.state(), FieldState::User);
        assert_eq!(radio.rssi.state(), FieldState::User);
        assert_eq!(radio.lqi.state(), FieldState::User);
        assert_eq!(radio.fcs_valid.state(), FieldState::User);
        assert_eq!(radio.fcs_type.state(), FieldState::User);

        assert_eq!(radio.effective_channel(), 15);
        assert_eq!(radio.effective_rssi(), Some(-58));
        assert_eq!(radio.effective_lqi(), Some(200));
        assert!(!radio.effective_fcs_valid());
        assert_eq!(radio.effective_fcs_type(), Some(1));
    }

    #[test]
    fn dot15d4_radio_builder_on_channel_sets_channel_user() {
        let radio = Dot15d4Radio::on_channel(26);

        assert_eq!(radio.channel.state(), FieldState::User);
        assert_eq!(radio.effective_channel(), 26);
        // Remaining descriptor fields stay unset and resolve to defaults.
        assert_eq!(radio.rssi.state(), FieldState::Unset);
        assert!(radio.effective_fcs_valid());
    }

    #[test]
    fn dot15d4_radio_encode() {
        // Channel 15, RSSI -60 dBm, valid (16-bit CRC) FCS. The reference bytes
        // are hand-derived from the IEEE 802.15.4 TAP Link Type Specification
        // v1.3 (Exegin), recorded in `.agents/docs/dot15d4-manifest.md`. All
        // fields are little-endian.
        let radio = Dot15d4Radio::new().channel(15).rssi(-60).fcs_valid(true);

        let mut out = Vec::new();
        radio.encode(&mut out);

        // -60.0 as a 32-bit IEEE-754 float is 0xC2700000, little-endian
        // [0x00, 0x00, 0x70, 0xC2].
        assert_eq!(
            (-60.0f32).to_le_bytes(),
            [0x00, 0x00, 0x70, 0xC2],
            "RSS float reference must match IEEE-754 little-endian encoding"
        );

        #[rustfmt::skip]
        let expected: &[u8] = &[
            // Fixed header: version 0, reserved 0, length = 28 (0x001C LE).
            // 4 (header) + 8 (FCS_TYPE TLV) + 8 (RSS TLV) + 8 (CHANNEL TLV) = 28.
            0x00, 0x00, 0x1C, 0x00,
            // FCS_TYPE TLV: type 0, length 1, value 1 (16-bit CRC), 3 pad octets.
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            // RSS TLV: type 1, length 4, value f32(-60.0) little-endian.
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x70, 0xC2,
            // CHANNEL_ASSIGNMENT TLV: type 3, length 3, channel 15 (u16 LE),
            // channel page 0, 1 pad octet.
            0x03, 0x00, 0x03, 0x00, 0x0F, 0x00, 0x00, 0x00,
        ];

        assert_eq!(out.as_slice(), expected);

        // The little-endian total-length field must equal the emitted length
        // and cover the fixed header plus all TLVs.
        let length = u16::from_le_bytes([out[2], out[3]]);
        assert_eq!(length as usize, out.len());
        assert_eq!(out.len(), radio.encoded_len());
        // Length is a multiple of 4 (32-bit TLV alignment).
        assert_eq!(length % 4, 0);
    }

    #[test]
    fn dot15d4_radio_encode_defaults_resolve_when_unset() {
        // Every field unset: channel 11, RSS 0.0 dBm, valid (16-bit CRC) FCS.
        let radio = Dot15d4Radio::new();

        let mut out = Vec::new();
        radio.encode(&mut out);

        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x00, 0x00, 0x1C, 0x00,
            // FCS_TYPE TLV: valid FCS resolves to 16-bit CRC (1).
            0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            // RSS TLV: unset RSS resolves to 0.0 dBm (all-zero float).
            0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            // CHANNEL_ASSIGNMENT TLV: default channel 11, page 0.
            0x03, 0x00, 0x03, 0x00, 0x0B, 0x00, 0x00, 0x00,
        ];

        assert_eq!(out.as_slice(), expected);
        assert_eq!(out.len(), radio.encoded_len());
    }

    #[test]
    fn dot15d4_radio_encode_honors_out_of_range_channel_without_clamping() {
        // A deliberately out-of-range channel (200) must be emitted verbatim;
        // malformed-on-purpose descriptors are supported.
        let radio = Dot15d4Radio::new().channel(200).fcs_valid(false);

        let mut out = Vec::new();
        radio.encode(&mut out);

        // FCS_TYPE: invalid FCS resolves to type none (0).
        assert_eq!(&out[4..12], &[0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // CHANNEL_ASSIGNMENT: channel 200 (0x00C8 LE) emitted without clamping.
        assert_eq!(&out[20..28], &[0x03, 0x00, 0x03, 0x00, 0xC8, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn dot15d4_radio_layer_compile_equals_encode() {
        // Compiling the descriptor through the packet stack must emit exactly the
        // same TAP bytes the standalone encoder produces.
        let radio = Dot15d4Radio::new().channel(15).rssi(-60).fcs_valid(true);

        let mut encoded = Vec::new();
        radio.encode(&mut encoded);

        let compiled = Packet::from_layer(radio.clone())
            .compile()
            .expect("compile Dot15d4Radio TAP pseudo-header");

        assert_eq!(compiled.as_bytes(), encoded.as_slice());
        assert_eq!(compiled.len(), radio.encoded_len());
    }

    #[test]
    fn dot15d4_radio_layer_summary_text() {
        let with_rssi = Dot15d4Radio::new().channel(15).rssi(-60).fcs_valid(true);
        assert_eq!(with_rssi.summary(), "Dot15d4Radio(ch=15, rssi=-60, fcs_ok)");

        let invalid_fcs = Dot15d4Radio::new().channel(20).fcs_valid(false);
        assert_eq!(invalid_fcs.summary(), "Dot15d4Radio(ch=20, fcs_bad)");

        // The packet summary surfaces the layer summary fields.
        let summary = Packet::from_layer(with_rssi).summary();
        assert!(summary.contains("ch=15"));
        assert!(summary.contains("rssi=-60"));
        assert!(summary.contains("fcs_ok"));
    }

    #[test]
    fn dot15d4_radio_layer_inspection_fields_list_channel_rssi_lqi_fcs_valid() {
        let radio = Dot15d4Radio::new()
            .channel(15)
            .rssi(-60)
            .lqi(200)
            .fcs_valid(true);

        let fields = radio.inspection_fields();

        assert!(fields.contains(&("channel", "15".to_string())));
        assert!(fields.contains(&("rssi", "-60".to_string())));
        assert!(fields.contains(&("lqi", "200".to_string())));
        assert!(fields.contains(&("fcs_valid", "true".to_string())));
    }

    #[test]
    fn dot15d4_radio_layer_round_trips_compiled_pseudo_header() {
        let radio = Dot15d4Radio::new().channel(15).rssi(-60).fcs_valid(true);
        let mut bytes = Vec::new();
        radio.encode(&mut bytes);
        // Append a trailing MAC frame so decode returns the remaining bytes.
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        let (decoded, tail) =
            decode_dot15d4_radio(&bytes).expect("decode Dot15d4Radio TAP pseudo-header");

        assert_eq!(tail, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(decoded.effective_channel(), 15);
        assert_eq!(decoded.effective_rssi(), Some(-60));
        assert_eq!(decoded.effective_fcs_type(), Some(DOT15D4_TAP_FCS_TYPE_CRC16));
        assert!(decoded.effective_fcs_valid());
    }

    #[test]
    fn dot15d4_radio_decode_reports_invalid_fcs_when_type_none() {
        // FCS type none (NOFCS-style capture) must still decode and report the
        // FCS as invalid through the descriptor rather than rejecting the frame.
        let radio = Dot15d4Radio::new().channel(11).fcs_valid(false);
        let mut bytes = Vec::new();
        radio.encode(&mut bytes);

        let (decoded, tail) =
            decode_dot15d4_radio(&bytes).expect("decode NOFCS-style TAP pseudo-header");

        assert!(tail.is_empty());
        assert!(!decoded.effective_fcs_valid());
        assert_eq!(decoded.effective_fcs_type(), Some(DOT15D4_TAP_FCS_TYPE_NONE));
    }

    #[test]
    fn dot15d4_radio_decode_truncated_header_is_structured_error() {
        let err = decode_dot15d4_radio(&[0x00, 0x00, 0x1C])
            .expect_err("must reject a truncated TAP fixed header");

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: "dot15d4.tap.header",
                required: DOT15D4_TAP_HEADER_LEN,
                available: 3,
            }
        );
    }

    #[test]
    fn dot15d4_radio_decode_truncated_tlv_body_is_structured_error_not_panic() {
        // Declares a 28-octet total length but supplies only the fixed header
        // plus a single full TLV (12 octets), so walking the remaining TLVs
        // must surface a structured error rather than panicking.
        let mut bytes = Vec::new();
        radio_encode_only_header(&mut bytes, 28);
        // One complete FCS_TYPE TLV (8 octets), leaving the declared length
        // pointing past the supplied bytes.
        bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00]);

        let err = decode_dot15d4_radio(&bytes)
            .expect_err("must reject a TAP header whose declared length exceeds the buffer");

        assert_eq!(
            err,
            CrafterError::BufferTooShort {
                context: "dot15d4.tap.header",
                required: 28,
                available: bytes.len(),
            }
        );
    }

    #[test]
    fn dot15d4_radio_decode_rejects_unsupported_version() {
        let err = decode_dot15d4_radio(&[0x01, 0x00, 0x04, 0x00])
            .expect_err("must reject an unsupported TAP version");

        assert_eq!(
            err,
            CrafterError::invalid_field_value("dot15d4.tap.header", "unsupported TAP version")
        );
    }

    #[test]
    fn dot15d4_radio_decode_skips_unknown_tlv() {
        // Fixed header (length 12) + one unknown TLV (type 0x00FF, length 4,
        // 4-octet value): 4 (header) + 4 (TLV header) + 4 (value) = 12.
        let mut bytes = Vec::new();
        radio_encode_only_header(&mut bytes, 12);
        bytes.extend_from_slice(&[0xFF, 0x00, 0x04, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);

        let (decoded, tail) =
            decode_dot15d4_radio(&bytes).expect("unknown TLVs must be skipped, not rejected");

        assert!(tail.is_empty());
        // No channel/RSS/FCS TLV present, so resolvers fall back to defaults.
        assert_eq!(decoded.effective_channel(), DOT15D4_CHANNEL_MIN);
        assert_eq!(decoded.effective_rssi(), None);
    }

    #[test]
    fn dot15d4_radio_roundtrip() {
        // Build a radio descriptor with lab-safe values, compile it as a
        // lone-layer packet to TAP bytes, then decode those bytes back and
        // confirm the descriptor fields survive the round-trip.
        let radio = Dot15d4Radio::on_channel(20)
            .rssi(-55)
            .fcs_valid(true)
            .lqi(200);

        let bytes = Packet::from_layer(radio.clone())
            .compile()
            .expect("compile Dot15d4Radio TAP pseudo-header");

        // The compiled bytes are exactly the TAP pseudo-header: the fixed
        // 4-octet header plus the three padded TLVs.
        assert_eq!(bytes.len(), radio.encoded_len());
        assert_eq!(bytes.as_bytes().len(), DOT15D4_TAP_HEADER_LEN + 8 + 8 + 8);

        // The little-endian total-length field in the fixed header equals the
        // emitted length and is a multiple of the 32-bit TLV alignment.
        let total_len = u16::from_le_bytes([bytes.as_bytes()[2], bytes.as_bytes()[3]]);
        assert_eq!(total_len as usize, bytes.as_bytes().len());
        assert_eq!(total_len % DOT15D4_TAP_TLV_ALIGN as u16, 0);

        let (decoded, tail) =
            decode_dot15d4_radio(bytes.as_bytes()).expect("decode Dot15d4Radio TAP pseudo-header");

        // No MAC frame follows the lone descriptor, so the decoded tail is empty.
        assert!(tail.is_empty());
        assert_eq!(decoded.effective_channel(), 20);
        assert_eq!(decoded.effective_rssi(), Some(-55));
        assert!(decoded.effective_fcs_valid());
        // LQI is receive-side metadata that the TAP pseudo-header encoder does
        // not serialize, so it is not recoverable on decode and resolves back to
        // its unset state.
        assert_eq!(decoded.effective_lqi(), None);

        // A truncated pseudo-header surfaces a structured error rather than
        // panicking, even after a successful round-trip.
        let err = decode_dot15d4_radio(&bytes.as_bytes()[..DOT15D4_TAP_HEADER_LEN - 1])
            .expect_err("a truncated TAP fixed header must be a structured error");
        assert_eq!(
            err,
            CrafterError::buffer_too_short(
                "dot15d4.tap.header",
                DOT15D4_TAP_HEADER_LEN,
                DOT15D4_TAP_HEADER_LEN - 1,
            )
        );
    }

    #[test]
    fn dot15d4_radio_div_builds_two_layer_packet() {
        let packet = Dot15d4Radio::on_channel(15) / Raw::from_bytes([0u8; 4]);

        assert_eq!(packet.len(), 2);
        assert!(packet.layer::<Dot15d4Radio>().is_some());
        assert!(packet.layer::<Raw>().is_some());
    }

    /// Write only the fixed 4-octet TAP header with a chosen total-length field.
    fn radio_encode_only_header(out: &mut Vec<u8>, total_len: u16) {
        out.push(DOT15D4_TAP_VERSION);
        out.push(0);
        out.extend_from_slice(&total_len.to_le_bytes());
    }
}
