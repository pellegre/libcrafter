//! IEEE 802.15.4 radio pseudo-header metadata.
//!
//! `Dot15d4Radio` is the 802.15.4 analog of the BLE `BleRadio` pseudo-header:
//! a radio descriptor carrying channel, RSSI, FCS validity, LQI, and FCS-type
//! metadata. It serializes to the `LINKTYPE_IEEE802_15_4_TAP` (DLT 283) TLV
//! pseudo-header and bridges to WHAD receive metadata. Encoding, decoding, and
//! the `Layer` implementation are added in later steps; this module defines the
//! struct, builders, and resolver helpers only.

use crate::field::Field;

use super::consts::DOT15D4_CHANNEL_MIN;

/// Documented default 2.4 GHz O-QPSK PHY channel used when the caller leaves
/// the channel unset (the lowest channel, IEEE 802.15.4 channel 11).
const DOT15D4_RADIO_DEFAULT_CHANNEL: u8 = DOT15D4_CHANNEL_MIN;
/// Documented default FCS validity used when the caller leaves it unset.
///
/// Crafted frames carry a freshly auto-filled FCS, so the descriptor reports a
/// valid FCS unless a backend or caller says otherwise.
const DOT15D4_RADIO_DEFAULT_FCS_VALID: bool = true;

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
}

impl Default for Dot15d4Radio {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::field::FieldState;

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
}
