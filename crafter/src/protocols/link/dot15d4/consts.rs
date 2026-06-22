//! IEEE 802.15.4 and Zigbee constants and codepoints.
//!
//! Values are grounded in `.agents/docs/dot15d4-codepoints.md` and
//! `.agents/docs/dot15d4-manifest.md` (IEEE Std 802.15.4-2020, the Zigbee
//! Specification R23, and the tcpdump.org Link-Layer Header Types registry).

/// Lowest 2.4 GHz O-QPSK PHY channel number (IEEE 802.15.4 channel page 0).
///
/// IEEE Std 802.15.4-2020, Clause 10.1.3.3 (2450 MHz band channel assignments).
pub const DOT15D4_CHANNEL_MIN: u8 = 11;
/// Highest 2.4 GHz O-QPSK PHY channel number (IEEE 802.15.4 channel page 0).
///
/// IEEE Std 802.15.4-2020, Clause 10.1.3.3 (2450 MHz band channel assignments).
pub const DOT15D4_CHANNEL_MAX: u8 = 26;

/// Center frequency, in MHz, of the lowest 2.4 GHz channel (channel 11).
///
/// IEEE Std 802.15.4-2020, Clause 10.1.3.3, channel center-frequency equation.
pub const DOT15D4_CHANNEL_BASE_FREQUENCY_MHZ: u32 = 2405;
/// Channel spacing, in MHz, between adjacent 2.4 GHz channels.
///
/// IEEE Std 802.15.4-2020, Clause 10.1.3.3, channel center-frequency equation.
pub const DOT15D4_CHANNEL_SPACING_MHZ: u32 = 5;

/// Length, in octets, of the MAC Frame Check Sequence (16-bit FCS).
///
/// IEEE Std 802.15.4-2020, Clause 7.2.10, FCS field.
pub const DOT15D4_FCS_LEN: usize = 2;
/// Length, in octets, of the MAC Frame Control field (FCF).
///
/// IEEE Std 802.15.4-2020, Clause 7.2.2, Frame Control field.
pub const DOT15D4_FCF_LEN: usize = 2;
/// Length, in octets, of the MAC Sequence Number field.
///
/// IEEE Std 802.15.4-2020, Clause 7.2.3, Sequence Number field.
pub const DOT15D4_SEQ_LEN: usize = 1;
/// Length, in octets, of a PAN identifier field when present.
///
/// IEEE Std 802.15.4-2020, Clause 7.2.4 through 7.2.8, Addressing fields.
pub const DOT15D4_PAN_ID_LEN: usize = 2;
/// Length, in octets, of a short (16-bit) address field when present.
///
/// IEEE Std 802.15.4-2020, Clause 7.2.4 through 7.2.8, Addressing fields.
pub const DOT15D4_SHORT_ADDR_LEN: usize = 2;
/// Length, in octets, of an extended (64-bit) address field when present.
///
/// IEEE Std 802.15.4-2020, Clause 7.2.4 through 7.2.8, Addressing fields.
pub const DOT15D4_EXTENDED_ADDR_LEN: usize = 8;

/// `LINKTYPE_IEEE802_15_4_WITHFCS` pcap DLT value (frame including trailing FCS).
///
/// tcpdump.org Link-Layer Header Types registry.
pub const DLT_IEEE802_15_4_WITHFCS: u32 = 195;
/// `LINKTYPE_IEEE802_15_4_NOFCS` pcap DLT value (frame without trailing FCS).
///
/// tcpdump.org Link-Layer Header Types registry.
pub const DLT_IEEE802_15_4_NOFCS: u32 = 230;
/// `LINKTYPE_IEEE802_15_4_TAP` pcap DLT value (TAP pseudo-header + frame).
///
/// tcpdump.org Link-Layer Header Types registry.
pub const DLT_IEEE802_15_4_TAP: u32 = 283;

/// Return the center frequency, in MHz, for a 2.4 GHz O-QPSK PHY channel.
///
/// Returns `Some(2405 + 5*(channel - 11))` for channels 11..=26 and `None`
/// otherwise. IEEE Std 802.15.4-2020, Clause 10.1.3.3.
pub const fn channel_frequency_mhz(channel: u8) -> Option<u32> {
    if channel >= DOT15D4_CHANNEL_MIN && channel <= DOT15D4_CHANNEL_MAX {
        Some(
            DOT15D4_CHANNEL_BASE_FREQUENCY_MHZ
                + DOT15D4_CHANNEL_SPACING_MHZ * (channel as u32 - DOT15D4_CHANNEL_MIN as u32),
        )
    } else {
        None
    }
}

/// IEEE 802.15.4 MAC frame type (Frame Control field bits 0-2).
///
/// IEEE Std 802.15.4-2020, Clause 7.2.2.1, Table 7-1. Only the frame types
/// this crate models as typed builders are represented; reserved and extended
/// values (4-7) return `None` from [`Dot15d4FrameType::from_u3`] so the decoder
/// can preserve them structurally as raw rather than failing.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dot15d4FrameType {
    Beacon = 0,
    Data = 1,
    Ack = 2,
    MacCommand = 3,
}

impl Dot15d4FrameType {
    /// Convert a three-bit frame type codepoint to a modeled value.
    ///
    /// Returns `None` for reserved/extended values (4-7), which the decoder
    /// preserves structurally rather than modeling as a typed builder.
    pub const fn from_u3(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Beacon),
            1 => Some(Self::Data),
            2 => Some(Self::Ack),
            3 => Some(Self::MacCommand),
            _ => None,
        }
    }

    /// Return the three-bit frame type codepoint.
    pub const fn as_u3(self) -> u8 {
        self as u8
    }
}

/// IEEE 802.15.4 addressing mode (destination bits 10-11 / source bits 14-15).
///
/// IEEE Std 802.15.4-2020, Clause 7.2.2.8 / 7.2.2.10, Table 7-3. The reserved
/// value `0b01` is preserved structurally and returns `None` from
/// [`Dot15d4AddrMode::from_u2`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dot15d4AddrMode {
    None = 0,
    Short = 2,
    Extended = 3,
}

impl Dot15d4AddrMode {
    /// Convert a two-bit addressing-mode codepoint to a modeled value.
    ///
    /// Returns `None` for the reserved value `0b01`.
    pub const fn from_u2(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            2 => Some(Self::Short),
            3 => Some(Self::Extended),
            _ => None,
        }
    }

    /// Return the two-bit addressing-mode codepoint.
    pub const fn as_u2(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot15d4_consts_channel_bounds_match_manifest() {
        assert_eq!(DOT15D4_CHANNEL_MIN, 11);
        assert_eq!(DOT15D4_CHANNEL_MAX, 26);
        assert_eq!(DOT15D4_FCS_LEN, 2);
        assert_eq!(DLT_IEEE802_15_4_WITHFCS, 195);
        assert_eq!(DLT_IEEE802_15_4_NOFCS, 230);
        assert_eq!(DLT_IEEE802_15_4_TAP, 283);
    }

    #[test]
    fn dot15d4_consts_channel_frequency_round_trips() {
        assert_eq!(channel_frequency_mhz(11), Some(2405));
        assert_eq!(channel_frequency_mhz(12), Some(2410));
        assert_eq!(channel_frequency_mhz(26), Some(2480));
        assert_eq!(channel_frequency_mhz(27), None);
        assert_eq!(channel_frequency_mhz(10), None);
        assert_eq!(channel_frequency_mhz(0), None);
    }

    #[test]
    fn dot15d4_consts_frame_type_round_trips() {
        let frame_types = [
            (0, Dot15d4FrameType::Beacon),
            (1, Dot15d4FrameType::Data),
            (2, Dot15d4FrameType::Ack),
            (3, Dot15d4FrameType::MacCommand),
        ];

        for (raw, frame_type) in frame_types {
            assert_eq!(Dot15d4FrameType::from_u3(raw), Some(frame_type));
            assert_eq!(frame_type.as_u3(), raw);
        }

        assert_eq!(Dot15d4FrameType::from_u3(4), None);
        assert_eq!(Dot15d4FrameType::from_u3(5), None);
        assert_eq!(Dot15d4FrameType::from_u3(6), None);
        assert_eq!(Dot15d4FrameType::from_u3(7), None);
    }

    #[test]
    fn dot15d4_consts_addr_mode_round_trips() {
        let addr_modes = [
            (0, Dot15d4AddrMode::None),
            (2, Dot15d4AddrMode::Short),
            (3, Dot15d4AddrMode::Extended),
        ];

        for (raw, addr_mode) in addr_modes {
            assert_eq!(Dot15d4AddrMode::from_u2(raw), Some(addr_mode));
            assert_eq!(addr_mode.as_u2(), raw);
        }

        assert_eq!(Dot15d4AddrMode::from_u2(1), None);
    }
}
