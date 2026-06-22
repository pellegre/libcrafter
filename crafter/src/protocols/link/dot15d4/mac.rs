//! IEEE 802.15.4 MAC frame layer scaffolding.

use crate::field::Field;

pub use super::consts::{Dot15d4AddrMode, Dot15d4FrameType};

/// IEEE 802.15.4 MAC frame.
///
/// `Dot15d4` is the 802.15.4 analog of `BleLlAdv`: a framed-PDU layer carrying
/// the MAC Frame Control field (FCF), sequence number, optional destination and
/// source PAN identifiers and addresses, a payload, and a trailing 2-octet
/// Frame Check Sequence (FCS). Every header field uses [`Field<T>`] so a value
/// the caller sets explicitly survives `compile()` untouched (including values
/// that are wrong on purpose), while any field left unset is auto-filled.
///
/// Field semantics are grounded in `.agents/docs/dot15d4-manifest.md` and
/// `.agents/docs/dot15d4-codepoints.md` (IEEE Std 802.15.4-2020, Clause 7.2):
///
/// - The 16-bit FCF packs the frame type (bits 0-2), the security-enabled
///   (bit 3), frame-pending (bit 4), ack-request (bit 5), and PAN-ID-compression
///   (bit 6) flags, the destination addressing mode (bits 10-11), the frame
///   version (bits 12-13), and the source addressing mode (bits 14-15).
/// - The sequence number is a single octet (Clause 7.2.3).
/// - PAN identifiers and addresses are present according to the addressing
///   modes and the PAN-ID-compression flag; addresses are stored as `u64` with
///   the corresponding addressing mode deciding 16-bit (short) versus 64-bit
///   (extended) serialization (Clause 7.2.4 through 7.2.8).
/// - The FCS is a 16-bit CRC auto-filled during `compile()` (Clause 7.2.10).
///
/// Builders, `compile()`/FCS auto-fill, the `Layer` implementation, and decode
/// arrive in later steps; this step only defines the struct, a manual `Clone`,
/// and the `new()` constructor.
#[derive(Debug)]
pub struct Dot15d4 {
    /// Frame type stored in FCF bits 0..=2.
    frame_type: Field<Dot15d4FrameType>,
    /// Security Enabled flag (FCF bit 3).
    security_enabled: Field<bool>,
    /// Frame Pending flag (FCF bit 4).
    frame_pending: Field<bool>,
    /// Acknowledgment Request flag (FCF bit 5).
    ack_request: Field<bool>,
    /// PAN ID Compression flag (FCF bit 6).
    pan_id_compression: Field<bool>,
    /// Frame Version stored in FCF bits 12..=13.
    frame_version: Field<u8>,
    /// Destination addressing mode (FCF bits 10..=11).
    dest_addr_mode: Field<Dot15d4AddrMode>,
    /// Source addressing mode (FCF bits 14..=15).
    src_addr_mode: Field<Dot15d4AddrMode>,
    /// Sequence number octet.
    seq: Field<u8>,
    /// Destination PAN identifier when present.
    dest_pan: Field<u16>,
    /// Destination address; the addressing mode decides 16- vs 64-bit form.
    dest_addr: Field<u64>,
    /// Source PAN identifier when present.
    src_pan: Field<u16>,
    /// Source address; the addressing mode decides 16- vs 64-bit form.
    src_addr: Field<u64>,
    /// MAC payload octets carried after the addressing fields.
    payload: Vec<u8>,
    /// Frame Check Sequence; auto-filled during compile.
    fcs: Field<u16>,
}

impl Clone for Dot15d4 {
    fn clone(&self) -> Self {
        Self {
            frame_type: self.frame_type.clone(),
            security_enabled: self.security_enabled.clone(),
            frame_pending: self.frame_pending.clone(),
            ack_request: self.ack_request.clone(),
            pan_id_compression: self.pan_id_compression.clone(),
            frame_version: self.frame_version.clone(),
            dest_addr_mode: self.dest_addr_mode.clone(),
            src_addr_mode: self.src_addr_mode.clone(),
            seq: self.seq.clone(),
            dest_pan: self.dest_pan.clone(),
            dest_addr: self.dest_addr.clone(),
            src_pan: self.src_pan.clone(),
            src_addr: self.src_addr.clone(),
            payload: self.payload.clone(),
            fcs: self.fcs.clone(),
        }
    }
}

impl Dot15d4 {
    /// Create an empty 802.15.4 MAC frame with every header field unset.
    ///
    /// All fields start as [`Field::unset`] and the payload is empty; builders
    /// and `compile()`-time auto-fill arrive in later steps.
    pub fn new() -> Self {
        Self {
            frame_type: Field::unset(),
            security_enabled: Field::unset(),
            frame_pending: Field::unset(),
            ack_request: Field::unset(),
            pan_id_compression: Field::unset(),
            frame_version: Field::unset(),
            dest_addr_mode: Field::unset(),
            src_addr_mode: Field::unset(),
            seq: Field::unset(),
            dest_pan: Field::unset(),
            dest_addr: Field::unset(),
            src_pan: Field::unset(),
            src_addr: Field::unset(),
            payload: Vec::new(),
            fcs: Field::unset(),
        }
    }

    /// Create a Data MAC frame.
    ///
    /// Sets the frame type to [`Dot15d4FrameType::Data`]; every other field is
    /// left unset for later auto-fill.
    pub fn data() -> Self {
        Self::new().frame_type(Dot15d4FrameType::Data)
    }

    /// Create a Beacon MAC frame.
    ///
    /// Sets the frame type to [`Dot15d4FrameType::Beacon`]; every other field is
    /// left unset for later auto-fill.
    pub fn beacon() -> Self {
        Self::new().frame_type(Dot15d4FrameType::Beacon)
    }

    /// Create an Acknowledgment MAC frame.
    ///
    /// Sets the frame type to [`Dot15d4FrameType::Ack`]; every other field is
    /// left unset for later auto-fill.
    pub fn ack() -> Self {
        Self::new().frame_type(Dot15d4FrameType::Ack)
    }

    /// Create a MAC Command frame.
    ///
    /// Sets the frame type to [`Dot15d4FrameType::MacCommand`]; every other
    /// field is left unset for later auto-fill.
    pub fn command() -> Self {
        Self::new().frame_type(Dot15d4FrameType::MacCommand)
    }

    /// Set the frame type (FCF bits 0..=2).
    pub fn frame_type(mut self, frame_type: Dot15d4FrameType) -> Self {
        self.frame_type.set_user(frame_type);
        self
    }

    /// Set the sequence number octet.
    pub fn seq(mut self, seq: u8) -> Self {
        self.seq.set_user(seq);
        self
    }

    /// Set or clear the Security Enabled flag (FCF bit 3).
    pub fn security(mut self, security_enabled: bool) -> Self {
        self.security_enabled.set_user(security_enabled);
        self
    }

    /// Set or clear the Frame Pending flag (FCF bit 4).
    pub fn frame_pending(mut self, frame_pending: bool) -> Self {
        self.frame_pending.set_user(frame_pending);
        self
    }

    /// Set or clear the Acknowledgment Request flag (FCF bit 5).
    pub fn ack_request(mut self, ack_request: bool) -> Self {
        self.ack_request.set_user(ack_request);
        self
    }

    /// Set or clear the PAN ID Compression flag (FCF bit 6).
    pub fn pan_id_compression(mut self, pan_id_compression: bool) -> Self {
        self.pan_id_compression.set_user(pan_id_compression);
        self
    }

    /// Set the Frame Version (FCF bits 12..=13).
    pub fn frame_version(mut self, frame_version: u8) -> Self {
        self.frame_version.set_user(frame_version);
        self
    }

    /// Set the MAC payload octets carried after the addressing fields.
    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        self
    }

    /// Set a 16-bit (short) destination PAN identifier and address.
    ///
    /// Sets `dest_pan`/`dest_addr` and, unless the caller already set
    /// `dest_addr_mode` explicitly, marks the destination addressing mode as
    /// [`Dot15d4AddrMode::Short`] (IEEE Std 802.15.4-2020, Clause 7.2.2.8).
    pub fn dest_short(mut self, pan: u16, addr: u16) -> Self {
        self.dest_pan.set_user(pan);
        self.dest_addr.set_user(u64::from(addr));
        if !self.dest_addr_mode.is_user_set() {
            self.dest_addr_mode.set_user(Dot15d4AddrMode::Short);
        }
        self
    }

    /// Set a 64-bit (extended) destination PAN identifier and address.
    ///
    /// Sets `dest_pan`/`dest_addr` and, unless the caller already set
    /// `dest_addr_mode` explicitly, marks the destination addressing mode as
    /// [`Dot15d4AddrMode::Extended`] (IEEE Std 802.15.4-2020, Clause 7.2.2.8).
    pub fn dest_extended(mut self, pan: u16, addr: u64) -> Self {
        self.dest_pan.set_user(pan);
        self.dest_addr.set_user(addr);
        if !self.dest_addr_mode.is_user_set() {
            self.dest_addr_mode.set_user(Dot15d4AddrMode::Extended);
        }
        self
    }

    /// Set a 16-bit (short) source PAN identifier and address.
    ///
    /// Sets `src_pan`/`src_addr` and, unless the caller already set
    /// `src_addr_mode` explicitly, marks the source addressing mode as
    /// [`Dot15d4AddrMode::Short`] (IEEE Std 802.15.4-2020, Clause 7.2.2.10).
    pub fn src_short(mut self, pan: u16, addr: u16) -> Self {
        self.src_pan.set_user(pan);
        self.src_addr.set_user(u64::from(addr));
        if !self.src_addr_mode.is_user_set() {
            self.src_addr_mode.set_user(Dot15d4AddrMode::Short);
        }
        self
    }

    /// Set a 64-bit (extended) source PAN identifier and address.
    ///
    /// Sets `src_pan`/`src_addr` and, unless the caller already set
    /// `src_addr_mode` explicitly, marks the source addressing mode as
    /// [`Dot15d4AddrMode::Extended`] (IEEE Std 802.15.4-2020, Clause 7.2.2.10).
    pub fn src_extended(mut self, pan: u16, addr: u64) -> Self {
        self.src_pan.set_user(pan);
        self.src_addr.set_user(addr);
        if !self.src_addr_mode.is_user_set() {
            self.src_addr_mode.set_user(Dot15d4AddrMode::Extended);
        }
        self
    }

    /// Resolve the effective destination addressing mode (FCF bits 10..=11).
    ///
    /// Honors a user-set `dest_addr_mode`; otherwise infers it from the
    /// presence of a destination address: a set address defaults to
    /// [`Dot15d4AddrMode::Short`] (a fuller short/extended distinction is made
    /// by the typed `dest_short`/`dest_extended` builders), and an unset
    /// address resolves to [`Dot15d4AddrMode::None`]
    /// (IEEE Std 802.15.4-2020, Clause 7.2.2.8).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_dest_addr_mode(&self) -> Dot15d4AddrMode {
        match self.dest_addr_mode.value() {
            Some(mode) => *mode,
            None => {
                if self.dest_addr.value().is_some() {
                    Dot15d4AddrMode::Short
                } else {
                    Dot15d4AddrMode::None
                }
            }
        }
    }

    /// Resolve the effective source addressing mode (FCF bits 14..=15).
    ///
    /// Honors a user-set `src_addr_mode`; otherwise infers it from the
    /// presence of a source address, mirroring
    /// [`Dot15d4::effective_dest_addr_mode`]
    /// (IEEE Std 802.15.4-2020, Clause 7.2.2.10).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_src_addr_mode(&self) -> Dot15d4AddrMode {
        match self.src_addr_mode.value() {
            Some(mode) => *mode,
            None => {
                if self.src_addr.value().is_some() {
                    Dot15d4AddrMode::Short
                } else {
                    Dot15d4AddrMode::None
                }
            }
        }
    }

    /// Resolve the effective addressing mode for the requested direction.
    ///
    /// `effective_addr_mode(true)` returns the destination mode and
    /// `effective_addr_mode(false)` the source mode, sharing the same
    /// honored-override-then-infer rule used by the per-direction resolvers.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_addr_mode(&self, destination: bool) -> Dot15d4AddrMode {
        if destination {
            self.effective_dest_addr_mode()
        } else {
            self.effective_src_addr_mode()
        }
    }

    /// Resolve the effective PAN-ID-compression bit (FCF bit 6).
    ///
    /// Honors a user-set `pan_id_compression`; otherwise applies the standard
    /// default rule: compression is set when both the destination and source
    /// addresses are present and share the same PAN identifier, so the source
    /// PAN ID is omitted on the wire and the single shared PAN ID is serialized
    /// once (IEEE Std 802.15.4-2020, Clause 7.2.2.6, PAN ID Compression field).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_pan_id_compression(&self) -> bool {
        if let Some(value) = self.pan_id_compression.value() {
            return *value;
        }

        let dest_present = self.effective_dest_addr_mode() != Dot15d4AddrMode::None;
        let src_present = self.effective_src_addr_mode() != Dot15d4AddrMode::None;
        if !(dest_present && src_present) {
            return false;
        }

        match (self.dest_pan.value(), self.src_pan.value()) {
            (Some(dest_pan), Some(src_pan)) => dest_pan == src_pan,
            // With both addresses present and only one PAN ID supplied, treat
            // the single PAN as shared and compress.
            (Some(_), None) | (None, Some(_)) => true,
            (None, None) => false,
        }
    }

    /// Resolve whether the destination PAN identifier is present on the wire.
    ///
    /// The destination PAN ID is present whenever the destination addressing
    /// mode is not [`Dot15d4AddrMode::None`]
    /// (IEEE Std 802.15.4-2020, Clause 7.2.2, Table 7-2).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_dest_pan_present(&self) -> bool {
        self.effective_dest_addr_mode() != Dot15d4AddrMode::None
    }

    /// Resolve whether the source PAN identifier is present on the wire.
    ///
    /// The source PAN ID is present when the source addressing mode is not
    /// [`Dot15d4AddrMode::None`] and PAN-ID compression is not in effect; when
    /// compression is set the source PAN ID is omitted and the destination PAN
    /// ID serves both addresses
    /// (IEEE Std 802.15.4-2020, Clause 7.2.2.6 / Table 7-2).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn effective_src_pan_present(&self) -> bool {
        if self.effective_src_addr_mode() == Dot15d4AddrMode::None {
            return false;
        }
        !self.effective_pan_id_compression()
    }
}

impl Default for Dot15d4 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod dot15d4_mac_builder {
    use super::{Dot15d4, Dot15d4FrameType};

    #[test]
    fn frame_type_constructors_mark_frame_type_user_set() {
        for (frame, expected) in [
            (Dot15d4::data(), Dot15d4FrameType::Data),
            (Dot15d4::beacon(), Dot15d4FrameType::Beacon),
            (Dot15d4::ack(), Dot15d4FrameType::Ack),
            (Dot15d4::command(), Dot15d4FrameType::MacCommand),
        ] {
            assert!(frame.frame_type.is_user_set());
            assert_eq!(frame.frame_type.value(), Some(&expected));
        }
    }

    #[test]
    fn setters_mark_their_fields_user_set() {
        let frame = Dot15d4::new()
            .frame_type(Dot15d4FrameType::Data)
            .seq(7)
            .security(true)
            .frame_pending(true)
            .ack_request(true)
            .pan_id_compression(true)
            .frame_version(2);

        assert!(frame.frame_type.is_user_set());
        assert!(frame.seq.is_user_set());
        assert!(frame.security_enabled.is_user_set());
        assert!(frame.frame_pending.is_user_set());
        assert!(frame.ack_request.is_user_set());
        assert!(frame.pan_id_compression.is_user_set());
        assert!(frame.frame_version.is_user_set());

        assert_eq!(frame.security_enabled.value(), Some(&true));
        assert_eq!(frame.frame_pending.value(), Some(&true));
        assert_eq!(frame.ack_request.value(), Some(&true));
        assert_eq!(frame.pan_id_compression.value(), Some(&true));
        assert_eq!(frame.frame_version.value(), Some(&2));
    }

    #[test]
    fn data_seq_payload_holds_expected_values() {
        let frame = Dot15d4::data().seq(7).payload(&[1, 2, 3]);

        assert_eq!(frame.frame_type.value(), Some(&Dot15d4FrameType::Data));
        assert_eq!(frame.seq.value(), Some(&7));
        assert_eq!(frame.payload, vec![1, 2, 3]);
    }

    #[test]
    fn untouched_fields_stay_unset() {
        let frame = Dot15d4::data().seq(7).payload(&[1, 2, 3]);

        assert!(frame.security_enabled.is_unset());
        assert!(frame.frame_pending.is_unset());
        assert!(frame.ack_request.is_unset());
        assert!(frame.pan_id_compression.is_unset());
        assert!(frame.frame_version.is_unset());
        assert!(frame.fcs.is_unset());
    }
}

#[cfg(test)]
mod dot15d4_mac_address {
    use super::{Dot15d4, Dot15d4AddrMode};

    #[test]
    fn short_dest_and_src_share_pan_under_compression() {
        let frame = Dot15d4::data()
            .dest_short(0xABCD, 0x1234)
            .src_short(0xABCD, 0x5678);

        // Typed builders set the addressing modes to Short.
        assert_eq!(frame.dest_addr_mode.value(), Some(&Dot15d4AddrMode::Short));
        assert_eq!(frame.src_addr_mode.value(), Some(&Dot15d4AddrMode::Short));
        assert_eq!(frame.dest_addr.value(), Some(&0x1234));
        assert_eq!(frame.src_addr.value(), Some(&0x5678));

        // Resolvers report Short modes.
        assert_eq!(frame.effective_dest_addr_mode(), Dot15d4AddrMode::Short);
        assert_eq!(frame.effective_src_addr_mode(), Dot15d4AddrMode::Short);
        assert_eq!(frame.effective_addr_mode(true), Dot15d4AddrMode::Short);
        assert_eq!(frame.effective_addr_mode(false), Dot15d4AddrMode::Short);

        // Both addresses present and share a PAN: compression defaults on, so
        // the source PAN ID is omitted and the single shared PAN is serialized
        // once via the destination PAN ID.
        assert!(frame.effective_pan_id_compression());
        assert!(frame.effective_dest_pan_present());
        assert!(!frame.effective_src_pan_present());
    }

    #[test]
    fn extended_dest_and_src_addresses() {
        let frame = Dot15d4::data()
            .dest_extended(0x0001, 0x0011_2233_4455_6677)
            .src_extended(0x0002, 0x8899_AABB_CCDD_EEFF);

        assert_eq!(
            frame.dest_addr_mode.value(),
            Some(&Dot15d4AddrMode::Extended)
        );
        assert_eq!(
            frame.src_addr_mode.value(),
            Some(&Dot15d4AddrMode::Extended)
        );
        assert_eq!(frame.dest_addr.value(), Some(&0x0011_2233_4455_6677));
        assert_eq!(frame.src_addr.value(), Some(&0x8899_AABB_CCDD_EEFF));

        assert_eq!(frame.effective_dest_addr_mode(), Dot15d4AddrMode::Extended);
        assert_eq!(frame.effective_src_addr_mode(), Dot15d4AddrMode::Extended);

        // Distinct PAN IDs: compression stays off and both PAN IDs are present.
        assert!(!frame.effective_pan_id_compression());
        assert!(frame.effective_dest_pan_present());
        assert!(frame.effective_src_pan_present());
    }

    #[test]
    fn destination_only_frame_has_no_source_addressing() {
        let frame = Dot15d4::data().dest_short(0xABCD, 0x1234);

        assert_eq!(frame.effective_dest_addr_mode(), Dot15d4AddrMode::Short);
        assert_eq!(frame.effective_src_addr_mode(), Dot15d4AddrMode::None);

        // With no source address, compression does not apply; the destination
        // PAN ID is present and there is no source PAN ID.
        assert!(!frame.effective_pan_id_compression());
        assert!(frame.effective_dest_pan_present());
        assert!(!frame.effective_src_pan_present());
    }

    #[test]
    fn typed_builder_does_not_override_explicit_addr_mode() {
        // Caller sets an extended mode but then supplies a short address on
        // purpose; the explicit mode must survive (malformed-on-purpose).
        let frame = Dot15d4::data();
        let mut frame = frame;
        frame.dest_addr_mode.set_user(Dot15d4AddrMode::Extended);
        let frame = frame.dest_short(0xABCD, 0x1234);

        assert_eq!(
            frame.dest_addr_mode.value(),
            Some(&Dot15d4AddrMode::Extended)
        );
        assert_eq!(frame.effective_dest_addr_mode(), Dot15d4AddrMode::Extended);
    }

    #[test]
    fn user_set_compression_is_honored() {
        // Destination-only frame would default compression off, but an explicit
        // request to compress must be honored.
        let frame = Dot15d4::data()
            .dest_short(0xABCD, 0x1234)
            .pan_id_compression(true);

        assert!(frame.effective_pan_id_compression());

        // And an explicit request to disable compression on a frame that would
        // otherwise compress must also be honored.
        let frame = Dot15d4::data()
            .dest_short(0xABCD, 0x1234)
            .src_short(0xABCD, 0x5678)
            .pan_id_compression(false);

        assert!(!frame.effective_pan_id_compression());
        assert!(frame.effective_src_pan_present());
    }
}
