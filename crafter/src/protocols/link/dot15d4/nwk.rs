//! Zigbee Network (NWK) layer scaffolding.

use crate::field::Field;

/// NWK Frame Control: Frame Type sub-field bit offset (bits 0..=1).
///
/// Zigbee Specification R23 (05-3474-23), Section 3.3.1.1, Figure 3-5; see
/// `.agents/docs/zigbee-manifest.md`.
const NWK_FC_FRAME_TYPE_SHIFT: u16 = 0;
/// NWK Frame Control: Protocol Version sub-field bit offset (bits 2..=5).
const NWK_FC_PROTOCOL_VERSION_SHIFT: u16 = 2;
/// NWK Frame Control: Discover Route sub-field bit offset (bits 6..=7).
const NWK_FC_DISCOVER_ROUTE_SHIFT: u16 = 6;
/// NWK Frame Control: deprecated Multicast flag bit offset (bit 8).
const NWK_FC_MULTICAST_SHIFT: u16 = 8;
/// NWK Frame Control: Security flag bit offset (bit 9).
const NWK_FC_SECURITY_SHIFT: u16 = 9;
/// NWK Frame Control: Source Route flag bit offset (bit 10).
const NWK_FC_SOURCE_ROUTE_SHIFT: u16 = 10;
/// NWK Frame Control: Destination IEEE Address flag bit offset (bit 11).
const NWK_FC_DEST_IEEE_SHIFT: u16 = 11;
/// NWK Frame Control: Source IEEE Address flag bit offset (bit 12).
const NWK_FC_SRC_IEEE_SHIFT: u16 = 12;

/// NWK Frame Type code point for a data frame (0b00).
///
/// Zigbee Specification R23, Section 3.3.1.1.1, Table 3-48.
const NWK_FRAME_TYPE_DATA: u8 = 0b00;
/// NWK Frame Type code point for a NWK command frame (0b01).
///
/// Zigbee Specification R23, Section 3.3.1.1.1, Table 3-48.
const NWK_FRAME_TYPE_COMMAND: u8 = 0b01;
/// `nwkcProtocolVersion`: the Zigbee PRO NWK protocol version (0x02).
///
/// Zigbee Specification R23, Section 3.3.1.1.2.
const NWK_PROTOCOL_VERSION_DEFAULT: u8 = 0x02;
/// Default NWK Radius when the caller leaves it unset.
const NWK_RADIUS_DEFAULT: u8 = 0;
/// Default NWK Sequence Number when the caller leaves it unset.
const NWK_SEQ_DEFAULT: u8 = 0;

/// Length, in octets, of the NWK Frame Control field.
const NWK_FRAME_CONTROL_LEN: usize = 2;
/// Length, in octets, of a NWK 16-bit (short) network address field.
const NWK_SHORT_ADDR_LEN: usize = 2;
/// Length, in octets, of the NWK Radius field.
const NWK_RADIUS_LEN: usize = 1;
/// Length, in octets, of the NWK Sequence Number field.
const NWK_SEQ_LEN: usize = 1;
/// Length, in octets, of a NWK 64-bit IEEE address field when present.
const NWK_IEEE_ADDR_LEN: usize = 8;

/// Zigbee Network (NWK) frame.
///
/// `ZigbeeNwk` is the network-layer frame that rides inside the IEEE 802.15.4
/// MAC data payload, the Zigbee analog of a simple framed-PDU layer like
/// `BleLlAdv`. Every header field uses [`Field<T>`] so a value the caller sets
/// explicitly survives `compile()` untouched (including values that are wrong on
/// purpose), while any field left unset is auto-filled.
///
/// Field semantics and the header field order are grounded in
/// `.agents/docs/zigbee-manifest.md` (Zigbee Specification Revision 23,
/// 05-3474-23, Section 3.3.1, Figure 3-4 and Figure 3-5):
///
/// - The 16-bit NWK Frame Control field packs the frame type (bits 0..=1), the
///   protocol version (bits 2..=5), the discover-route sub-field (bits 6..=7),
///   the deprecated multicast flag (bit 8), the security flag (bit 9), the
///   source-route flag (bit 10), the destination-IEEE-address flag (bit 11),
///   and the source-IEEE-address flag (bit 12).
/// - The destination and source 16-bit network addresses, the radius, and the
///   sequence number are always present, in that order.
/// - The 64-bit destination and source IEEE addresses follow the sequence
///   number and are present only when their frame-control flags are set.
/// - The NWK payload follows the (optional) IEEE addresses.
///
/// The `Layer` implementation and decode arrive in step 20; this step defines
/// the struct, builders, and byte serialization.
#[derive(Debug)]
pub struct ZigbeeNwk {
    /// Frame type stored in NWK Frame Control bits 0..=1.
    frame_type: Field<u8>,
    /// Protocol version stored in NWK Frame Control bits 2..=5.
    protocol_version: Field<u8>,
    /// Discover-route sub-field stored in NWK Frame Control bits 6..=7.
    discover_route: Field<u8>,
    /// Deprecated multicast flag (NWK Frame Control bit 8).
    multicast: Field<bool>,
    /// Security flag (NWK Frame Control bit 9).
    security: Field<bool>,
    /// Source-route flag (NWK Frame Control bit 10).
    source_route: Field<bool>,
    /// Destination-IEEE-address flag (NWK Frame Control bit 11).
    dest_ieee_flag: Field<bool>,
    /// Source-IEEE-address flag (NWK Frame Control bit 12).
    src_ieee_flag: Field<bool>,
    /// Destination 16-bit network (short) address.
    dest: Field<u16>,
    /// Source 16-bit network (short) address.
    src: Field<u16>,
    /// Radius octet (hop limit).
    radius: Field<u8>,
    /// Sequence number octet.
    seq: Field<u8>,
    /// Optional 64-bit destination IEEE address (present when its flag is set).
    dest_ieee: Field<u64>,
    /// Optional 64-bit source IEEE address (present when its flag is set).
    src_ieee: Field<u64>,
    /// NWK payload octets carried after the (optional) IEEE addresses.
    payload: Vec<u8>,
}

impl Clone for ZigbeeNwk {
    fn clone(&self) -> Self {
        Self {
            frame_type: self.frame_type.clone(),
            protocol_version: self.protocol_version.clone(),
            discover_route: self.discover_route.clone(),
            multicast: self.multicast.clone(),
            security: self.security.clone(),
            source_route: self.source_route.clone(),
            dest_ieee_flag: self.dest_ieee_flag.clone(),
            src_ieee_flag: self.src_ieee_flag.clone(),
            dest: self.dest.clone(),
            src: self.src.clone(),
            radius: self.radius.clone(),
            seq: self.seq.clone(),
            dest_ieee: self.dest_ieee.clone(),
            src_ieee: self.src_ieee.clone(),
            payload: self.payload.clone(),
        }
    }
}

impl ZigbeeNwk {
    /// Create an empty NWK frame with every header field unset.
    ///
    /// All fields start as [`Field::unset`] and the payload is empty; builders
    /// and `compile()`-time auto-fill resolve the wire values.
    pub fn new() -> Self {
        Self {
            frame_type: Field::unset(),
            protocol_version: Field::unset(),
            discover_route: Field::unset(),
            multicast: Field::unset(),
            security: Field::unset(),
            source_route: Field::unset(),
            dest_ieee_flag: Field::unset(),
            src_ieee_flag: Field::unset(),
            dest: Field::unset(),
            src: Field::unset(),
            radius: Field::unset(),
            seq: Field::unset(),
            dest_ieee: Field::unset(),
            src_ieee: Field::unset(),
            payload: Vec::new(),
        }
    }

    /// Create a NWK Data frame.
    ///
    /// Sets the frame type to the data code point (0b00, Zigbee Specification
    /// R23, Table 3-48); every other field is left unset for later auto-fill.
    pub fn data() -> Self {
        Self::new().frame_type(NWK_FRAME_TYPE_DATA)
    }

    /// Create a NWK Command frame.
    ///
    /// Sets the frame type to the command code point (0b01, Zigbee Specification
    /// R23, Table 3-48); every other field is left unset for later auto-fill.
    pub fn command() -> Self {
        Self::new().frame_type(NWK_FRAME_TYPE_COMMAND)
    }

    /// Set the NWK frame type (Frame Control bits 0..=1).
    pub fn frame_type(mut self, frame_type: u8) -> Self {
        self.frame_type.set_user(frame_type);
        self
    }

    /// Set the NWK protocol version (Frame Control bits 2..=5).
    pub fn protocol_version(mut self, protocol_version: u8) -> Self {
        self.protocol_version.set_user(protocol_version);
        self
    }

    /// Set the destination 16-bit network address.
    pub fn dest(mut self, dest: u16) -> Self {
        self.dest.set_user(dest);
        self
    }

    /// Set the source 16-bit network address.
    pub fn src(mut self, src: u16) -> Self {
        self.src.set_user(src);
        self
    }

    /// Set the NWK Radius octet (hop limit).
    pub fn radius(mut self, radius: u8) -> Self {
        self.radius.set_user(radius);
        self
    }

    /// Set the NWK Sequence Number octet.
    pub fn seq(mut self, seq: u8) -> Self {
        self.seq.set_user(seq);
        self
    }

    /// Set the NWK payload octets carried after the header.
    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        self
    }

    /// Resolve the effective NWK frame type (Frame Control bits 0..=1).
    ///
    /// Honors a user-set frame type; otherwise defaults to the data code point
    /// (0b00).
    fn effective_frame_type(&self) -> u8 {
        self.frame_type.value().copied().unwrap_or(NWK_FRAME_TYPE_DATA)
    }

    /// Resolve the effective NWK protocol version (Frame Control bits 2..=5).
    ///
    /// Honors a user-set version; otherwise defaults to `nwkcProtocolVersion`
    /// (0x02, the Zigbee PRO NWK protocol version).
    fn effective_protocol_version(&self) -> u8 {
        self.protocol_version
            .value()
            .copied()
            .unwrap_or(NWK_PROTOCOL_VERSION_DEFAULT)
    }

    /// Resolve the effective discover-route sub-field (Frame Control bits 6..=7).
    fn effective_discover_route(&self) -> u8 {
        self.discover_route.value().copied().unwrap_or(0)
    }

    /// Resolve the effective destination-IEEE-address flag (Frame Control bit 11).
    ///
    /// Honors a user-set flag; otherwise the destination IEEE address is present
    /// only when one has been supplied.
    fn effective_dest_ieee_flag(&self) -> bool {
        match self.dest_ieee_flag.value() {
            Some(flag) => *flag,
            None => self.dest_ieee.value().is_some(),
        }
    }

    /// Resolve the effective source-IEEE-address flag (Frame Control bit 12).
    ///
    /// Honors a user-set flag; otherwise the source IEEE address is present only
    /// when one has been supplied.
    fn effective_src_ieee_flag(&self) -> bool {
        match self.src_ieee_flag.value() {
            Some(flag) => *flag,
            None => self.src_ieee.value().is_some(),
        }
    }

    /// Assemble the 16-bit NWK Frame Control field from the effective fields.
    ///
    /// Packs the frame type (bits 0..=1), protocol version (bits 2..=5),
    /// discover-route sub-field (bits 6..=7), multicast flag (bit 8), security
    /// flag (bit 9), source-route flag (bit 10), destination-IEEE flag
    /// (bit 11), and source-IEEE flag (bit 12), per Zigbee Specification R23
    /// Section 3.3.1.1 (Figure 3-5; see `.agents/docs/zigbee-manifest.md`).
    /// User-set sub-fields are honored exactly; the frame control is never
    /// "corrected" to be consistent with the addresses present.
    fn frame_control(&self) -> u16 {
        let frame_type = u16::from(self.effective_frame_type() & 0b11);
        let protocol_version = u16::from(self.effective_protocol_version() & 0b1111);
        let discover_route = u16::from(self.effective_discover_route() & 0b11);
        let multicast = u16::from(self.multicast.value().copied().unwrap_or(false));
        let security = u16::from(self.security.value().copied().unwrap_or(false));
        let source_route = u16::from(self.source_route.value().copied().unwrap_or(false));
        let dest_ieee = u16::from(self.effective_dest_ieee_flag());
        let src_ieee = u16::from(self.effective_src_ieee_flag());

        (frame_type << NWK_FC_FRAME_TYPE_SHIFT)
            | (protocol_version << NWK_FC_PROTOCOL_VERSION_SHIFT)
            | (discover_route << NWK_FC_DISCOVER_ROUTE_SHIFT)
            | (multicast << NWK_FC_MULTICAST_SHIFT)
            | (security << NWK_FC_SECURITY_SHIFT)
            | (source_route << NWK_FC_SOURCE_ROUTE_SHIFT)
            | (dest_ieee << NWK_FC_DEST_IEEE_SHIFT)
            | (src_ieee << NWK_FC_SRC_IEEE_SHIFT)
    }

    /// Encoded length, in octets, of the full NWK frame.
    ///
    /// Mirrors [`ZigbeeNwk::encode`]: Frame Control + destination + source +
    /// radius + sequence number + the optional IEEE addresses implied by the
    /// effective flags + payload.
    pub(crate) fn encoded_len(&self) -> usize {
        let mut len = NWK_FRAME_CONTROL_LEN
            + NWK_SHORT_ADDR_LEN
            + NWK_SHORT_ADDR_LEN
            + NWK_RADIUS_LEN
            + NWK_SEQ_LEN;
        if self.effective_dest_ieee_flag() {
            len += NWK_IEEE_ADDR_LEN;
        }
        if self.effective_src_ieee_flag() {
            len += NWK_IEEE_ADDR_LEN;
        }
        len += self.payload.len();
        len
    }

    /// Serialize the Zigbee NWK frame to bytes.
    ///
    /// Emits the 16-bit Frame Control field (little-endian), the destination and
    /// source 16-bit network addresses (little-endian), the radius octet, the
    /// sequence number octet, the optional 64-bit destination and source IEEE
    /// addresses (little-endian, present only when their frame-control flags are
    /// set), and the payload, in the spec field order (Zigbee Specification R23
    /// Section 3.3.1, Figure 3-4; see `.agents/docs/zigbee-manifest.md`). Every
    /// user-set field is honored verbatim; no value is clamped or "corrected".
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());

        out.extend_from_slice(&self.frame_control().to_le_bytes());
        out.extend_from_slice(&self.dest.value().copied().unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&self.src.value().copied().unwrap_or(0).to_le_bytes());
        out.push(self.radius.value().copied().unwrap_or(NWK_RADIUS_DEFAULT));
        out.push(self.seq.value().copied().unwrap_or(NWK_SEQ_DEFAULT));

        if self.effective_dest_ieee_flag() {
            out.extend_from_slice(&self.dest_ieee.value().copied().unwrap_or(0).to_le_bytes());
        }
        if self.effective_src_ieee_flag() {
            out.extend_from_slice(&self.src_ieee.value().copied().unwrap_or(0).to_le_bytes());
        }

        out.extend_from_slice(&self.payload);
        out
    }
}

impl Default for ZigbeeNwk {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ZigbeeNwk;

    #[test]
    fn zigbee_nwk_encode() {
        // A data NWK frame addressed short-to-short with a small payload.
        //
        // Header field order (Zigbee Specification R23, Section 3.3.1,
        // Figure 3-4; see `.agents/docs/zigbee-manifest.md`): Frame Control
        // (u16 LE) + Destination (u16 LE) + Source (u16 LE) + Radius (u8) +
        // Sequence Number (u8) + payload.
        //
        // Frame Control: frame type Data = 0b00 (bits 0..=1), protocol version
        // nwkcProtocolVersion = 0x02 (bits 2..=5 -> 0b0010 << 2 = 0x0008), every
        // other sub-field/flag 0, so FC = 0x0008, little-endian bytes 08 00.
        //
        // This is the layout scapy emits for
        //   ZigbeeNWK(frametype=0, proto_version=2, destination=0x1234,
        //             source=0x5678, radius=30, seqnum=42)/Raw(b"\xAA\xBB")
        // whose bytes are 08 00 34 12 78 56 1E 2A AA BB (FC + LE short
        // addresses + radius + seqnum + payload), cross-checked against the
        // scapy `ZigbeeNWK` field layout.
        let frame = ZigbeeNwk::data()
            .dest(0x1234)
            .src(0x5678)
            .radius(30)
            .seq(42)
            .payload(&[0xAA, 0xBB]);

        let bytes = frame.encode();

        assert_eq!(
            bytes,
            vec![
                0x08, 0x00, // NWK Frame Control (little-endian): Data + version 2
                0x34, 0x12, // destination 0x1234 (little-endian)
                0x78, 0x56, // source 0x5678 (little-endian)
                0x1E, // radius 30
                0x2A, // sequence number 42
                0xAA, 0xBB, // NWK payload
            ]
        );

        // encoded_len() matches the serialized length.
        assert_eq!(frame.encoded_len(), bytes.len());
    }

    #[test]
    fn zigbee_nwk_command_frame_type_and_default_version() {
        // A command frame leaves the protocol version unset; it must auto-fill
        // to nwkcProtocolVersion = 0x02, so the Frame Control low byte is
        // 0b0000_1001 = 0x09 (frame type Command = 0b01, version 0x02 << 2).
        let frame = ZigbeeNwk::command().dest(0x0000).src(0x0001);
        let bytes = frame.encode();

        assert_eq!(&bytes[..2], &[0x09, 0x00]);
    }

    #[test]
    fn zigbee_nwk_dest_ieee_flag_includes_address() {
        // Supplying a destination IEEE address sets the dest-IEEE flag (bit 11)
        // and serializes the 64-bit address after the sequence number, before
        // the payload (Zigbee Specification R23, Section 3.3.1.6).
        let mut frame = ZigbeeNwk::data().dest(0x1234).src(0x5678).radius(1).seq(2);
        frame.dest_ieee.set_user(0x0011_2233_4455_6677);
        let bytes = frame.encode();

        // Frame Control bit 11 (dest IEEE) set: low word 0x0808 -> 08 08.
        assert_eq!(&bytes[..2], &[0x08, 0x08]);
        // The 8-octet destination IEEE address follows radius+seqnum (offset 8),
        // little-endian, before the (empty) payload.
        assert_eq!(
            &bytes[8..16],
            &[0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]
        );
        assert_eq!(frame.encoded_len(), bytes.len());
    }
}
