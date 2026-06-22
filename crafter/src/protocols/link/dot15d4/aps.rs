//! Zigbee Application Support sublayer (APS) layer scaffolding.

use crate::field::Field;

/// APS Frame Control: Frame Type sub-field bit offset (bits 0..=1).
///
/// Zigbee Specification R23 (05-3474-23), Section 2.2.5.1.1, Figure 2-4; see
/// `.agents/docs/zigbee-manifest.md`.
const APS_FC_FRAME_TYPE_SHIFT: u8 = 0;
/// APS Frame Control: Delivery Mode sub-field bit offset (bits 2..=3).
const APS_FC_DELIVERY_MODE_SHIFT: u8 = 2;
/// APS Frame Control: ACK Format flag bit offset (bit 4).
const APS_FC_ACK_FORMAT_SHIFT: u8 = 4;
/// APS Frame Control: Security flag bit offset (bit 5).
const APS_FC_SECURITY_SHIFT: u8 = 5;
/// APS Frame Control: ACK Request flag bit offset (bit 6).
const APS_FC_ACK_REQUEST_SHIFT: u8 = 6;
/// APS Frame Control: Extended Header Present flag bit offset (bit 7).
const APS_FC_EXT_HEADER_SHIFT: u8 = 7;

/// APS Frame Type code point for a data frame (0b00).
///
/// Zigbee Specification R23, Section 2.2.5.1.1.1, Table 2-20.
const APS_FRAME_TYPE_DATA: u8 = 0b00;
/// APS Frame Type code point for a command frame (0b01).
///
/// Zigbee Specification R23, Section 2.2.5.1.1.1, Table 2-20.
const APS_FRAME_TYPE_COMMAND: u8 = 0b01;
/// APS Frame Type code point for an acknowledgement frame (0b10).
///
/// Zigbee Specification R23, Section 2.2.5.1.1.1, Table 2-20.
const APS_FRAME_TYPE_ACK: u8 = 0b10;

/// APS Delivery Mode code point for normal unicast delivery (0b00).
///
/// Zigbee Specification R23, Section 2.2.5.1.1.2, Table 2-21.
const APS_DELIVERY_MODE_UNICAST: u8 = 0b00;
/// APS Delivery Mode code point for broadcast delivery (0b10).
///
/// Zigbee Specification R23, Section 2.2.5.1.1.2, Table 2-21.
const APS_DELIVERY_MODE_BROADCAST: u8 = 0b10;
/// APS Delivery Mode code point for group addressing (0b11).
///
/// Zigbee Specification R23, Section 2.2.5.1.1.2, Table 2-21.
const APS_DELIVERY_MODE_GROUP: u8 = 0b11;

/// Default APS Counter when the caller leaves it unset.
const APS_COUNTER_DEFAULT: u8 = 0;

/// Length, in octets, of the APS Frame Control field.
const APS_FRAME_CONTROL_LEN: usize = 1;
/// Length, in octets, of an APS endpoint field (destination or source).
const APS_ENDPOINT_LEN: usize = 1;
/// Length, in octets, of the APS Cluster Identifier field.
const APS_CLUSTER_LEN: usize = 2;
/// Length, in octets, of the APS Profile Identifier field.
const APS_PROFILE_LEN: usize = 2;
/// Length, in octets, of the APS Counter field.
const APS_COUNTER_LEN: usize = 1;

/// Zigbee Application Support sublayer (APS) frame.
///
/// `ZigbeeAps` is the application-support-layer frame that rides inside the
/// Zigbee NWK payload, the APS analog of [`super::ZigbeeNwk`]. Every header
/// field uses [`Field<T>`] so a value the caller sets explicitly survives
/// `compile()` untouched (including values that are wrong on purpose), while
/// any field left unset is auto-filled.
///
/// Field semantics and the header field order are grounded in
/// `.agents/docs/zigbee-manifest.md` (Zigbee Specification Revision 23,
/// 05-3474-23, Section 2.2.5.1, Figure 2-3 and Figure 2-4):
///
/// - The 8-bit APS Frame Control field packs the frame type (bits 0..=1), the
///   delivery mode (bits 2..=3), the ACK-format flag (bit 4), the security flag
///   (bit 5), the ACK-request flag (bit 6), and the extended-header-present flag
///   (bit 7).
/// - The header field order is Frame Control, Destination Endpoint (0/1),
///   Cluster Identifier (0/2), Profile Identifier (0/2), Source Endpoint (0/1),
///   APS Counter (1), Frame Payload.
///
/// Field-presence rule (Zigbee Specification R23, Sections 2.2.5.1.2-2.2.5.1.5;
/// see `.agents/docs/zigbee-manifest.md`):
///
/// - The Destination Endpoint is present only when the delivery mode is unicast
///   (0b00) or broadcast (0b10); under group addressing (0b11) a 2-octet Group
///   Address replaces it. Group addressing is not modeled here, so the
///   destination endpoint is emitted for non-group delivery modes.
/// - The Cluster Identifier and Profile Identifier are present only for data
///   (0b00) or acknowledgement (0b10) frames.
/// - The Source Endpoint and APS Counter are part of the standard header.
///
/// The extended header sub-frame (bit 7) and group addressing (delivery mode
/// 0b11) are out of scope for this layer; the extended-header flag is honored in
/// the frame control byte but no extended header bytes are emitted.
#[derive(Debug)]
pub struct ZigbeeAps {
    /// Frame type stored in APS Frame Control bits 0..=1.
    frame_type: Field<u8>,
    /// Delivery mode stored in APS Frame Control bits 2..=3.
    delivery_mode: Field<u8>,
    /// ACK-format flag (APS Frame Control bit 4).
    ack_format: Field<bool>,
    /// Security flag (APS Frame Control bit 5).
    security: Field<bool>,
    /// ACK-request flag (APS Frame Control bit 6).
    ack_request: Field<bool>,
    /// Extended-header-present flag (APS Frame Control bit 7).
    ext_header: Field<bool>,
    /// Optional destination endpoint (present for unicast/broadcast delivery).
    dest_endpoint: Field<u8>,
    /// Cluster identifier (present for data or acknowledgement frames).
    cluster: Field<u16>,
    /// Profile identifier (present for data or acknowledgement frames).
    profile: Field<u16>,
    /// Optional source endpoint.
    src_endpoint: Field<u8>,
    /// APS Counter octet.
    counter: Field<u8>,
    /// APS payload octets carried after the header.
    payload: Vec<u8>,
}

impl Clone for ZigbeeAps {
    fn clone(&self) -> Self {
        Self {
            frame_type: self.frame_type.clone(),
            delivery_mode: self.delivery_mode.clone(),
            ack_format: self.ack_format.clone(),
            security: self.security.clone(),
            ack_request: self.ack_request.clone(),
            ext_header: self.ext_header.clone(),
            dest_endpoint: self.dest_endpoint.clone(),
            cluster: self.cluster.clone(),
            profile: self.profile.clone(),
            src_endpoint: self.src_endpoint.clone(),
            counter: self.counter.clone(),
            payload: self.payload.clone(),
        }
    }
}

impl ZigbeeAps {
    /// Create an empty APS frame with every header field unset.
    ///
    /// All fields start as [`Field::unset`] and the payload is empty; builders
    /// and `compile()`-time auto-fill resolve the wire values.
    pub fn new() -> Self {
        Self {
            frame_type: Field::unset(),
            delivery_mode: Field::unset(),
            ack_format: Field::unset(),
            security: Field::unset(),
            ack_request: Field::unset(),
            ext_header: Field::unset(),
            dest_endpoint: Field::unset(),
            cluster: Field::unset(),
            profile: Field::unset(),
            src_endpoint: Field::unset(),
            counter: Field::unset(),
            payload: Vec::new(),
        }
    }

    /// Create an APS Data frame.
    ///
    /// Sets the frame type to the data code point (0b00, Zigbee Specification
    /// R23, Table 2-20); every other field is left unset for later auto-fill.
    pub fn data() -> Self {
        Self::new().frame_type(APS_FRAME_TYPE_DATA)
    }

    /// Create an APS Command frame.
    ///
    /// Sets the frame type to the command code point (0b01, Zigbee Specification
    /// R23, Table 2-20); every other field is left unset for later auto-fill.
    pub fn command() -> Self {
        Self::new().frame_type(APS_FRAME_TYPE_COMMAND)
    }

    /// Create an APS Acknowledgement frame.
    ///
    /// Sets the frame type to the acknowledgement code point (0b10, Zigbee
    /// Specification R23, Table 2-20); every other field is left unset for later
    /// auto-fill.
    pub fn ack() -> Self {
        Self::new().frame_type(APS_FRAME_TYPE_ACK)
    }

    /// Set the APS frame type (Frame Control bits 0..=1).
    pub fn frame_type(mut self, frame_type: u8) -> Self {
        self.frame_type.set_user(frame_type);
        self
    }

    /// Set the APS delivery mode (Frame Control bits 2..=3).
    pub fn delivery_mode(mut self, delivery_mode: u8) -> Self {
        self.delivery_mode.set_user(delivery_mode);
        self
    }

    /// Set the destination endpoint octet.
    pub fn dest_endpoint(mut self, dest_endpoint: u8) -> Self {
        self.dest_endpoint.set_user(dest_endpoint);
        self
    }

    /// Set the cluster identifier (16 bits).
    pub fn cluster(mut self, cluster: u16) -> Self {
        self.cluster.set_user(cluster);
        self
    }

    /// Set the profile identifier (16 bits).
    pub fn profile(mut self, profile: u16) -> Self {
        self.profile.set_user(profile);
        self
    }

    /// Set the source endpoint octet.
    pub fn src_endpoint(mut self, src_endpoint: u8) -> Self {
        self.src_endpoint.set_user(src_endpoint);
        self
    }

    /// Set the APS Counter octet.
    pub fn counter(mut self, counter: u8) -> Self {
        self.counter.set_user(counter);
        self
    }

    /// Set the APS payload octets carried after the header.
    pub fn payload(mut self, payload: &[u8]) -> Self {
        self.payload = payload.to_vec();
        self
    }

    /// Resolve the effective APS frame type (Frame Control bits 0..=1).
    ///
    /// Honors a user-set frame type; otherwise defaults to the data code point
    /// (0b00).
    fn effective_frame_type(&self) -> u8 {
        self.frame_type.value().copied().unwrap_or(APS_FRAME_TYPE_DATA)
    }

    /// Resolve the effective APS delivery mode (Frame Control bits 2..=3).
    ///
    /// Honors a user-set delivery mode; otherwise defaults to unicast (0b00).
    fn effective_delivery_mode(&self) -> u8 {
        self.delivery_mode
            .value()
            .copied()
            .unwrap_or(APS_DELIVERY_MODE_UNICAST)
    }

    /// Resolve whether the Destination Endpoint field is present.
    ///
    /// The destination endpoint is present only when the delivery mode is
    /// unicast (0b00) or broadcast (0b10); under group addressing (0b11) it is
    /// replaced by a Group Address, which this layer does not model (Zigbee
    /// Specification R23, Sections 2.2.5.1.2-2.2.5.1.3).
    fn effective_dest_endpoint_present(&self) -> bool {
        matches!(
            self.effective_delivery_mode() & 0b11,
            APS_DELIVERY_MODE_UNICAST | APS_DELIVERY_MODE_BROADCAST
        )
    }

    /// Resolve whether the Cluster Identifier and Profile Identifier are present.
    ///
    /// Both are present only for data (0b00) or acknowledgement (0b10) frames
    /// (Zigbee Specification R23, Sections 2.2.5.1.4-2.2.5.1.5).
    fn effective_cluster_profile_present(&self) -> bool {
        matches!(
            self.effective_frame_type() & 0b11,
            APS_FRAME_TYPE_DATA | APS_FRAME_TYPE_ACK
        )
    }

    /// Assemble the 8-bit APS Frame Control field from the effective fields.
    ///
    /// Packs the frame type (bits 0..=1), delivery mode (bits 2..=3), ACK-format
    /// flag (bit 4), security flag (bit 5), ACK-request flag (bit 6), and
    /// extended-header-present flag (bit 7), per Zigbee Specification R23
    /// Section 2.2.5.1.1 (Figure 2-4; see `.agents/docs/zigbee-manifest.md`).
    /// User-set sub-fields are honored exactly; the frame control is never
    /// "corrected" to be consistent with the fields present.
    fn frame_control(&self) -> u8 {
        let frame_type = self.effective_frame_type() & 0b11;
        let delivery_mode = self.effective_delivery_mode() & 0b11;
        let ack_format = u8::from(self.ack_format.value().copied().unwrap_or(false));
        let security = u8::from(self.security.value().copied().unwrap_or(false));
        let ack_request = u8::from(self.ack_request.value().copied().unwrap_or(false));
        let ext_header = u8::from(self.ext_header.value().copied().unwrap_or(false));

        (frame_type << APS_FC_FRAME_TYPE_SHIFT)
            | (delivery_mode << APS_FC_DELIVERY_MODE_SHIFT)
            | (ack_format << APS_FC_ACK_FORMAT_SHIFT)
            | (security << APS_FC_SECURITY_SHIFT)
            | (ack_request << APS_FC_ACK_REQUEST_SHIFT)
            | (ext_header << APS_FC_EXT_HEADER_SHIFT)
    }

    /// Encoded length, in octets, of the full APS frame.
    ///
    /// Mirrors [`ZigbeeAps::encode`]: Frame Control + the optional destination
    /// endpoint + the optional cluster and profile identifiers + the optional
    /// source endpoint + APS Counter + payload.
    pub(crate) fn encoded_len(&self) -> usize {
        let mut len = APS_FRAME_CONTROL_LEN;
        if self.effective_dest_endpoint_present() {
            len += APS_ENDPOINT_LEN;
        }
        if self.effective_cluster_profile_present() {
            len += APS_CLUSTER_LEN + APS_PROFILE_LEN;
        }
        // Source Endpoint is present whenever the cluster/profile addressing
        // fields are present (data or acknowledgement frames).
        if self.effective_cluster_profile_present() {
            len += APS_ENDPOINT_LEN;
        }
        len += APS_COUNTER_LEN;
        len += self.payload.len();
        len
    }

    /// Serialize the Zigbee APS frame to bytes.
    ///
    /// Emits the 8-bit Frame Control field, the optional destination endpoint,
    /// the optional cluster identifier (u16 LE) and profile identifier (u16 LE),
    /// the optional source endpoint, the APS Counter octet, and the payload, in
    /// the spec field order (Zigbee Specification R23 Section 2.2.5.1, Figure
    /// 2-3; see `.agents/docs/zigbee-manifest.md`). Field presence follows the
    /// effective delivery mode and frame type per the presence rule documented
    /// on [`ZigbeeAps`]. Every user-set field is honored verbatim; no value is
    /// clamped or "corrected".
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());

        out.push(self.frame_control());

        if self.effective_dest_endpoint_present() {
            out.push(self.dest_endpoint.value().copied().unwrap_or(0));
        }
        if self.effective_cluster_profile_present() {
            out.extend_from_slice(&self.cluster.value().copied().unwrap_or(0).to_le_bytes());
            out.extend_from_slice(&self.profile.value().copied().unwrap_or(0).to_le_bytes());
            out.push(self.src_endpoint.value().copied().unwrap_or(0));
        }

        out.push(self.counter.value().copied().unwrap_or(APS_COUNTER_DEFAULT));

        out.extend_from_slice(&self.payload);
        out
    }
}

impl Default for ZigbeeAps {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ZigbeeAps;

    #[test]
    fn zigbee_aps_encode() {
        // An APS data frame addressed to an application endpoint with a small
        // payload.
        //
        // Header field order (Zigbee Specification R23, Section 2.2.5.1,
        // Figure 2-3; see `.agents/docs/zigbee-manifest.md`): Frame Control
        // (u8) + Destination Endpoint (u8) + Cluster Identifier (u16 LE) +
        // Profile Identifier (u16 LE) + Source Endpoint (u8) + APS Counter (u8)
        // + payload.
        //
        // Frame Control: frame type Data = 0b00 (bits 0..=1), delivery mode
        // unicast = 0b00 (bits 2..=3), every other flag 0, so FC = 0x00.
        //
        // This is the layout scapy emits for
        //   ZigbeeAppDataPayload(frame_control=0, aps_frametype=0,
        //       delivery_mode=0, dst_endpoint=0x0A, cluster=0x0006,
        //       profile=0x0104, src_endpoint=0x01, counter=0x2A)/Raw(b"\xAA\xBB")
        // whose bytes are 00 0A 06 00 04 01 01 2A AA BB (FC + dst endpoint +
        // LE cluster + LE profile + src endpoint + counter + payload),
        // cross-checked against the scapy `ZigbeeAppDataPayload` field layout.
        let frame = ZigbeeAps::data()
            .dest_endpoint(0x0A)
            .cluster(0x0006)
            .profile(0x0104)
            .src_endpoint(0x01)
            .counter(0x2A)
            .payload(&[0xAA, 0xBB]);

        let bytes = frame.encode();

        assert_eq!(
            bytes,
            vec![
                0x00, // APS Frame Control: Data + unicast delivery
                0x0A, // destination endpoint 0x0A
                0x06, 0x00, // cluster identifier 0x0006 (little-endian)
                0x04, 0x01, // profile identifier 0x0104 (little-endian)
                0x01, // source endpoint 0x01
                0x2A, // APS counter 42
                0xAA, 0xBB, // APS payload
            ]
        );

        // encoded_len() matches the serialized length.
        assert_eq!(frame.encoded_len(), bytes.len());
    }

    #[test]
    fn zigbee_aps_frame_control_packs_subfields() {
        // Frame type Command = 0b01, delivery mode broadcast = 0b10
        // (0b10 << 2 = 0x08), ACK request set (bit 6 = 0x40):
        //   0x01 | 0x08 | 0x40 = 0x49.
        let frame = ZigbeeAps::command()
            .delivery_mode(0b10)
            .counter(0x01)
            .ack_request_for_test();
        let bytes = frame.encode();

        assert_eq!(bytes[0], 0x49);
    }

    #[test]
    fn zigbee_aps_command_omits_cluster_and_profile() {
        // A command frame (0b01) carries no cluster/profile identifiers, only
        // the frame control, destination endpoint (unicast default), and the
        // APS counter.
        let frame = ZigbeeAps::command().dest_endpoint(0x05).counter(0x07);
        let bytes = frame.encode();

        assert_eq!(
            bytes,
            vec![
                0x01, // APS Frame Control: Command + unicast delivery
                0x05, // destination endpoint 0x05
                0x07, // APS counter 7
            ]
        );
        assert_eq!(frame.encoded_len(), bytes.len());
    }

    #[test]
    fn zigbee_aps_group_delivery_omits_dest_endpoint() {
        // Under group addressing (delivery mode 0b11) the destination endpoint
        // is absent (replaced by a group address, which this layer does not
        // model), but cluster/profile/source-endpoint stay for a data frame.
        let frame = ZigbeeAps::data()
            .delivery_mode(0b11)
            .cluster(0x0006)
            .profile(0x0104)
            .src_endpoint(0x01)
            .counter(0x2A);
        let bytes = frame.encode();

        assert_eq!(
            bytes,
            vec![
                0x0C, // APS Frame Control: Data + group delivery (0b11 << 2)
                0x06, 0x00, // cluster identifier 0x0006 (little-endian)
                0x04, 0x01, // profile identifier 0x0104 (little-endian)
                0x01, // source endpoint 0x01
                0x2A, // APS counter 42
            ]
        );
        assert_eq!(frame.encoded_len(), bytes.len());
    }
}

#[cfg(test)]
impl ZigbeeAps {
    /// Test-only builder that sets the ACK-request flag (Frame Control bit 6).
    fn ack_request_for_test(mut self) -> Self {
        self.ack_request.set_user(true);
        self
    }
}
