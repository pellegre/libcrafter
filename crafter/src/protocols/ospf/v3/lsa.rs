//! OSPFv3 link-state advertisement header (RFC 5340 §A.4.2).
//!
//! The OSPFv3 LSA header is 20 octets, like the OSPFv2 header (RFC 2328
//! §A.4.1), but lays its fields out differently: the LS type is a full 16-bit
//! field (carrying scope and the U-bit, RFC 5340 §A.4.2.1) and there is no
//! separate 8-bit Options octet in the header — OSPFv3 carries Options inside
//! the LSA bodies instead:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            LS age             |           LS type             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Link State ID                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Advertising Router                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     LS sequence number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         LS checksum           |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! As in OSPFv2 the LS checksum is the Fletcher-16 checksum (RFC 905 Annex B)
//! computed over the LSA from octet 2 (the first octet of the LS type, with the
//! LS age excluded) to the end, with the LS checksum field zeroed. The checksum
//! field still sits at octet 16. The Database Description (RFC 5340 §A.3.3) and
//! Link State Acknowledgment (RFC 5340 §A.3.6) bodies carry bare 20-octet
//! [`Ospfv3LsaHeader`] records with no body. Like the OSPFv2 header,
//! [`Ospfv3LsaHeader`] uses [`Field`] members so `compile()` honors any value
//! the caller pinned while auto-filling the length and checksum.

use core::net::Ipv4Addr;

use crate::checksum::fletcher16_checkbytes;
use crate::field::Field;
use crate::{CrafterError, Result};

/// OSPFv3 LSA header length, in octets. RFC 5340 §A.4.2: LS age(2), LS type(2),
/// Link State ID(4), Advertising Router(4), LS sequence number(4), LS
/// checksum(2), length(2).
pub const OSPFV3_LSA_HEADER_LEN: usize = 20;

/// Default LS sequence number (the initial sequence number `InitialSequenceNumber`,
/// RFC 2328 §12.1.6, reused by OSPFv3 per RFC 5340 §A.4.2).
const OSPFV3_LSA_INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;

/// Offset of the LS checksum field within the OSPFv3 LSA, in octets (RFC 5340
/// §A.4.2).
const OSPFV3_LSA_CHECKSUM_OFFSET: usize = 16;

/// Offset where the Fletcher-protected region begins within the OSPFv3 LSA, in
/// octets: octet 2 (the first octet of the LS type), with the LS age (octets
/// 0..2) excluded (RFC 5340 §A.4.2, mirroring RFC 2328 §12.1.7).
const OSPFV3_LSA_CHECKSUM_START: usize = 2;

/// The 20-octet OSPFv3 LSA header (RFC 5340 §A.4.2).
///
/// Shared by the OSPFv3 Database Description and Link State Acknowledgment
/// bodies (which carry bare LSA headers). Unlike the OSPFv2 header
/// ([`OspfLsaHeader`](crate::protocols::ospf::lsa::OspfLsaHeader)) the LS type
/// is a full 16-bit field and there is no 8-bit Options octet in the header.
/// Each field is a [`Field`] so `compile()` fills the `length` and `ls_checksum`
/// the caller left unset while preserving anything set explicitly, including
/// wrong-on-purpose values.
#[derive(Debug, Clone)]
pub struct Ospfv3LsaHeader {
    /// LS age, in seconds (RFC 5340 §A.4.2); defaults to 0.
    ls_age: Field<u16>,
    /// LS type, a full 16-bit field carrying the LSA scope and U-bit (RFC 5340
    /// §A.4.2.1); left unset until a caller or typed body sets it.
    ls_type: Field<u16>,
    /// Link State ID (RFC 5340 §A.4.2); defaults to the unspecified address.
    link_state_id: Field<Ipv4Addr>,
    /// Advertising Router (RFC 5340 §A.4.2); defaults to the unspecified address.
    advertising_router: Field<Ipv4Addr>,
    /// LS sequence number (RFC 5340 §A.4.2); defaults to the initial sequence
    /// number `0x80000001`.
    ls_sequence_number: Field<u32>,
    /// LS checksum, the Fletcher-16 checksum (RFC 5340 §A.4.2); auto-filled.
    ls_checksum: Field<u16>,
    /// LSA length, in octets, including the 20-octet header (RFC 5340 §A.4.2);
    /// auto-filled to cover the header plus the body.
    length: Field<u16>,
}

impl Ospfv3LsaHeader {
    /// Build a new OSPFv3 LSA header with RFC defaults: LS age 0, the LS sequence
    /// number set to the initial sequence number `0x80000001`, the LS type, Link
    /// State ID, and Advertising Router left unset, and the LS checksum and
    /// length unset so `encode_with_body()` fills them.
    pub fn new() -> Self {
        Self {
            ls_age: Field::defaulted(0),
            ls_type: Field::unset(),
            link_state_id: Field::unset(),
            advertising_router: Field::unset(),
            ls_sequence_number: Field::defaulted(OSPFV3_LSA_INITIAL_SEQUENCE_NUMBER),
            ls_checksum: Field::unset(),
            length: Field::unset(),
        }
    }

    /// Construct an OSPFv3 LSA header from decoded wire fields, marking every
    /// field as caller-supplied so re-compilation preserves the decoded values
    /// byte-for-byte.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_decoded_parts(
        ls_age: u16,
        ls_type: u16,
        link_state_id: Ipv4Addr,
        advertising_router: Ipv4Addr,
        ls_sequence_number: u32,
        ls_checksum: u16,
        length: u16,
    ) -> Self {
        Self {
            ls_age: Field::user(ls_age),
            ls_type: Field::user(ls_type),
            link_state_id: Field::user(link_state_id),
            advertising_router: Field::user(advertising_router),
            ls_sequence_number: Field::user(ls_sequence_number),
            ls_checksum: Field::user(ls_checksum),
            length: Field::user(length),
        }
    }

    /// Set the LS age field, in seconds.
    pub fn ls_age(mut self, ls_age: u16) -> Self {
        self.ls_age.set_user(ls_age);
        self
    }

    /// Set the 16-bit LS type field (RFC 5340 §A.4.2.1).
    pub fn ls_type(mut self, ls_type: u16) -> Self {
        self.ls_type.set_user(ls_type);
        self
    }

    /// Set the Link State ID field.
    pub fn link_state_id(mut self, link_state_id: impl Into<Ipv4Addr>) -> Self {
        self.link_state_id.set_user(link_state_id.into());
        self
    }

    /// Set the Advertising Router field.
    pub fn advertising_router(mut self, advertising_router: impl Into<Ipv4Addr>) -> Self {
        self.advertising_router.set_user(advertising_router.into());
        self
    }

    /// Set the LS sequence number field.
    pub fn ls_sequence_number(mut self, ls_sequence_number: u32) -> Self {
        self.ls_sequence_number.set_user(ls_sequence_number);
        self
    }

    /// Force the LS checksum field.
    ///
    /// This preserves malformed-on-purpose LSAs whose checksum is not the
    /// computed Fletcher-16 checksum.
    pub fn ls_checksum(mut self, ls_checksum: u16) -> Self {
        self.ls_checksum.set_user(ls_checksum);
        self
    }

    /// Force the LSA length field.
    ///
    /// This preserves malformed-on-purpose LSAs whose declared length differs
    /// from the emitted byte count.
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// The effective LS age (the caller value, else 0).
    pub fn ls_age_value(&self) -> u16 {
        self.ls_age.value().copied().unwrap_or(0)
    }

    /// The effective 16-bit LS type (the caller value, else 0).
    pub fn ls_type_value(&self) -> u16 {
        self.ls_type.value().copied().unwrap_or(0)
    }

    /// The effective Link State ID (the caller value, else the unspecified
    /// address).
    pub fn link_state_id_value(&self) -> Ipv4Addr {
        self.link_state_id
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The effective Advertising Router (the caller value, else the unspecified
    /// address).
    pub fn advertising_router_value(&self) -> Ipv4Addr {
        self.advertising_router
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The effective LS sequence number (the caller value, else the initial
    /// sequence number `0x80000001`).
    pub fn ls_sequence_number_value(&self) -> u32 {
        self.ls_sequence_number
            .value()
            .copied()
            .unwrap_or(OSPFV3_LSA_INITIAL_SEQUENCE_NUMBER)
    }

    /// The pinned LS checksum, if the caller set it.
    pub fn ls_checksum_value(&self) -> Option<u16> {
        self.ls_checksum.value().copied()
    }

    /// The pinned LSA length, if the caller set it.
    pub fn length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// A one-line summary of the OSPFv3 LSA header for `summary()` /
    /// `inspection_fields()`, like
    /// `LSAv3(type=0x2001, id=192.0.2.1, adv=192.0.2.1, seq=0x80000001, age=0, len=...)`.
    ///
    /// The length shows the pinned value when the caller set one and `auto`
    /// otherwise (the effective length depends on the LSA body, which the header
    /// alone does not hold).
    pub fn summary(&self) -> String {
        let length = match self.length_value() {
            Some(length) => length.to_string(),
            None => "auto".to_string(),
        };
        format!(
            "LSAv3(type=0x{:04x}, id={}, adv={}, seq=0x{:08x}, age={}, len={})",
            self.ls_type_value(),
            self.link_state_id_value(),
            self.advertising_router_value(),
            self.ls_sequence_number_value(),
            self.ls_age_value(),
            length,
        )
    }

    /// Append the 20-octet OSPFv3 LSA header followed by `body` to `out`.
    ///
    /// The `length` field is filled with `20 + body.len()` unless the caller
    /// pinned it, and the LS checksum is filled with the Fletcher-16 checksum
    /// (RFC 905 Annex B) over the LSA from octet 2 to the end (LS age excluded),
    /// with the checksum field zeroed, unless the caller pinned it.
    pub fn encode_with_body(&self, body: &[u8], out: &mut Vec<u8>) {
        let start = out.len();

        // LS age (octets 0..2).
        out.extend_from_slice(&self.ls_age_value().to_be_bytes());
        // LS type, a full 16-bit field (octets 2..4).
        out.extend_from_slice(&self.ls_type_value().to_be_bytes());
        // Link State ID (octets 4..8) and Advertising Router (octets 8..12).
        out.extend_from_slice(&self.link_state_id_value().octets());
        out.extend_from_slice(&self.advertising_router_value().octets());
        // LS sequence number (octets 12..16).
        out.extend_from_slice(&self.ls_sequence_number_value().to_be_bytes());

        // LS checksum placeholder (octets 16..18): zeroed so the auto-fill below
        // can compute over the LSA-with-hole; a pinned checksum is written
        // verbatim.
        let pinned_checksum = self.ls_checksum.value().copied();
        out.extend_from_slice(&pinned_checksum.unwrap_or(0).to_be_bytes());

        // Length (octets 18..20): the caller value, else the 20-octet header
        // plus the body.
        let length = self
            .length
            .value()
            .copied()
            .unwrap_or((OSPFV3_LSA_HEADER_LEN + body.len()) as u16);
        out.extend_from_slice(&length.to_be_bytes());

        // LSA body follows the 20-octet header.
        out.extend_from_slice(body);

        // Auto-fill the LS checksum unless the caller pinned it. The checksum is
        // the Fletcher-16 checksum over the LSA from octet 2 (the first octet of
        // the LS type, LS age excluded) to the end, with the checksum field
        // zeroed (already zeroed by the placeholder above). The checksum field
        // sits at octet 16 of the full LSA, i.e. offset 14 within the octet-2
        // protected slice.
        if pinned_checksum.is_none() {
            let protected = &out[start + OSPFV3_LSA_CHECKSUM_START..];
            let checkbytes = fletcher16_checkbytes(
                protected,
                OSPFV3_LSA_CHECKSUM_OFFSET - OSPFV3_LSA_CHECKSUM_START,
            );
            out[start + OSPFV3_LSA_CHECKSUM_OFFSET..start + OSPFV3_LSA_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&checkbytes);
        }
    }

    /// Decode a 20-octet OSPFv3 LSA header from the front of `bytes`.
    ///
    /// Returns the parsed [`Ospfv3LsaHeader`] (with every field marked
    /// caller-supplied so the LSA round-trips byte-for-byte) and the declared
    /// LSA length read from the header, which spans the header plus the body.
    /// A buffer shorter than 20 octets yields a structured
    /// [`buffer_too_short`](CrafterError::buffer_too_short) error rather than a
    /// panic.
    pub fn decode(bytes: &[u8]) -> Result<(Ospfv3LsaHeader, usize)> {
        if bytes.len() < OSPFV3_LSA_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ospfv3 lsa header",
                OSPFV3_LSA_HEADER_LEN,
                bytes.len(),
            ));
        }

        let ls_age = u16::from_be_bytes([bytes[0], bytes[1]]);
        let ls_type = u16::from_be_bytes([bytes[2], bytes[3]]);
        let link_state_id = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let advertising_router = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);
        let ls_sequence_number = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let ls_checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let length = u16::from_be_bytes([bytes[18], bytes[19]]);

        let header = Ospfv3LsaHeader::from_decoded_parts(
            ls_age,
            ls_type,
            link_state_id,
            advertising_router,
            ls_sequence_number,
            ls_checksum,
            length,
        );

        Ok((header, length as usize))
    }
}

impl Default for Ospfv3LsaHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a trailing list of bare 20-octet OSPFv3 LSA headers.
///
/// The OSPFv3 Database Description (RFC 5340 §A.3.3) and Link State
/// Acknowledgment (RFC 5340 §A.3.6) bodies carry a sequence of LSA headers with
/// no body, so every entry is exactly [`OSPFV3_LSA_HEADER_LEN`] octets
/// regardless of the declared `length` field. This loops while `bytes` is
/// non-empty, decoding one header and advancing the cursor by 20 octets each
/// iteration, mirroring [`decode_lsa_headers`](crate::protocols::ospf::lsa). A
/// remainder shorter than 20 octets yields a structured
/// [`buffer_too_short`](CrafterError::buffer_too_short) error rather than a
/// panic.
///
/// The typed OSPFv3 Database Description and Link State Acknowledgment decoders
/// (`crate::protocols::ospf::v3::decode`) consume this parser.
pub(crate) fn decode_ospfv3_lsa_headers(mut bytes: &[u8]) -> Result<Vec<Ospfv3LsaHeader>> {
    let mut headers = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < OSPFV3_LSA_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ospfv3 lsa header",
                OSPFV3_LSA_HEADER_LEN,
                bytes.len(),
            ));
        }
        let (header, _declared_len) = Ospfv3LsaHeader::decode(bytes)?;
        headers.push(header);
        bytes = &bytes[OSPFV3_LSA_HEADER_LEN..];
    }
    Ok(headers)
}

/// Encode a list of bare OSPFv3 LSA headers, each as a header-only 20-octet
/// record.
///
/// Each header is emitted with an empty body via
/// [`Ospfv3LsaHeader::encode_with_body`], so every entry is exactly
/// [`OSPFV3_LSA_HEADER_LEN`] octets. Shared by the OSPFv3 Database Description
/// and Link State Acknowledgment encoders, which carry only LSA headers
/// (RFC 5340 §A.3.3, §A.3.6).
pub(crate) fn encode_ospfv3_lsa_headers(headers: &[Ospfv3LsaHeader], out: &mut Vec<u8>) {
    for header in headers {
        header.encode_with_body(&[], out);
    }
}

/// Mask selecting the low 24 bits of an OSPFv3 LSA-body Options field (RFC 5340
/// §A.2): the field is encoded as three octets on the wire, like the Options in
/// the Database Description (RFC 5340 §A.3.3).
const OSPFV3_LSA_OPTIONS_MASK: u32 = 0x00ff_ffff;

/// The on-wire length of a single OSPFv3 Router-LSA interface description, in
/// octets: Type(1) + Reserved(1) + Metric(2) + Interface ID(4) + Neighbor
/// Interface ID(4) + Neighbor Router ID(4). RFC 5340 §A.4.3.
const OSPFV3_ROUTER_LSA_INTERFACE_LEN: usize = 16;

/// The fixed (pre-interface-list) length of the OSPFv3 Router-LSA body, in
/// octets: flags(1) + Options(3). RFC 5340 §A.4.3.
const OSPFV3_ROUTER_LSA_FIXED_LEN: usize = 4;

/// The fixed (pre-router-list) length of the OSPFv3 Network-LSA body, in octets:
/// Reserved(1) + Options(3). RFC 5340 §A.4.4.
const OSPFV3_NETWORK_LSA_FIXED_LEN: usize = 4;

/// The on-wire length of a single OSPFv3 Network-LSA attached Router ID, in
/// octets (RFC 5340 §A.4.4).
const OSPFV3_NETWORK_LSA_ROUTER_LEN: usize = 4;

/// A single OSPFv3 Router-LSA interface description (RFC 5340 §A.4.3).
///
/// Each description is the 16-octet record naming one of the originating
/// router's adjacencies: a link Type, a Reserved octet, the Metric (cost), the
/// Interface ID, the Neighbor Interface ID, and the Neighbor Router ID. Unlike
/// the OSPFv2 Router-LSA link descriptions (RFC 2328 §A.4.2), OSPFv3 carries no
/// per-TOS entries and identifies links by interface IDs rather than addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3RouterInterface {
    /// The interface (link) Type (RFC 5340 §A.4.3): point-to-point, transit,
    /// reserved, or virtual link.
    if_type: u8,
    /// The Reserved octet (RFC 5340 §A.4.3); emitted as zero by default but
    /// settable so a malformed-on-purpose record can carry a non-zero value.
    reserved: u8,
    /// The Metric (cost) of using this interface (RFC 5340 §A.4.3).
    metric: u16,
    /// The Interface ID the originating router assigned to this link (RFC 5340
    /// §A.4.3).
    interface_id: u32,
    /// The Neighbor Interface ID (RFC 5340 §A.4.3).
    neighbor_interface_id: u32,
    /// The Neighbor Router ID (RFC 5340 §A.4.3).
    neighbor_router_id: Ipv4Addr,
}

impl Ospfv3RouterInterface {
    /// Build an OSPFv3 Router-LSA interface description from its fields. The
    /// Reserved octet is emitted as zero; use [`reserved`](Self::reserved) to
    /// pin a non-zero value for a malformed-on-purpose record.
    pub fn new(
        if_type: u8,
        metric: u16,
        interface_id: u32,
        neighbor_interface_id: u32,
        neighbor_router_id: impl Into<Ipv4Addr>,
    ) -> Self {
        Self {
            if_type,
            reserved: 0,
            metric,
            interface_id,
            neighbor_interface_id,
            neighbor_router_id: neighbor_router_id.into(),
        }
    }

    /// Set the Reserved octet (RFC 5340 §A.4.3). Normally 0; settable so a
    /// malformed-on-purpose record can carry a non-zero value.
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved = reserved;
        self
    }

    /// The interface (link) Type (RFC 5340 §A.4.3).
    pub fn if_type_value(&self) -> u8 {
        self.if_type
    }

    /// The Reserved octet (RFC 5340 §A.4.3).
    pub fn reserved_value(&self) -> u8 {
        self.reserved
    }

    /// The Metric (cost) of using this interface (RFC 5340 §A.4.3).
    pub fn metric_value(&self) -> u16 {
        self.metric
    }

    /// The Interface ID (RFC 5340 §A.4.3).
    pub fn interface_id_value(&self) -> u32 {
        self.interface_id
    }

    /// The Neighbor Interface ID (RFC 5340 §A.4.3).
    pub fn neighbor_interface_id_value(&self) -> u32 {
        self.neighbor_interface_id
    }

    /// The Neighbor Router ID (RFC 5340 §A.4.3).
    pub fn neighbor_router_id_value(&self) -> Ipv4Addr {
        self.neighbor_router_id
    }

    /// Append this interface description as its 16 big-endian octets — Type(1),
    /// Reserved(1), Metric(2), Interface ID(4), Neighbor Interface ID(4),
    /// Neighbor Router ID(4) — to `out` (RFC 5340 §A.4.3).
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.if_type);
        out.push(self.reserved);
        out.extend_from_slice(&self.metric.to_be_bytes());
        out.extend_from_slice(&self.interface_id.to_be_bytes());
        out.extend_from_slice(&self.neighbor_interface_id.to_be_bytes());
        out.extend_from_slice(&self.neighbor_router_id.octets());
    }
}

/// OSPFv3 Router-LSA body (RFC 5340 §A.4.3).
///
/// The Router-LSA (LS type function code 1, i.e. LS type `0x2001` with the
/// area scope and U-bit) describes the originating router's interfaces to an
/// area. It follows the 20-octet [`Ospfv3LsaHeader`] and is a 4-octet fixed
/// prefix — a router-description flags octet then the 24-bit Options — followed
/// by zero or more 16-octet interface descriptions:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    0    |Nt|x|V|E|B|            Options                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |       0       |          Metric              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Interface ID                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Neighbor Interface ID                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    Neighbor Router ID                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                            ...
/// ```
///
/// Like the other LSA bodies, [`Ospfv3RouterLsa`] rides inside an [`Ospfv3Lsa`]
/// as an [`Ospfv3LsaBody::Router`] variant, and [`Ospfv3Lsa::encode`] auto-fills
/// the enclosing LSA `length` and the Fletcher-16 checksum over the header plus
/// this body. The flags and 24-bit Options use [`Field`] members so `compile()`
/// honors any value the caller pinned.
#[derive(Debug, Clone)]
pub struct Ospfv3RouterLsa {
    /// The router-description flags octet (RFC 5340 §A.4.3); defaults to 0.
    flags: Field<u8>,
    /// Optional capabilities (RFC 5340 §A.2), 24-bit; defaults to 0. Only the low
    /// 24 bits are emitted on the wire.
    options: Field<u32>,
    /// The interface descriptions, in order (RFC 5340 §A.4.3).
    interfaces: Vec<Ospfv3RouterInterface>,
}

impl Ospfv3RouterLsa {
    /// Build an OSPFv3 Router-LSA body with the flags and Options defaulted to 0
    /// and an empty interface-description list.
    pub fn new() -> Self {
        Self {
            flags: Field::defaulted(0),
            options: Field::defaulted(0),
            interfaces: Vec::new(),
        }
    }

    /// Set the router-description flags octet (RFC 5340 §A.4.3).
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set the Options field (RFC 5340 §A.2 capability bits, 24-bit). Only the low
    /// 24 bits are emitted on the wire.
    pub fn options(mut self, options: u32) -> Self {
        self.options.set_user(options);
        self
    }

    /// Append a single interface description to the Router-LSA.
    pub fn interface(mut self, interface: Ospfv3RouterInterface) -> Self {
        self.interfaces.push(interface);
        self
    }

    /// Append several interface descriptions to the Router-LSA.
    pub fn interfaces<I>(mut self, interfaces: I) -> Self
    where
        I: IntoIterator<Item = Ospfv3RouterInterface>,
    {
        self.interfaces.extend(interfaces);
        self
    }

    /// The effective router-description flags octet (the caller value, else 0).
    pub fn flags_value(&self) -> u8 {
        self.flags.value().copied().unwrap_or(0)
    }

    /// The effective Options field, masked to the low 24 bits emitted on the wire
    /// (the caller value, else 0).
    pub fn options_value(&self) -> u32 {
        self.options.value().copied().unwrap_or(0) & OSPFV3_LSA_OPTIONS_MASK
    }

    /// The interface descriptions, in order (RFC 5340 §A.4.3).
    pub fn interfaces_value(&self) -> &[Ospfv3RouterInterface] {
        &self.interfaces
    }

    /// The on-wire length of this Router-LSA body, in octets: the 4-octet fixed
    /// prefix plus 16 octets per interface description.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPFV3_ROUTER_LSA_FIXED_LEN + self.interfaces.len() * OSPFV3_ROUTER_LSA_INTERFACE_LEN
    }

    /// Append the RFC 5340 §A.4.3 OSPFv3 Router-LSA body to `out`: the flags octet
    /// and the 24-bit Options packed into three octets, then each 16-octet
    /// interface description.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        // flags(1), then the 24-bit Options as three big-endian octets.
        out.push(self.flags_value());
        let options = self.options_value();
        out.push(((options >> 16) & 0xff) as u8);
        out.push(((options >> 8) & 0xff) as u8);
        out.push((options & 0xff) as u8);
        for interface in &self.interfaces {
            interface.encode(out);
        }
    }
}

impl Default for Ospfv3RouterLsa {
    fn default() -> Self {
        Self::new()
    }
}

/// OSPFv3 Network-LSA body (RFC 5340 §A.4.4).
///
/// The Network-LSA (LS type function code 2, i.e. LS type `0x2002`) is
/// originated for each transit network by its designated router. It follows the
/// 20-octet [`Ospfv3LsaHeader`] and is a 4-octet fixed prefix — a Reserved octet
/// then the 24-bit Options — followed by the Router IDs of each router attached
/// to the network (including the designated router itself):
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       0       |                  Options                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Attached Router                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              ...                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Unlike the OSPFv2 Network-LSA (RFC 2328 §A.4.3) there is no network-mask
/// field — OSPFv3 addressing lives in separate Intra-Area-Prefix-LSAs. Like the
/// other LSA bodies, [`Ospfv3NetworkLsa`] rides inside an [`Ospfv3Lsa`] as an
/// [`Ospfv3LsaBody::Network`] variant, and [`Ospfv3Lsa::encode`] auto-fills the
/// enclosing LSA `length` and the Fletcher-16 checksum. The Reserved octet and
/// 24-bit Options use [`Field`] members so `compile()` honors any pinned value.
#[derive(Debug, Clone)]
pub struct Ospfv3NetworkLsa {
    /// The Reserved octet (RFC 5340 §A.4.4); defaults to 0. Settable so a
    /// malformed-on-purpose body can carry a non-zero value.
    reserved: Field<u8>,
    /// Optional capabilities (RFC 5340 §A.2), 24-bit; defaults to 0. Only the low
    /// 24 bits are emitted on the wire.
    options: Field<u32>,
    /// The Router IDs of each attached router, in order (RFC 5340 §A.4.4).
    attached_routers: Vec<Ipv4Addr>,
}

impl Ospfv3NetworkLsa {
    /// Build an OSPFv3 Network-LSA body with the Reserved octet and Options
    /// defaulted to 0 and an empty attached-router list.
    pub fn new() -> Self {
        Self {
            reserved: Field::defaulted(0),
            options: Field::defaulted(0),
            attached_routers: Vec::new(),
        }
    }

    /// Set the Reserved octet (RFC 5340 §A.4.4). Normally 0; settable so a
    /// malformed-on-purpose body can carry a non-zero value.
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the Options field (RFC 5340 §A.2 capability bits, 24-bit). Only the low
    /// 24 bits are emitted on the wire.
    pub fn options(mut self, options: u32) -> Self {
        self.options.set_user(options);
        self
    }

    /// Append a single attached-router Router ID to the Network-LSA.
    pub fn attached_router(mut self, router_id: impl Into<Ipv4Addr>) -> Self {
        self.attached_routers.push(router_id.into());
        self
    }

    /// Append several attached-router Router IDs to the Network-LSA.
    pub fn attached_routers<I>(mut self, routers: I) -> Self
    where
        I: IntoIterator<Item = Ipv4Addr>,
    {
        self.attached_routers.extend(routers);
        self
    }

    /// The effective Reserved octet (the caller value, else 0).
    pub fn reserved_value(&self) -> u8 {
        self.reserved.value().copied().unwrap_or(0)
    }

    /// The effective Options field, masked to the low 24 bits emitted on the wire
    /// (the caller value, else 0).
    pub fn options_value(&self) -> u32 {
        self.options.value().copied().unwrap_or(0) & OSPFV3_LSA_OPTIONS_MASK
    }

    /// The attached-router Router IDs, in order (RFC 5340 §A.4.4).
    pub fn attached_routers_value(&self) -> &[Ipv4Addr] {
        &self.attached_routers
    }

    /// The on-wire length of this Network-LSA body, in octets: the 4-octet fixed
    /// prefix plus 4 octets per attached router.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPFV3_NETWORK_LSA_FIXED_LEN + self.attached_routers.len() * OSPFV3_NETWORK_LSA_ROUTER_LEN
    }

    /// Append the RFC 5340 §A.4.4 OSPFv3 Network-LSA body to `out`: the Reserved
    /// octet and the 24-bit Options packed into three octets, then each attached
    /// Router ID (4 octets each).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        // Reserved(1), then the 24-bit Options as three big-endian octets.
        out.push(self.reserved_value());
        let options = self.options_value();
        out.push(((options >> 16) & 0xff) as u8);
        out.push(((options >> 8) & 0xff) as u8);
        out.push((options & 0xff) as u8);
        for router in &self.attached_routers {
            out.extend_from_slice(&router.octets());
        }
    }
}

impl Default for Ospfv3NetworkLsa {
    fn default() -> Self {
        Self::new()
    }
}

/// The type-specific body of an OSPFv3 LSA, following the 20-octet
/// [`Ospfv3LsaHeader`] (RFC 5340 §A.4).
///
/// This block models the typed [`Ospfv3LsaBody::Router`] (RFC 5340 §A.4.3) and
/// [`Ospfv3LsaBody::Network`] (RFC 5340 §A.4.4) bodies, plus the
/// [`Ospfv3LsaBody::Raw`] variant, which preserves the LSA body bytes verbatim
/// for an LSA type the builder does not (yet) model so they round-trip
/// byte-for-byte (mirroring the OSPFv2
/// [`OspfLsaBody`](crate::protocols::ospf::lsa::OspfLsaBody) family). Further
/// typed v3 LSA bodies are added by later steps.
#[derive(Debug, Clone)]
pub enum Ospfv3LsaBody {
    /// An LSA body the container does not (yet) model, preserved verbatim. The
    /// bytes are everything after the 20-octet LSA header.
    Raw(Vec<u8>),
    /// A Router-LSA body (LS type function code 1), the originating router's
    /// interface descriptions to an area (RFC 5340 §A.4.3).
    Router(Ospfv3RouterLsa),
    /// A Network-LSA body (LS type function code 2), the Router IDs of each
    /// router attached to a transit network (RFC 5340 §A.4.4).
    Network(Ospfv3NetworkLsa),
}

impl Ospfv3LsaBody {
    /// The on-wire length of this LSA body, in octets (the bytes after the
    /// 20-octet header).
    pub(crate) fn encoded_len(&self) -> usize {
        match self {
            Ospfv3LsaBody::Raw(body) => body.len(),
            Ospfv3LsaBody::Router(router) => router.encoded_len(),
            Ospfv3LsaBody::Network(network) => network.encoded_len(),
        }
    }

    /// Append this LSA body's bytes to `out`. The typed variants serialize their
    /// fields per the RFC; the [`Ospfv3LsaBody::Raw`] variant writes its bytes
    /// verbatim.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Ospfv3LsaBody::Raw(body) => out.extend_from_slice(body),
            Ospfv3LsaBody::Router(router) => router.encode(out),
            Ospfv3LsaBody::Network(network) => network.encode(out),
        }
    }
}

/// A complete OSPFv3 link-state advertisement: the 20-octet [`Ospfv3LsaHeader`]
/// (RFC 5340 §A.4.2) immediately followed by its type-specific
/// [`Ospfv3LsaBody`].
///
/// The header's `length` field spans the header plus the body, and the LS
/// checksum is the Fletcher-16 checksum over the LSA from octet 2 (LS age
/// excluded) to the end. [`Ospfv3Lsa::encode`] auto-fills both over header +
/// body unless the caller pinned them — exactly as the OSPFv2
/// [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) does — so an LSA built with
/// the crate is protocol-correct by default while deliberately malformed
/// length/checksum values survive untouched.
#[derive(Debug, Clone)]
pub struct Ospfv3Lsa {
    /// The 20-octet OSPFv3 LSA header (RFC 5340 §A.4.2).
    pub header: Ospfv3LsaHeader,
    /// The type-specific LSA body following the header.
    pub body: Ospfv3LsaBody,
}

impl Ospfv3Lsa {
    /// Build an OSPFv3 LSA from its header and body.
    pub fn new(header: Ospfv3LsaHeader, body: Ospfv3LsaBody) -> Self {
        Self { header, body }
    }

    /// The on-wire length of this LSA, in octets: the 20-octet header plus the
    /// body.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPFV3_LSA_HEADER_LEN + self.body.encoded_len()
    }

    /// Append the complete OSPFv3 LSA (header + body) to `out`.
    ///
    /// The body is serialized to a scratch buffer first, then the header is
    /// emitted via [`Ospfv3LsaHeader::encode_with_body`] so the `length` field is
    /// filled with `20 + body.len()` and the LS Fletcher checksum is filled over
    /// the LSA from octet 2 (LS age excluded) — each unless the caller pinned it.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let mut body_bytes = Vec::with_capacity(self.body.encoded_len());
        self.body.encode(&mut body_bytes);
        self.header.encode_with_body(&body_bytes, out);
    }
}

/// The on-wire length of the OSPFv3 Link State Update `# LSAs` count field, in
/// octets (RFC 5340 §A.3.5).
const OSPFV3_LSU_COUNT_LEN: usize = 4;

/// OSPFv3 Link State Update packet body (RFC 5340 §A.3.5).
///
/// The Link State Update body follows the 16-octet OSPFv3 common header (RFC
/// 5340 §A.3.1) and carries the flooded LSAs themselves. It begins with a
/// 4-octet count of advertisements and is then the concatenation of that many
/// complete OSPFv3 LSAs:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            # LSAs                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             LSAs                              |
/// +-                                                            +-+
/// |                              ...                             ...
/// ```
///
/// Each LSA is a 20-octet [`Ospfv3LsaHeader`] (RFC 5340 §A.4.2) immediately
/// followed by its type-specific body; the header's `length` field covers the
/// header plus the body. The `# LSAs` count auto-fills from the number of
/// carried LSAs unless the caller pinned it, so a deliberately wrong count
/// survives `compile()`. Like the other v3 bodies, [`Ospfv3LinkStateUpdate`]
/// rides inside the [`Ospfv3`](crate::protocols::ospf::Ospfv3) layer as an
/// [`Ospfv3Body::LinkStateUpdate`](crate::protocols::ospf::Ospfv3Body::LinkStateUpdate)
/// variant; its `encode()`/`encoded_len()` are what the layer's `compile()`
/// routes to.
#[derive(Debug, Clone)]
pub struct Ospfv3LinkStateUpdate {
    /// The `# LSAs` count (RFC 5340 §A.3.5). Left unset so `encode()` fills it
    /// with the number of carried LSAs; a pinned value (including a deliberately
    /// wrong one) survives untouched.
    num_lsas: Field<u32>,
    /// The carried LSAs, in order.
    lsas: Vec<Ospfv3Lsa>,
}

impl Ospfv3LinkStateUpdate {
    /// Build an OSPFv3 Link State Update body with an empty LSA list and an unset
    /// count.
    pub fn new() -> Self {
        Self {
            num_lsas: Field::unset(),
            lsas: Vec::new(),
        }
    }

    /// Append a single LSA to the update's LSA list.
    pub fn lsa(mut self, lsa: Ospfv3Lsa) -> Self {
        self.lsas.push(lsa);
        self
    }

    /// Append several LSAs to the update's LSA list.
    pub fn lsas<I>(mut self, lsas: I) -> Self
    where
        I: IntoIterator<Item = Ospfv3Lsa>,
    {
        self.lsas.extend(lsas);
        self
    }

    /// Force the `# LSAs` count field (RFC 5340 §A.3.5).
    ///
    /// This preserves malformed-on-purpose updates whose declared count differs
    /// from the number of carried LSAs.
    pub fn num_lsas(mut self, num_lsas: u32) -> Self {
        self.num_lsas.set_user(num_lsas);
        self
    }

    /// The carried LSAs, in order.
    pub fn lsas_value(&self) -> &[Ospfv3Lsa] {
        &self.lsas
    }

    /// The effective `# LSAs` count: the caller value, else the number of carried
    /// LSAs.
    pub fn num_lsas_value(&self) -> u32 {
        self.num_lsas
            .value()
            .copied()
            .unwrap_or(self.lsas.len() as u32)
    }

    /// The on-wire length of this Link State Update body, in octets: the 4-octet
    /// count plus the total size of every carried LSA (each 20-octet header plus
    /// its body).
    pub(crate) fn encoded_len(&self) -> usize {
        OSPFV3_LSU_COUNT_LEN + self.lsas.iter().map(Ospfv3Lsa::encoded_len).sum::<usize>()
    }

    /// Append the RFC 5340 §A.3.5 OSPFv3 Link State Update body to `out`: the
    /// `# LSAs` count (the caller value, else the number of carried LSAs), then
    /// each LSA (header + body) with its length and LS checksum auto-filled.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.num_lsas_value().to_be_bytes());
        for lsa in &self.lsas {
            lsa.encode(out);
        }
    }
}

impl Default for Ospfv3LinkStateUpdate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;

    /// An OSPFv3 LSA header built over a small body round-trips through
    /// `encode_with_body` / `decode`: the auto-filled length covers the 20-octet
    /// header plus the body, the Fletcher checksum validates, the 16-bit LS type
    /// occupies octets 2..4, and the decoded fields equal the built ones.
    #[test]
    fn ospfv3_lsa_header_round_trips_with_auto_length_and_checksum() {
        let body = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        // 0x2001 is the OSPFv3 Router-LSA function code with the U-bit and the
        // area scope bits set (RFC 5340 §A.4.2.1); here it just exercises a full
        // 16-bit LS type value.
        let header = Ospfv3LsaHeader::new()
            .ls_age(0)
            .ls_type(0x2001)
            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
            .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
            .ls_sequence_number(0x8000_0001);

        let mut out = Vec::new();
        header.encode_with_body(&body, &mut out);

        // The emitted LSA is the 20-octet header plus the body.
        assert_eq!(out.len(), OSPFV3_LSA_HEADER_LEN + body.len());

        // The 16-bit LS type occupies octets 2..4 (no 8-bit Options octet, unlike
        // OSPFv2).
        assert_eq!(&out[2..4], &0x2001u16.to_be_bytes());

        // The auto-filled length field (octets 18..20) covers header + body.
        let expected_len = (OSPFV3_LSA_HEADER_LEN + body.len()) as u16;
        assert_eq!(&out[18..20], &expected_len.to_be_bytes());

        // The Fletcher-16 checksum over the whole LSA validates.
        assert!(
            fletcher16_valid(&out),
            "auto-filled Fletcher checksum should validate over the OSPFv3 LSA"
        );

        // Decoding returns the parsed header and the declared LSA length.
        let (decoded, declared_len) =
            Ospfv3LsaHeader::decode(&out).expect("OSPFv3 LSA header decodes");
        assert_eq!(declared_len, OSPFV3_LSA_HEADER_LEN + body.len());

        // The decoded fields equal the built ones.
        assert_eq!(decoded.ls_age_value(), 0);
        assert_eq!(decoded.ls_type_value(), 0x2001);
        assert_eq!(decoded.link_state_id_value(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            decoded.advertising_router_value(),
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert_eq!(decoded.ls_sequence_number_value(), 0x8000_0001);
        assert_eq!(decoded.length_value(), Some(expected_len));

        // Re-encoding the decoded header (its checksum is now user-set) with the
        // same body reproduces the original LSA bytes.
        let mut reencoded = Vec::new();
        decoded.encode_with_body(&body, &mut reencoded);
        assert_eq!(reencoded, out);
    }

    /// A caller-set LS checksum survives `encode_with_body` untouched, so
    /// malformed-on-purpose OSPFv3 LSAs keep their wrong checksum.
    #[test]
    fn ospfv3_lsa_header_user_checksum_survives_encode() {
        let body = [0x00, 0x01, 0x02, 0x03];
        let header = Ospfv3LsaHeader::new()
            .ls_type(0x2002)
            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
            .advertising_router(Ipv4Addr::new(192, 0, 2, 2))
            .ls_checksum(0xBEEF);

        let mut out = Vec::new();
        header.encode_with_body(&body, &mut out);

        // The pinned checksum is written verbatim, not recomputed.
        assert_eq!(&out[16..18], &0xBEEFu16.to_be_bytes());

        // The length still auto-fills to cover the header plus the body.
        assert_eq!(
            &out[18..20],
            &((OSPFV3_LSA_HEADER_LEN + body.len()) as u16).to_be_bytes()
        );
    }

    /// A buffer shorter than the 20-octet OSPFv3 LSA header yields a structured
    /// buffer-too-short error rather than a panic.
    #[test]
    fn ospfv3_lsa_header_decode_rejects_short_buffer() {
        let short = [0u8; OSPFV3_LSA_HEADER_LEN - 1];
        let err = Ospfv3LsaHeader::decode(&short).expect_err("a short buffer must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospfv3 lsa header");
                assert_eq!(required, OSPFV3_LSA_HEADER_LEN);
                assert_eq!(available, OSPFV3_LSA_HEADER_LEN - 1);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }

    /// A list of three bare OSPFv3 LSA headers encodes to 60 octets and
    /// round-trips through `encode_ospfv3_lsa_headers` / `decode_ospfv3_lsa_headers`,
    /// and a 50-octet buffer (two full headers plus a 10-octet partial third)
    /// yields a structured buffer-too-short error rather than a panic.
    #[test]
    fn ospfv3_lsa_headers_list_round_trips_and_rejects_partial_trailer() {
        let headers = [
            Ospfv3LsaHeader::new()
                .ls_type(0x2001)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            Ospfv3LsaHeader::new()
                .ls_type(0x2002)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                .ls_sequence_number(0x8000_0002),
            Ospfv3LsaHeader::new()
                .ls_type(0x2003)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0003),
        ];

        let mut out = Vec::new();
        encode_ospfv3_lsa_headers(&headers, &mut out);

        // Three header-only records, 20 octets each.
        assert_eq!(out.len(), 3 * OSPFV3_LSA_HEADER_LEN);

        let decoded = decode_ospfv3_lsa_headers(&out).expect("OSPFv3 LSA header list decodes");
        assert_eq!(decoded.len(), 3);

        // Every field round-trips for each header.
        for (original, parsed) in headers.iter().zip(decoded.iter()) {
            assert_eq!(parsed.ls_age_value(), original.ls_age_value());
            assert_eq!(parsed.ls_type_value(), original.ls_type_value());
            assert_eq!(parsed.link_state_id_value(), original.link_state_id_value());
            assert_eq!(
                parsed.advertising_router_value(),
                original.advertising_router_value()
            );
            assert_eq!(
                parsed.ls_sequence_number_value(),
                original.ls_sequence_number_value()
            );
            // The declared length of a header-only record is 20 octets.
            assert_eq!(parsed.length_value(), Some(OSPFV3_LSA_HEADER_LEN as u16));
        }

        // A 50-octet buffer (two full headers plus a 10-octet partial third)
        // surfaces a structured error on the trailing remainder.
        let partial = &out[..2 * OSPFV3_LSA_HEADER_LEN + 10];
        assert_eq!(partial.len(), 50);
        let err =
            decode_ospfv3_lsa_headers(partial).expect_err("a partial trailing header must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospfv3 lsa header");
                assert_eq!(required, OSPFV3_LSA_HEADER_LEN);
                assert_eq!(available, 10);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }

    /// An OSPFv3 Router-LSA body built with one 16-octet interface description
    /// encodes to the exact RFC 5340 §A.4.3 layout — the 4-octet fixed prefix
    /// (flags + 24-bit Options) then Type(1), Reserved(1), Metric(2), Interface
    /// ID(4), Neighbor Interface ID(4), Neighbor Router ID(4) — and, wrapped in an
    /// [`Ospfv3Lsa`], auto-fills the LSA length and a valid Fletcher checksum.
    #[test]
    fn ospfv3_router_lsa_one_interface_layout_and_checksum() {
        // 0x000013 exercises the 24-bit Options packing; the high octet of the
        // u32 (0xff) must be masked off on the wire.
        let router =
            Ospfv3RouterLsa::new()
                .options(0x00ff_0013)
                .interface(Ospfv3RouterInterface::new(
                    1, // Type: point-to-point
                    10,
                    0x0000_0005,
                    0x0000_0006,
                    Ipv4Addr::new(192, 0, 2, 2),
                ));

        assert_eq!(router.options_value(), 0x00ff_0013);
        assert_eq!(router.interfaces_value().len(), 1);

        let mut body = Vec::new();
        router.encode(&mut body);
        assert_eq!(body.len(), router.encoded_len());
        // 4-octet fixed prefix plus one 16-octet interface description.
        assert_eq!(body.len(), 20);

        // Hand-checked RFC 5340 §A.4.3 fixed prefix (flags + 24-bit Options).
        assert_eq!(body[0], 0x00); // flags
        assert_eq!(&body[1..4], &[0xff, 0x00, 0x13]); // Options (24-bit)

        // The 16-octet interface description.
        assert_eq!(body[4], 1); // Type
        assert_eq!(body[5], 0); // Reserved
        assert_eq!(&body[6..8], &10u16.to_be_bytes()); // Metric
        assert_eq!(&body[8..12], &0x0000_0005u32.to_be_bytes()); // Interface ID
        assert_eq!(&body[12..16], &0x0000_0006u32.to_be_bytes()); // Neighbor Interface ID
        assert_eq!(&body[16..20], &Ipv4Addr::new(192, 0, 2, 2).octets()); // Neighbor Router ID

        // Wrap the Router-LSA in an Ospfv3Lsa: the LSA length auto-fills to cover
        // the 20-octet header plus the body, and the Fletcher checksum validates.
        let lsa = Ospfv3Lsa::new(
            Ospfv3LsaHeader::new()
                .ls_type(0x2001)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            Ospfv3LsaBody::Router(router),
        );
        assert_eq!(lsa.encoded_len(), OSPFV3_LSA_HEADER_LEN + body.len());

        let mut lsa_bytes = Vec::new();
        lsa.encode(&mut lsa_bytes);
        assert_eq!(lsa_bytes.len(), OSPFV3_LSA_HEADER_LEN + body.len());
        // The LSA length field (octets 18..20) covers header + body.
        assert_eq!(
            &lsa_bytes[18..20],
            &((OSPFV3_LSA_HEADER_LEN + body.len()) as u16).to_be_bytes()
        );
        // The body follows the 20-octet header verbatim.
        assert_eq!(&lsa_bytes[OSPFV3_LSA_HEADER_LEN..], body.as_slice());
        assert!(
            fletcher16_valid(&lsa_bytes),
            "auto-filled Fletcher checksum should validate over the OSPFv3 Router-LSA"
        );
    }

    /// An OSPFv3 Network-LSA body built with two attached routers encodes to the
    /// exact RFC 5340 §A.4.4 layout — the 4-octet fixed prefix (Reserved +
    /// 24-bit Options) then each 4-octet attached Router ID — and, wrapped in an
    /// [`Ospfv3Lsa`], auto-fills the LSA length and a valid Fletcher checksum.
    #[test]
    fn ospfv3_network_lsa_two_attached_routers_layout_and_checksum() {
        let network = Ospfv3NetworkLsa::new()
            .options(0x0000_0013)
            .attached_router(Ipv4Addr::new(192, 0, 2, 1))
            .attached_router(Ipv4Addr::new(192, 0, 2, 2));

        assert_eq!(network.options_value(), 0x0000_0013);
        assert_eq!(network.attached_routers_value().len(), 2);

        let mut body = Vec::new();
        network.encode(&mut body);
        assert_eq!(body.len(), network.encoded_len());
        // 4-octet fixed prefix plus two 4-octet attached routers.
        assert_eq!(body.len(), 12);

        // Hand-checked RFC 5340 §A.4.4 fixed prefix (Reserved + 24-bit Options);
        // unlike OSPFv2 there is no network-mask field.
        assert_eq!(body[0], 0x00); // Reserved
        assert_eq!(&body[1..4], &[0x00, 0x00, 0x13]); // Options (24-bit)
        assert_eq!(&body[4..8], &Ipv4Addr::new(192, 0, 2, 1).octets());
        assert_eq!(&body[8..12], &Ipv4Addr::new(192, 0, 2, 2).octets());

        let lsa = Ospfv3Lsa::new(
            Ospfv3LsaHeader::new()
                .ls_type(0x2002)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0002),
            Ospfv3LsaBody::Network(network),
        );
        assert_eq!(lsa.encoded_len(), OSPFV3_LSA_HEADER_LEN + body.len());

        let mut lsa_bytes = Vec::new();
        lsa.encode(&mut lsa_bytes);
        assert_eq!(
            &lsa_bytes[18..20],
            &((OSPFV3_LSA_HEADER_LEN + body.len()) as u16).to_be_bytes()
        );
        assert_eq!(&lsa_bytes[OSPFV3_LSA_HEADER_LEN..], body.as_slice());
        assert!(
            fletcher16_valid(&lsa_bytes),
            "auto-filled Fletcher checksum should validate over the OSPFv3 Network-LSA"
        );
    }

    /// An OSPFv3 Link State Update body carrying a Router-LSA and a Network-LSA
    /// reports two LSAs, sizes each LSA's length and Fletcher checksum correctly,
    /// and matches the standalone-encoded LSA bytes after the 4-octet count.
    #[test]
    fn ospfv3_link_state_update_body_carries_router_and_network_lsas() {
        let router_lsa = Ospfv3Lsa::new(
            Ospfv3LsaHeader::new()
                .ls_type(0x2001)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            Ospfv3LsaBody::Router(Ospfv3RouterLsa::new().interface(Ospfv3RouterInterface::new(
                1,
                10,
                0x0000_0005,
                0x0000_0006,
                Ipv4Addr::new(192, 0, 2, 2),
            ))),
        );
        let network_lsa = Ospfv3Lsa::new(
            Ospfv3LsaHeader::new()
                .ls_type(0x2002)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0002),
            Ospfv3LsaBody::Network(
                Ospfv3NetworkLsa::new()
                    .attached_router(Ipv4Addr::new(192, 0, 2, 1))
                    .attached_router(Ipv4Addr::new(192, 0, 2, 2)),
            ),
        );

        // Standalone-encode each LSA for comparison.
        let mut router_bytes = Vec::new();
        router_lsa.encode(&mut router_bytes);
        let mut network_bytes = Vec::new();
        network_lsa.encode(&mut network_bytes);

        let lsu = Ospfv3LinkStateUpdate::new()
            .lsa(router_lsa)
            .lsa(network_lsa);
        assert_eq!(lsu.lsas_value().len(), 2);
        assert_eq!(lsu.num_lsas_value(), 2);

        let mut body = Vec::new();
        lsu.encode(&mut body);
        assert_eq!(body.len(), lsu.encoded_len());

        // # LSAs field (octets 0..4) reports two LSAs.
        assert_eq!(&body[0..4], &2u32.to_be_bytes());

        // The two LSAs follow the count, each matching its standalone encoding.
        assert_eq!(
            &body[OSPFV3_LSU_COUNT_LEN..OSPFV3_LSU_COUNT_LEN + router_bytes.len()],
            router_bytes.as_slice()
        );
        assert_eq!(
            &body[OSPFV3_LSU_COUNT_LEN + router_bytes.len()..],
            network_bytes.as_slice()
        );

        // Each carried LSA carries a valid Fletcher-16 checksum.
        assert!(fletcher16_valid(&router_bytes));
        assert!(fletcher16_valid(&network_bytes));
    }

    /// A caller-set `# LSAs` count survives `encode()` untouched, so a
    /// malformed-on-purpose OSPFv3 update keeps its wrong count.
    #[test]
    fn ospfv3_link_state_update_user_count_survives_encode() {
        let lsu = Ospfv3LinkStateUpdate::new()
            .lsa(Ospfv3Lsa::new(
                Ospfv3LsaHeader::new()
                    .ls_type(0x2001)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                    .advertising_router(Ipv4Addr::new(192, 0, 2, 1)),
                Ospfv3LsaBody::Raw(vec![0x00, 0x01]),
            ))
            .num_lsas(5);
        assert_eq!(lsu.num_lsas_value(), 5);

        let mut body = Vec::new();
        lsu.encode(&mut body);
        assert_eq!(&body[0..4], &5u32.to_be_bytes());
    }

    /// An `Ipv6 / Ospfv3::link_state_update()` packet carrying an OSPFv3
    /// Router-LSA and a Network-LSA compiles with auto-filled per-LSA lengths and
    /// Fletcher checksums, decodes back through the default registry over IPv6
    /// next-header 89, and round-trips byte-for-byte. Uses `2001:db8::/32`
    /// documentation addresses. The decode path preserves the LSU body verbatim
    /// in `Ospfv3Body::Unknown` (typed LSU decode lands in a later step), so the
    /// round-trip holds via byte preservation.
    #[test]
    fn ospfv3_link_state_update_over_ipv6_round_trips() {
        use crate::packet::{NetworkLayer, Packet};
        use crate::protocols::ip::v6::Ipv6;
        use crate::protocols::ospf::{Ospfv3, OSPFV3_HEADER_LEN, OSPFV3_TYPE_LINK_STATE_UPDATE};
        use core::net::Ipv6Addr;

        let router_lsa = Ospfv3Lsa::new(
            Ospfv3LsaHeader::new()
                .ls_type(0x2001)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            Ospfv3LsaBody::Router(Ospfv3RouterLsa::new().interface(Ospfv3RouterInterface::new(
                1,
                10,
                0x0000_0005,
                0x0000_0006,
                Ipv4Addr::new(192, 0, 2, 2),
            ))),
        );
        let network_lsa = Ospfv3Lsa::new(
            Ospfv3LsaHeader::new()
                .ls_type(0x2002)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0002),
            Ospfv3LsaBody::Network(
                Ospfv3NetworkLsa::new()
                    .attached_router(Ipv4Addr::new(192, 0, 2, 1))
                    .attached_router(Ipv4Addr::new(192, 0, 2, 2)),
            ),
        );

        let lsu = Ospfv3LinkStateUpdate::new()
            .lsa(router_lsa)
            .lsa(network_lsa);
        let mut body = Vec::new();
        lsu.encode(&mut body);

        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let ospfv3 = Ospfv3::link_state_update()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_update(|u| *u = lsu);

        let bytes = (Ipv6::new().src(src).dst(dst) / ospfv3)
            .compile()
            .expect("Ipv6 / Ospfv3 LSU compiles");

        // The OSPFv3 LSU body bytes follow the 16-octet common header verbatim.
        let body_start = bytes.as_bytes().len() - body.len();
        assert_eq!(&bytes.as_bytes()[body_start..], body.as_slice());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("the default registry decodes the OSPFv3 LSU over IPv6");
        let layer = decoded
            .layer::<Ospfv3>()
            .expect("the decoded packet exposes a typed Ospfv3 layer");
        assert_eq!(layer.packet_type_value(), OSPFV3_TYPE_LINK_STATE_UPDATE);

        // The decode path preserves the body verbatim after the 16-octet header.
        let ospfv3_start = bytes.as_bytes().len() - (OSPFV3_HEADER_LEN + body.len());
        assert_eq!(
            &bytes.as_bytes()[ospfv3_start + OSPFV3_HEADER_LEN..],
            body.as_slice()
        );

        // The decoded packet re-compiles byte-for-byte.
        let recompiled = decoded
            .compile()
            .expect("the decoded OSPFv3 LSU re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }
}
