//! OSPFv3 Database Description, Link State Request, and Link State
//! Acknowledgment packet bodies (RFC 5340 §A.3.3 / §A.3.4 / §A.3.6).
//!
//! These three bodies follow the 16-octet OSPFv3 common header (RFC 5340
//! §A.3.1) and mirror their OSPFv2 counterparts (RFC 2328 §A.3.3 / §A.3.4 /
//! §A.3.6) with the OSPFv3 wire differences:
//!
//! - **Database Description** ([`Ospfv3DatabaseDescription`]): the fixed prefix
//!   is 12 octets — Reserved(1), Options(3, a 24-bit field), Interface MTU(2),
//!   Reserved(1), flags(1) carrying the I/M/MS bits, DD sequence number(4) —
//!   followed by a list of bare 20-octet [`Ospfv3LsaHeader`] records.
//! - **Link State Request** ([`Ospfv3LinkStateRequest`]): a concatenation of
//!   12-octet entries — Reserved(2), LS type(2, a full 16-bit field), Link State
//!   ID(4), Advertising Router(4). The LS type is 2 octets in OSPFv3, distinct
//!   from the 4-octet LS type in the OSPFv2 request entry (RFC 2328 §A.3.4).
//! - **Link State Acknowledgment** ([`Ospfv3LinkStateAck`]): a concatenation of
//!   bare 20-octet [`Ospfv3LsaHeader`] records, with no fixed prefix.
//!
//! Like the OSPFv3 Hello body, each lives inside the
//! [`Ospfv3`](crate::protocols::ospf::Ospfv3) layer as an
//! [`Ospfv3Body`](crate::protocols::ospf::Ospfv3Body) variant; its `Field<T>`
//! members let `compile()` honor any value the caller pinned while filling
//! sensible RFC defaults for the rest.

use core::net::Ipv4Addr;

use crate::field::Field;

use super::constants::{OSPFV3_DD_FLAG_I, OSPFV3_DD_FLAG_M, OSPFV3_DD_FLAG_MS};
use super::lsa::{encode_ospfv3_lsa_headers, Ospfv3LsaHeader, OSPFV3_LSA_HEADER_LEN};

/// The fixed (pre-LSA-header-list) length of the OSPFv3 Database Description
/// body, in octets: Reserved(1) + Options(3) + Interface MTU(2) + Reserved(1) +
/// flags(1) + DD sequence number(4). RFC 5340 §A.3.3.
const OSPFV3_DD_FIXED_LEN: usize = 12;

/// Mask selecting the low 24 bits of the OSPFv3 Options field (RFC 5340 §A.2):
/// the field is encoded as three octets on the wire.
const OSPFV3_OPTIONS_MASK: u32 = 0x00ff_ffff;

/// The on-wire length of a single OSPFv3 Link State Request entry, in octets:
/// Reserved(2) + LS type(2) + Link State ID(4) + Advertising Router(4).
/// RFC 5340 §A.3.4.
const OSPFV3_LSR_ENTRY_LEN: usize = 12;

/// OSPFv3 Database Description packet body (RFC 5340 §A.3.3).
///
/// Carries a 1-octet Reserved field, the 24-bit Options, the Interface MTU, a
/// second 1-octet Reserved field, the I/M/MS flag bits, the DD sequence number,
/// and the list of LSA headers describing the originator's link-state database:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       0       |                  Options                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Interface MTU          |      0        |0|0|0|0|0|I|M|MS
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     DD sequence number                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          An LSA Header                        ...
/// ```
///
/// Each scalar field is a [`Field`] so `compile()` fills the ones the caller
/// left unset (sensible RFC defaults) while preserving anything set explicitly,
/// including wrong-on-purpose values.
#[derive(Debug, Clone)]
pub struct Ospfv3DatabaseDescription {
    /// First Reserved octet (RFC 5340 §A.3.3); defaults to 0.
    reserved1: Field<u8>,
    /// Optional capabilities (RFC 5340 §A.2), 24-bit; defaults to 0. Only the
    /// low 24 bits are emitted on the wire.
    options: Field<u32>,
    /// Interface MTU, in octets (RFC 5340 §A.3.3); defaults to 0.
    interface_mtu: Field<u16>,
    /// Second Reserved octet (RFC 5340 §A.3.3); defaults to 0.
    reserved2: Field<u8>,
    /// Database Description flags octet carrying the I/M/MS bits in its low three
    /// bits (RFC 5340 §A.3.3); defaults to 0.
    flags: Field<u8>,
    /// DD sequence number (RFC 5340 §A.3.3); defaults to 0.
    dd_sequence_number: Field<u32>,
    /// The list of bare 20-octet OSPFv3 LSA headers (RFC 5340 §A.4.2) describing
    /// the originator's link-state database.
    lsa_headers: Vec<Ospfv3LsaHeader>,
}

impl Ospfv3DatabaseDescription {
    /// Build an OSPFv3 Database Description body with RFC defaults: both Reserved
    /// octets, Options, Interface MTU, flags, and DD sequence number all 0, and
    /// an empty LSA-header list.
    pub fn new() -> Self {
        Self {
            reserved1: Field::defaulted(0),
            options: Field::defaulted(0),
            interface_mtu: Field::defaulted(0),
            reserved2: Field::defaulted(0),
            flags: Field::defaulted(0),
            dd_sequence_number: Field::defaulted(0),
            lsa_headers: Vec::new(),
        }
    }

    /// Set the first Reserved octet (RFC 5340 §A.3.3). Normally 0; settable so a
    /// malformed-on-purpose packet can carry a non-zero value.
    pub fn reserved1(mut self, reserved1: u8) -> Self {
        self.reserved1.set_user(reserved1);
        self
    }

    /// Set the Options field (RFC 5340 §A.2 capability bits, 24-bit). Only the
    /// low 24 bits are emitted on the wire.
    pub fn options(mut self, options: u32) -> Self {
        self.options.set_user(options);
        self
    }

    /// Set the Interface MTU field, in octets.
    pub fn interface_mtu(mut self, interface_mtu: u16) -> Self {
        self.interface_mtu.set_user(interface_mtu);
        self
    }

    /// Set the second Reserved octet (RFC 5340 §A.3.3). Normally 0; settable so a
    /// malformed-on-purpose packet can carry a non-zero value.
    pub fn reserved2(mut self, reserved2: u8) -> Self {
        self.reserved2.set_user(reserved2);
        self
    }

    /// Set the whole flags octet (RFC 5340 §A.3.3).
    ///
    /// The I/M/MS bits live in the low three bits; use [`init`](Self::init),
    /// [`more`](Self::more), and [`master`](Self::master) to toggle individual
    /// bits while leaving the rest untouched.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set the DD sequence number field.
    pub fn dd_sequence_number(mut self, dd_sequence_number: u32) -> Self {
        self.dd_sequence_number.set_user(dd_sequence_number);
        self
    }

    /// Toggle the I (Init) flag bit (RFC 5340 §A.3.3), leaving the other flag
    /// bits untouched.
    pub fn init(mut self, init: bool) -> Self {
        self.set_flag_bit(OSPFV3_DD_FLAG_I, init);
        self
    }

    /// Toggle the M (More) flag bit (RFC 5340 §A.3.3), leaving the other flag
    /// bits untouched.
    pub fn more(mut self, more: bool) -> Self {
        self.set_flag_bit(OSPFV3_DD_FLAG_M, more);
        self
    }

    /// Toggle the MS (Master/Slave) flag bit (RFC 5340 §A.3.3), leaving the other
    /// flag bits untouched.
    pub fn master(mut self, master: bool) -> Self {
        self.set_flag_bit(OSPFV3_DD_FLAG_MS, master);
        self
    }

    /// Set or clear a single flag bit in the flags octet, marking the field as
    /// caller-supplied.
    fn set_flag_bit(&mut self, bit: u8, set: bool) {
        let mut flags = self.flags_value();
        if set {
            flags |= bit;
        } else {
            flags &= !bit;
        }
        self.flags.set_user(flags);
    }

    /// Append a single LSA header to the Database Description's header list.
    pub fn lsa_header(mut self, header: Ospfv3LsaHeader) -> Self {
        self.lsa_headers.push(header);
        self
    }

    /// Append several LSA headers to the Database Description's header list.
    pub fn lsa_headers<I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = Ospfv3LsaHeader>,
    {
        self.lsa_headers.extend(headers);
        self
    }

    /// The effective first Reserved octet (the caller value, else 0).
    pub fn reserved1_value(&self) -> u8 {
        self.reserved1.value().copied().unwrap_or(0)
    }

    /// The effective Options field, masked to the low 24 bits emitted on the wire
    /// (the caller value, else 0).
    pub fn options_value(&self) -> u32 {
        self.options.value().copied().unwrap_or(0) & OSPFV3_OPTIONS_MASK
    }

    /// The effective Interface MTU (the caller value, else 0).
    pub fn interface_mtu_value(&self) -> u16 {
        self.interface_mtu.value().copied().unwrap_or(0)
    }

    /// The effective second Reserved octet (the caller value, else 0).
    pub fn reserved2_value(&self) -> u8 {
        self.reserved2.value().copied().unwrap_or(0)
    }

    /// The effective flags octet (the caller value, else 0).
    pub fn flags_value(&self) -> u8 {
        self.flags.value().copied().unwrap_or(0)
    }

    /// Whether the I (Init) flag bit is set (RFC 5340 §A.3.3).
    pub fn is_init(&self) -> bool {
        self.flags_value() & OSPFV3_DD_FLAG_I != 0
    }

    /// Whether the M (More) flag bit is set (RFC 5340 §A.3.3).
    pub fn is_more(&self) -> bool {
        self.flags_value() & OSPFV3_DD_FLAG_M != 0
    }

    /// Whether the MS (Master/Slave) flag bit is set (RFC 5340 §A.3.3).
    pub fn is_master(&self) -> bool {
        self.flags_value() & OSPFV3_DD_FLAG_MS != 0
    }

    /// Render the set Database Description flag bits (RFC 5340 §A.3.3) as their
    /// `I`, `M`, and `MS` labels joined by `|`, in I/M/MS order, for `summary()`
    /// / `inspection_fields()`. Returns an empty string when no recognized flag
    /// bit is set.
    pub fn dd_flags_summary(&self) -> String {
        let flags = self.flags_value();
        let mut labels: Vec<&str> = Vec::new();
        if flags & OSPFV3_DD_FLAG_I != 0 {
            labels.push("I");
        }
        if flags & OSPFV3_DD_FLAG_M != 0 {
            labels.push("M");
        }
        if flags & OSPFV3_DD_FLAG_MS != 0 {
            labels.push("MS");
        }
        labels.join("|")
    }

    /// The effective DD sequence number (the caller value, else 0).
    pub fn dd_sequence_number_value(&self) -> u32 {
        self.dd_sequence_number.value().copied().unwrap_or(0)
    }

    /// The LSA headers describing the originator's link-state database.
    pub fn lsa_headers_value(&self) -> &[Ospfv3LsaHeader] {
        &self.lsa_headers
    }

    /// The on-wire length of this Database Description body, in octets: the fixed
    /// 12 octets plus 20 octets per LSA header.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPFV3_DD_FIXED_LEN + self.lsa_headers.len() * OSPFV3_LSA_HEADER_LEN
    }

    /// Append the RFC 5340 §A.3.3 OSPFv3 Database Description body to `out`: the
    /// fixed 12 octets (with the 24-bit Options packed into three octets after
    /// the first Reserved octet), then each bare 20-octet LSA header.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        // First Reserved octet, then the 24-bit Options as three big-endian
        // octets.
        out.push(self.reserved1_value());
        let options = self.options_value();
        out.push(((options >> 16) & 0xff) as u8);
        out.push(((options >> 8) & 0xff) as u8);
        out.push((options & 0xff) as u8);
        // Interface MTU(2), second Reserved octet(1), flags(1), DD sequence
        // number(4).
        out.extend_from_slice(&self.interface_mtu_value().to_be_bytes());
        out.push(self.reserved2_value());
        out.push(self.flags_value());
        out.extend_from_slice(&self.dd_sequence_number_value().to_be_bytes());
        // The list of bare 20-octet LSA headers.
        encode_ospfv3_lsa_headers(&self.lsa_headers, out);
    }
}

impl Default for Ospfv3DatabaseDescription {
    fn default() -> Self {
        Self::new()
    }
}

/// A single OSPFv3 Link State Request entry (RFC 5340 §A.3.4).
///
/// Identifies one LSA the originator wants from its neighbor by the triple that
/// keys the LSA in the link-state database, preceded by a 2-octet Reserved
/// field: the 2-octet LS type, the Link State ID, and the Advertising Router.
/// Unlike the OSPFv2 request entry (RFC 2328 §A.3.4), whose LS type is a full
/// 32-bit field, the OSPFv3 LS type is a 16-bit field carried after the 2-octet
/// Reserved field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ospfv3LinkStateRequestEntry {
    /// The 16-bit LS type of the requested LSA (RFC 5340 §A.3.4 / §A.4.2.1).
    ls_type: u16,
    /// The Link State ID of the requested LSA.
    link_state_id: Ipv4Addr,
    /// The Advertising Router of the requested LSA.
    advertising_router: Ipv4Addr,
}

impl Ospfv3LinkStateRequestEntry {
    /// Build an OSPFv3 Link State Request entry from its three identifying
    /// fields. The 2-octet Reserved field is emitted as zero.
    pub fn new(
        ls_type: u16,
        link_state_id: impl Into<Ipv4Addr>,
        advertising_router: impl Into<Ipv4Addr>,
    ) -> Self {
        Self {
            ls_type,
            link_state_id: link_state_id.into(),
            advertising_router: advertising_router.into(),
        }
    }

    /// The 16-bit LS type of the requested LSA.
    pub fn ls_type_value(&self) -> u16 {
        self.ls_type
    }

    /// The Link State ID of the requested LSA.
    pub fn link_state_id_value(&self) -> Ipv4Addr {
        self.link_state_id
    }

    /// The Advertising Router of the requested LSA.
    pub fn advertising_router_value(&self) -> Ipv4Addr {
        self.advertising_router
    }

    /// Append this entry as its 12 big-endian octets — Reserved(2)=0, LS type(2),
    /// Link State ID(4), Advertising Router(4) — to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        // 2-octet Reserved field, emitted as zero (RFC 5340 §A.3.4).
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&self.ls_type.to_be_bytes());
        out.extend_from_slice(&self.link_state_id.octets());
        out.extend_from_slice(&self.advertising_router.octets());
    }
}

/// OSPFv3 Link State Request packet body (RFC 5340 §A.3.4).
///
/// Carries the list of [`Ospfv3LinkStateRequestEntry`] entries naming the LSAs
/// the originator needs from its neighbor. The body is just the concatenation of
/// these 12-octet entries; an empty list is legal.
#[derive(Debug, Clone)]
pub struct Ospfv3LinkStateRequest {
    /// The list of requested LSAs, in order.
    entries: Vec<Ospfv3LinkStateRequestEntry>,
}

impl Ospfv3LinkStateRequest {
    /// Build an OSPFv3 Link State Request body with an empty request list.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a single request entry to the request list.
    pub fn request(mut self, entry: Ospfv3LinkStateRequestEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Append several request entries to the request list.
    pub fn requests<I>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = Ospfv3LinkStateRequestEntry>,
    {
        self.entries.extend(entries);
        self
    }

    /// The requested-LSA entries, in order.
    pub fn entries_value(&self) -> &[Ospfv3LinkStateRequestEntry] {
        &self.entries
    }

    /// The on-wire length of this Link State Request body, in octets: 12 octets
    /// per request entry.
    pub(crate) fn encoded_len(&self) -> usize {
        self.entries.len() * OSPFV3_LSR_ENTRY_LEN
    }

    /// Append the RFC 5340 §A.3.4 OSPFv3 Link State Request body to `out`: each
    /// entry as its 12 big-endian octets, in order.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        for entry in &self.entries {
            entry.encode(out);
        }
    }
}

impl Default for Ospfv3LinkStateRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// OSPFv3 Link State Acknowledgment packet body (RFC 5340 §A.3.6).
///
/// Carries the list of bare 20-octet OSPFv3 LSA headers (RFC 5340 §A.4.2)
/// acknowledging the LSAs the originator just received. The body is just the
/// concatenation of these headers; an empty list is legal.
#[derive(Debug, Clone)]
pub struct Ospfv3LinkStateAck {
    /// The list of bare 20-octet OSPFv3 LSA headers (RFC 5340 §A.4.2) being
    /// acknowledged.
    lsa_headers: Vec<Ospfv3LsaHeader>,
}

impl Ospfv3LinkStateAck {
    /// Build an OSPFv3 Link State Acknowledgment body with an empty LSA-header
    /// list.
    pub fn new() -> Self {
        Self {
            lsa_headers: Vec::new(),
        }
    }

    /// Append a single LSA header to the acknowledgment's header list.
    pub fn lsa_header(mut self, header: Ospfv3LsaHeader) -> Self {
        self.lsa_headers.push(header);
        self
    }

    /// Append several LSA headers to the acknowledgment's header list.
    pub fn lsa_headers<I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = Ospfv3LsaHeader>,
    {
        self.lsa_headers.extend(headers);
        self
    }

    /// The LSA headers being acknowledged, in order.
    pub fn lsa_headers_value(&self) -> &[Ospfv3LsaHeader] {
        &self.lsa_headers
    }

    /// The on-wire length of this Link State Acknowledgment body, in octets: 20
    /// octets per LSA header.
    pub(crate) fn encoded_len(&self) -> usize {
        self.lsa_headers.len() * OSPFV3_LSA_HEADER_LEN
    }

    /// Append the RFC 5340 §A.3.6 OSPFv3 Link State Acknowledgment body to `out`:
    /// each bare 20-octet LSA header, in order.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        encode_ospfv3_lsa_headers(&self.lsa_headers, out);
    }
}

impl Default for Ospfv3LinkStateAck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::lsa::decode_ospfv3_lsa_headers;
    use super::*;
    use crate::packet::{NetworkLayer, Packet};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::ospf::{
        Ospfv3, OSPFV3_HEADER_LEN, OSPFV3_TYPE_DATABASE_DESCRIPTION, OSPFV3_TYPE_LINK_STATE_ACK,
        OSPFV3_TYPE_LINK_STATE_REQUEST,
    };
    use core::net::Ipv6Addr;

    /// Helper: compile an `Ipv6 / Ospfv3` packet, decode it through the default
    /// registry, assert the OSPFv3 type code, and assert the OSPFv3 body bytes
    /// (after the 16-octet common header) equal `expected_body`, then assert the
    /// decoded packet re-compiles byte-for-byte. Returns the compiled bytes.
    fn round_trip_v3_body(ospfv3: Ospfv3, type_code: u8, expected_body: &[u8]) -> Vec<u8> {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let bytes = (Ipv6::new().src(src).dst(dst) / ospfv3)
            .compile()
            .expect("Ipv6 / Ospfv3 body compiles");

        // The OSPFv3 body bytes follow the 16-octet common header verbatim.
        let body_start = bytes.as_bytes().len() - expected_body.len();
        assert_eq!(&bytes.as_bytes()[body_start..], expected_body);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("the default registry decodes the OSPFv3 body over IPv6");
        let layer = decoded
            .layer::<Ospfv3>()
            .expect("the decoded packet exposes a typed Ospfv3 layer");
        assert_eq!(layer.packet_type_value(), type_code);
        // The Unknown-body decode path preserves the body verbatim after the
        // 16-octet common header.
        let ospfv3_start = bytes.as_bytes().len() - (OSPFV3_HEADER_LEN + expected_body.len());
        assert_eq!(
            &bytes.as_bytes()[ospfv3_start + OSPFV3_HEADER_LEN..],
            expected_body
        );

        let recompiled = decoded.compile().expect("the decoded OSPFv3 body re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());

        bytes.as_bytes().to_vec()
    }

    /// An OSPFv3 Database Description body built with two LSA headers and the
    /// M+MS flags encodes to the exact RFC 5340 §A.3.3 layout — the 12-octet
    /// fixed prefix with the 24-bit Options packed into three octets after the
    /// first Reserved octet — and round-trips byte-for-byte over IPv6. Uses
    /// `2001:db8::/32` documentation addresses.
    #[test]
    fn ospfv3_database_description_body_compiles_and_round_trips() {
        let dd = Ospfv3DatabaseDescription::new()
            .interface_mtu(1500)
            // 0x000013 exercises the 24-bit Options packing; the high octet of the
            // u32 (0xff) must be masked off on the wire.
            .options(0x00ff_0013)
            .dd_sequence_number(0x0000_1a2b)
            .more(true)
            .master(true)
            .lsa_header(
                Ospfv3LsaHeader::new()
                    .ls_type(0x2001)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                    .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                    .ls_sequence_number(0x8000_0001),
            )
            .lsa_header(
                Ospfv3LsaHeader::new()
                    .ls_type(0x2002)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                    .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                    .ls_sequence_number(0x8000_0002),
            );

        // The M+MS flags occupy the low three bits of the flags octet.
        assert_eq!(dd.flags_value(), OSPFV3_DD_FLAG_M | OSPFV3_DD_FLAG_MS);
        assert!(dd.is_more());
        assert!(dd.is_master());
        assert!(!dd.is_init());
        // The Options accessor masks to the low 24 bits emitted on the wire.
        assert_eq!(dd.options_value(), 0x00ff_0013);

        let mut body = Vec::new();
        dd.encode(&mut body);
        assert_eq!(
            dd.encoded_len(),
            OSPFV3_DD_FIXED_LEN + 2 * OSPFV3_LSA_HEADER_LEN
        );
        assert_eq!(body.len(), dd.encoded_len());

        // Hand-checked RFC 5340 §A.3.3 fixed portion (12 octets).
        assert_eq!(body[0], 0x00); // first Reserved octet
        assert_eq!(&body[1..4], &[0xff, 0x00, 0x13]); // Options (24-bit)
        assert_eq!(&body[4..6], &1500u16.to_be_bytes()); // Interface MTU
        assert_eq!(body[6], 0x00); // second Reserved octet
        assert_eq!(body[7], OSPFV3_DD_FLAG_M | OSPFV3_DD_FLAG_MS); // flags (M+MS)
        assert_eq!(&body[8..12], &0x0000_1a2bu32.to_be_bytes()); // DD sequence number

        // The two 20-octet LSA headers follow the fixed prefix and match
        // standalone-encoded headers.
        let mut expected_headers = Vec::new();
        encode_ospfv3_lsa_headers(dd.lsa_headers_value(), &mut expected_headers);
        assert_eq!(&body[OSPFV3_DD_FIXED_LEN..], expected_headers.as_slice());
        assert_eq!(expected_headers.len(), 2 * OSPFV3_LSA_HEADER_LEN);

        let ospfv3 = Ospfv3::database_description()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_database_description(|d| *d = dd);
        round_trip_v3_body(ospfv3, OSPFV3_TYPE_DATABASE_DESCRIPTION, &body);
    }

    /// An OSPFv3 Link State Request body built with two entries encodes to the
    /// exact RFC 5340 §A.3.4 layout — two 12-octet entries each with the 2-octet
    /// LS type after a 2-octet Reserved field — and round-trips byte-for-byte
    /// over IPv6.
    #[test]
    fn ospfv3_link_state_request_body_compiles_and_round_trips() {
        let lsr = Ospfv3LinkStateRequest::new()
            .request(Ospfv3LinkStateRequestEntry::new(
                0x2001,
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 1),
            ))
            .request(Ospfv3LinkStateRequestEntry::new(
                0x2002,
                Ipv4Addr::new(192, 0, 2, 2),
                Ipv4Addr::new(198, 51, 100, 7),
            ));

        let mut body = Vec::new();
        lsr.encode(&mut body);
        assert_eq!(lsr.encoded_len(), 2 * OSPFV3_LSR_ENTRY_LEN);
        assert_eq!(body.len(), lsr.encoded_len());
        assert_eq!(body.len(), 24);

        // Hand-checked RFC 5340 §A.3.4 entries: Reserved(2)=0, LS type(2), Link
        // State ID(4), Advertising Router(4), big-endian. The LS type is two
        // octets, distinct from the OSPFv2 4-octet LS type.
        assert_eq!(&body[0..2], &0u16.to_be_bytes()); // Reserved
        assert_eq!(&body[2..4], &0x2001u16.to_be_bytes()); // LS type (2-octet)
        assert_eq!(&body[4..8], &Ipv4Addr::new(192, 0, 2, 1).octets());
        assert_eq!(&body[8..12], &Ipv4Addr::new(192, 0, 2, 1).octets());
        assert_eq!(&body[12..14], &0u16.to_be_bytes()); // Reserved
        assert_eq!(&body[14..16], &0x2002u16.to_be_bytes()); // LS type (2-octet)
        assert_eq!(&body[16..20], &Ipv4Addr::new(192, 0, 2, 2).octets());
        assert_eq!(&body[20..24], &Ipv4Addr::new(198, 51, 100, 7).octets());

        let ospfv3 = Ospfv3::link_state_request()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_request(|r| *r = lsr);
        round_trip_v3_body(ospfv3, OSPFV3_TYPE_LINK_STATE_REQUEST, &body);
    }

    /// An OSPFv3 Link State Acknowledgment body built with two LSA headers
    /// encodes to the exact RFC 5340 §A.3.6 layout (two bare 20-octet headers, no
    /// fixed prefix) and round-trips byte-for-byte over IPv6.
    #[test]
    fn ospfv3_link_state_ack_body_compiles_and_round_trips() {
        let ack = Ospfv3LinkStateAck::new()
            .lsa_header(
                Ospfv3LsaHeader::new()
                    .ls_type(0x2001)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                    .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                    .ls_sequence_number(0x8000_0001),
            )
            .lsa_header(
                Ospfv3LsaHeader::new()
                    .ls_type(0x2002)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                    .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                    .ls_sequence_number(0x8000_0002),
            );

        let mut body = Vec::new();
        ack.encode(&mut body);
        assert_eq!(ack.encoded_len(), 2 * OSPFV3_LSA_HEADER_LEN);
        assert_eq!(body.len(), ack.encoded_len());
        assert_eq!(body.len(), 40);

        // The two bare 20-octet LSA headers match standalone-encoded headers,
        // with no fixed prefix.
        let mut expected_headers = Vec::new();
        encode_ospfv3_lsa_headers(ack.lsa_headers_value(), &mut expected_headers);
        assert_eq!(body, expected_headers);
        assert_eq!(expected_headers.len(), 2 * OSPFV3_LSA_HEADER_LEN);

        let ospfv3 = Ospfv3::link_state_ack()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_ack(|a| *a = ack);
        round_trip_v3_body(ospfv3, OSPFV3_TYPE_LINK_STATE_ACK, &body);
    }

    /// An empty OSPFv3 Database Description (no LSA headers), an empty Link State
    /// Request, and an empty Link State Acknowledgment all build and round-trip:
    /// the DD encodes its 12-octet fixed prefix while the LSR and LSAck encode
    /// empty bodies.
    #[test]
    fn ospfv3_empty_bodies_build_and_round_trip() {
        let mut dd_body = Vec::new();
        Ospfv3DatabaseDescription::new().encode(&mut dd_body);
        assert_eq!(dd_body.len(), OSPFV3_DD_FIXED_LEN);

        let mut lsr_body = Vec::new();
        Ospfv3LinkStateRequest::new().encode(&mut lsr_body);
        assert!(lsr_body.is_empty());

        let mut ack_body = Vec::new();
        Ospfv3LinkStateAck::new().encode(&mut ack_body);
        assert!(ack_body.is_empty());

        round_trip_v3_body(
            Ospfv3::database_description()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0]),
            OSPFV3_TYPE_DATABASE_DESCRIPTION,
            &dd_body,
        );
        round_trip_v3_body(
            Ospfv3::link_state_request()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0]),
            OSPFV3_TYPE_LINK_STATE_REQUEST,
            &lsr_body,
        );
        round_trip_v3_body(
            Ospfv3::link_state_ack()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0]),
            OSPFV3_TYPE_LINK_STATE_ACK,
            &ack_body,
        );
    }

    /// The shared `decode_ospfv3_lsa_headers` parser round-trips a Database
    /// Description's LSA-header list: re-decoding the encoded list yields the same
    /// header fields.
    #[test]
    fn ospfv3_dd_lsa_header_list_parses_back() {
        let dd = Ospfv3DatabaseDescription::new().lsa_header(
            Ospfv3LsaHeader::new()
                .ls_type(0x2001)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
        );
        let mut body = Vec::new();
        dd.encode(&mut body);

        // The LSA-header list sits after the 12-octet fixed prefix.
        let headers = decode_ospfv3_lsa_headers(&body[OSPFV3_DD_FIXED_LEN..])
            .expect("the DD LSA-header list decodes");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].ls_type_value(), 0x2001);
        assert_eq!(headers[0].link_state_id_value(), Ipv4Addr::new(192, 0, 2, 1));
    }
}
