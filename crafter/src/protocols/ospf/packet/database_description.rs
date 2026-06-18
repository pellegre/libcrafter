//! OSPFv2 Database Description packet body (RFC 2328 §A.3.3).
//!
//! The Database Description body follows the 24-octet common header and carries
//! the parameters two routers exchange while synchronizing their link-state
//! databases:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         Interface MTU         |    Options    |0|0|0|0|0|I|M|MS
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     DD sequence number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +-                                                             -+
//! |                             An LSA Header                      |
//! +-                                                             -+
//! |                                                               |
//! +-                                                             -+
//! |                                                               |
//! +-                                                             -+
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                              ...                              ...
//! ```
//!
//! The fixed portion is 8 octets (Interface MTU(2), Options(1), flags(1), DD
//! sequence number(4)), followed by a list of bare 20-octet LSA headers
//! (RFC 2328 §A.4.1). Like the other bodies, [`OspfDatabaseDescription`] lives
//! inside the [`Ospfv2`](crate::protocols::ospf::Ospfv2) layer as an
//! [`OspfBody::DatabaseDescription`](crate::protocols::ospf::OspfBody::DatabaseDescription)
//! variant; its `Field<T>` members let `compile()` honor any value the caller
//! pinned while filling sensible RFC defaults for the rest.

use crate::field::Field;
use crate::protocols::ospf::lsa::{encode_lsa_headers, OspfLsaHeader};

/// The fixed (pre-LSA-header-list) length of the Database Description body, in
/// octets: Interface MTU(2) + Options(1) + flags(1) + DD sequence number(4).
const OSPF_DD_FIXED_LEN: usize = 8;

/// Master/Slave bit (MS) in the Database Description flags octet (RFC 2328
/// §A.3.3): set when the router is the master.
pub const OSPF_DD_FLAG_MS: u8 = 0x01;
/// More bit (M) in the Database Description flags octet (RFC 2328 §A.3.3): set
/// when more Database Description packets follow.
pub const OSPF_DD_FLAG_M: u8 = 0x02;
/// Init bit (I) in the Database Description flags octet (RFC 2328 §A.3.3): set
/// on the first Database Description packet of an exchange.
pub const OSPF_DD_FLAG_I: u8 = 0x04;

/// OSPFv2 Database Description packet body (RFC 2328 §A.3.3).
///
/// Carries the Interface MTU, Options, the I/M/MS flag bits, the DD sequence
/// number, and the list of LSA headers describing the originator's link-state
/// database. Each scalar field is a [`Field`] so `compile()` fills the ones the
/// caller left unset (sensible RFC defaults) while preserving anything set
/// explicitly, including wrong-on-purpose values.
#[derive(Debug, Clone)]
pub struct OspfDatabaseDescription {
    /// Interface MTU, in octets (RFC 2328 §A.3.3); defaults to 0.
    interface_mtu: Field<u16>,
    /// Optional capabilities (RFC 2328 §A.2); defaults to 0.
    options: Field<u8>,
    /// Database Description flags octet carrying the I/M/MS bits in its low
    /// three bits (RFC 2328 §A.3.3); defaults to 0.
    flags: Field<u8>,
    /// DD sequence number (RFC 2328 §A.3.3); defaults to 0.
    dd_sequence_number: Field<u32>,
    /// The list of bare 20-octet LSA headers (RFC 2328 §A.4.1) describing the
    /// originator's link-state database.
    lsa_headers: Vec<OspfLsaHeader>,
}

impl OspfDatabaseDescription {
    /// Build a Database Description body with RFC defaults: Interface MTU,
    /// Options, flags, and DD sequence number all 0, and an empty LSA-header
    /// list.
    pub fn new() -> Self {
        Self {
            interface_mtu: Field::defaulted(0),
            options: Field::defaulted(0),
            flags: Field::defaulted(0),
            dd_sequence_number: Field::defaulted(0),
            lsa_headers: Vec::new(),
        }
    }

    /// Construct a Database Description body from decoded wire fields, marking
    /// every scalar field as caller-supplied so re-compilation preserves the
    /// decoded values byte-for-byte.
    #[allow(dead_code)]
    pub(crate) fn from_decoded_parts(
        interface_mtu: u16,
        options: u8,
        flags: u8,
        dd_sequence_number: u32,
        lsa_headers: Vec<OspfLsaHeader>,
    ) -> Self {
        Self {
            interface_mtu: Field::user(interface_mtu),
            options: Field::user(options),
            flags: Field::user(flags),
            dd_sequence_number: Field::user(dd_sequence_number),
            lsa_headers,
        }
    }

    /// Set the Interface MTU field, in octets.
    pub fn interface_mtu(mut self, interface_mtu: u16) -> Self {
        self.interface_mtu.set_user(interface_mtu);
        self
    }

    /// Set the Options field (RFC 2328 §A.2 capability bits).
    pub fn options(mut self, options: u8) -> Self {
        self.options.set_user(options);
        self
    }

    /// Set the whole flags octet (RFC 2328 §A.3.3).
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

    /// Toggle the I (Init) flag bit (RFC 2328 §A.3.3), leaving the other flag
    /// bits untouched.
    pub fn init(mut self, init: bool) -> Self {
        self.set_flag_bit(OSPF_DD_FLAG_I, init);
        self
    }

    /// Toggle the M (More) flag bit (RFC 2328 §A.3.3), leaving the other flag
    /// bits untouched.
    pub fn more(mut self, more: bool) -> Self {
        self.set_flag_bit(OSPF_DD_FLAG_M, more);
        self
    }

    /// Toggle the MS (Master/Slave) flag bit (RFC 2328 §A.3.3), leaving the
    /// other flag bits untouched.
    pub fn master(mut self, master: bool) -> Self {
        self.set_flag_bit(OSPF_DD_FLAG_MS, master);
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
    pub fn lsa_header(mut self, header: OspfLsaHeader) -> Self {
        self.lsa_headers.push(header);
        self
    }

    /// Append several LSA headers to the Database Description's header list.
    pub fn lsa_headers<I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = OspfLsaHeader>,
    {
        self.lsa_headers.extend(headers);
        self
    }

    /// The effective Interface MTU (the caller value, else 0).
    pub fn interface_mtu_value(&self) -> u16 {
        self.interface_mtu.value().copied().unwrap_or(0)
    }

    /// The effective Options field (the caller value, else 0).
    pub fn options_value(&self) -> u8 {
        self.options.value().copied().unwrap_or(0)
    }

    /// The effective flags octet (the caller value, else 0).
    pub fn flags_value(&self) -> u8 {
        self.flags.value().copied().unwrap_or(0)
    }

    /// Whether the I (Init) flag bit is set.
    pub fn init_value(&self) -> bool {
        self.flags_value() & OSPF_DD_FLAG_I != 0
    }

    /// Whether the M (More) flag bit is set.
    pub fn more_value(&self) -> bool {
        self.flags_value() & OSPF_DD_FLAG_M != 0
    }

    /// Whether the MS (Master/Slave) flag bit is set.
    pub fn master_value(&self) -> bool {
        self.flags_value() & OSPF_DD_FLAG_MS != 0
    }

    /// The effective DD sequence number (the caller value, else 0).
    pub fn dd_sequence_number_value(&self) -> u32 {
        self.dd_sequence_number.value().copied().unwrap_or(0)
    }

    /// The LSA headers describing the originator's link-state database.
    pub fn lsa_headers_value(&self) -> &[OspfLsaHeader] {
        &self.lsa_headers
    }

    /// The on-wire length of this Database Description body, in octets: the fixed
    /// 8 octets plus 20 octets per LSA header.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_DD_FIXED_LEN + self.lsa_headers.len() * crate::protocols::ospf::lsa::OSPF_LSA_HEADER_LEN
    }

    /// Append the RFC 2328 §A.3.3 Database Description body to `out`: the fixed
    /// 8 octets in big-endian, then each bare 20-octet LSA header.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.interface_mtu_value().to_be_bytes());
        out.push(self.options_value());
        out.push(self.flags_value());
        out.extend_from_slice(&self.dd_sequence_number_value().to_be_bytes());
        encode_lsa_headers(&self.lsa_headers, out);
    }
}

impl Default for OspfDatabaseDescription {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv4Addr;

    /// A Database Description body built with two LSA headers and the M+MS flags
    /// compiles to the exact RFC 2328 §A.3.3 layout, and the enclosing OSPF
    /// packet length covers the 24-octet common header plus the DD body.
    #[test]
    fn ospf_database_description_body_compiles_with_two_lsa_headers() {
        use crate::packet::{Layer, Packet};
        use crate::protocols::ospf::lsa::{OspfLsaHeader, OSPF_LSA_NETWORK, OSPF_LSA_ROUTER};
        use crate::protocols::ospf::{Ospfv2, OSPF_HEADER_LEN, OSPF_TYPE_DATABASE_DESCRIPTION};

        let dd = OspfDatabaseDescription::new()
            .interface_mtu(1500)
            .options(0x02)
            .dd_sequence_number(0x0000_1a2b)
            .more(true)
            .master(true)
            .lsa_header(
                OspfLsaHeader::new()
                    .ls_type(OSPF_LSA_ROUTER)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                    .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                    .ls_sequence_number(0x8000_0001),
            )
            .lsa_header(
                OspfLsaHeader::new()
                    .ls_type(OSPF_LSA_NETWORK)
                    .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                    .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                    .ls_sequence_number(0x8000_0002),
            );

        // The M+MS flags occupy the low three bits of the flags octet.
        assert_eq!(dd.flags_value(), OSPF_DD_FLAG_M | OSPF_DD_FLAG_MS);
        assert!(dd.more_value());
        assert!(dd.master_value());
        assert!(!dd.init_value());

        // The body encodes to the fixed 8 octets plus two 20-octet LSA headers.
        let mut body = Vec::new();
        dd.encode(&mut body);
        assert_eq!(
            dd.encoded_len(),
            OSPF_DD_FIXED_LEN + 2 * crate::protocols::ospf::lsa::OSPF_LSA_HEADER_LEN
        );
        assert_eq!(body.len(), dd.encoded_len());

        // Hand-checked RFC 2328 §A.3.3 fixed portion.
        assert_eq!(&body[0..2], &1500u16.to_be_bytes()); // Interface MTU
        assert_eq!(body[2], 0x02); // Options
        assert_eq!(body[3], OSPF_DD_FLAG_M | OSPF_DD_FLAG_MS); // flags (M+MS)
        assert_eq!(&body[4..8], &0x0000_1a2bu32.to_be_bytes()); // DD sequence number

        // The two LSA headers follow the fixed portion, 20 octets each, and
        // match standalone-encoded headers.
        let mut expected_headers = Vec::new();
        encode_lsa_headers(dd.lsa_headers_value(), &mut expected_headers);
        assert_eq!(&body[OSPF_DD_FIXED_LEN..], expected_headers.as_slice());
        assert_eq!(expected_headers.len(), 2 * 20);

        // The DD rides inside an Ospfv2 layer; the compiled packet's Packet
        // Length field (octets 2..4) covers the common header plus the body.
        let ospf = Ospfv2::database_description().with_database_description(|d| {
            *d = dd.clone();
        });
        let bytes = Packet::from_layer(ospf)
            .compile()
            .expect("DatabaseDescription compiles");

        let total = OSPF_HEADER_LEN + body.len();
        assert_eq!(bytes.len(), total);
        assert_eq!(&bytes[2..4], &(total as u16).to_be_bytes());
        // The header Type octet carries the Database Description type code.
        assert_eq!(bytes[1], OSPF_TYPE_DATABASE_DESCRIPTION);
        // The body bytes follow the 24-octet header verbatim.
        assert_eq!(&bytes[OSPF_HEADER_LEN..], body.as_slice());

        // `Layer::encoded_len` agrees with the emitted length.
        let layer = Ospfv2::database_description().with_database_description(|d| *d = dd);
        assert_eq!(layer.encoded_len(), total);
    }
}
