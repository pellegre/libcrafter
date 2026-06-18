//! OSPFv2 link-state advertisement (LSA) support.
//!
//! This block defines the 20-octet [`OspfLsaHeader`] primitive (RFC 2328
//! §A.4.1) shared by the Database Description, Link State Acknowledgment, and
//! Link State Update bodies. The header carries the LS age, Options, LS type,
//! Link State ID, Advertising Router, LS sequence number, LS checksum, and the
//! LSA length; the typed LSA bodies and the shared list parser are added in
//! later steps.
//!
//! Layout (RFC 2328 §A.4.1):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            LS age              |    Options    |    LS type    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Link State ID                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Advertising Router                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     LS sequence number                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         LS checksum           |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The LS checksum is the Fletcher-16 checksum (RFC 905 Annex B) computed over
//! the LSA from the Options octet (offset 2) to the end, with the LS age
//! excluded and the LS checksum field zeroed. Like the OSPF packet bodies,
//! [`OspfLsaHeader`] uses [`Field`] members so `compile()` honors any value the
//! caller pinned while auto-filling the length and checksum.

use core::net::Ipv4Addr;

use crate::checksum::fletcher16_checkbytes;
use crate::field::Field;
use crate::{CrafterError, Result};

// ---------------------------------------------------------------------------
// LSA types (RFC 2328 §A.4.1, RFC 3101 §2.4, RFC 5250 §3)
// ---------------------------------------------------------------------------

/// Router-LSA (type 1). RFC 2328 §A.4.2.
pub const OSPF_LSA_ROUTER: u8 = 1;
/// Network-LSA (type 2). RFC 2328 §A.4.3.
pub const OSPF_LSA_NETWORK: u8 = 2;
/// Summary-LSA for an IP network (type 3). RFC 2328 §A.4.4.
pub const OSPF_LSA_SUMMARY_IP: u8 = 3;
/// Summary-LSA for an AS boundary router (type 4). RFC 2328 §A.4.4.
pub const OSPF_LSA_SUMMARY_ASBR: u8 = 4;
/// AS-external-LSA (type 5). RFC 2328 §A.4.5.
pub const OSPF_LSA_AS_EXTERNAL: u8 = 5;
/// NSSA-LSA (type 7). RFC 3101 §2.4.
pub const OSPF_LSA_NSSA: u8 = 7;
/// Link-local-scope Opaque-LSA (type 9). RFC 5250 §3.
pub const OSPF_LSA_OPAQUE_LINK_LOCAL: u8 = 9;
/// Area-scope Opaque-LSA (type 10). RFC 5250 §3.
pub const OSPF_LSA_OPAQUE_AREA: u8 = 10;
/// AS-scope Opaque-LSA (type 11). RFC 5250 §3.
pub const OSPF_LSA_OPAQUE_AS: u8 = 11;

/// Short human-readable name for an OSPF LS type code (RFC 2328 §A.4.1,
/// RFC 3101 §2.4, RFC 5250 §3), used by `summary()` and `inspection_fields()`.
/// Unrecognized codes map to `"Unknown"`.
pub fn ospf_lsa_type_name(ls_type: u8) -> &'static str {
    match ls_type {
        OSPF_LSA_ROUTER => "Router",
        OSPF_LSA_NETWORK => "Network",
        OSPF_LSA_SUMMARY_IP => "Summary-IP",
        OSPF_LSA_SUMMARY_ASBR => "Summary-ASBR",
        OSPF_LSA_AS_EXTERNAL => "AS-External",
        OSPF_LSA_NSSA => "NSSA",
        OSPF_LSA_OPAQUE_LINK_LOCAL => "Opaque-LinkLocal",
        OSPF_LSA_OPAQUE_AREA => "Opaque-Area",
        OSPF_LSA_OPAQUE_AS => "Opaque-AS",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 2328 §A.4.1)
// ---------------------------------------------------------------------------

/// LSA header length, in octets. RFC 2328 §A.4.1.
pub const OSPF_LSA_HEADER_LEN: usize = 20;

/// Default LS sequence number (the initial sequence number `InitialSequenceNumber`,
/// RFC 2328 §12.1.6).
const OSPF_LSA_INITIAL_SEQUENCE_NUMBER: u32 = 0x8000_0001;

/// Offset of the LS checksum field within the LSA, in octets (RFC 2328 §A.4.1).
const OSPF_LSA_CHECKSUM_OFFSET: usize = 16;

/// Offset where the Fletcher-protected region begins within the LSA, in octets:
/// the Options octet (offset 2), with the LS age (offset 0..2) excluded
/// (RFC 2328 §12.1.7).
const OSPF_LSA_CHECKSUM_START: usize = 2;

/// The 20-octet LSA header (RFC 2328 §A.4.1).
///
/// Shared by every link-state advertisement and by the Database Description and
/// Link State Acknowledgment bodies (which carry bare LSA headers). Each field
/// is a [`Field`] so `compile()` fills the `length` and `ls_checksum` the caller
/// left unset while preserving anything set explicitly, including
/// wrong-on-purpose values.
///
/// The LS checksum is the Fletcher-16 checksum (RFC 905 Annex B) over the LSA
/// from the Options octet to the end (LS age excluded), with the LS checksum
/// field zeroed; the length covers the 20-octet header plus the LSA body.
#[derive(Debug, Clone)]
pub struct OspfLsaHeader {
    /// LS age, in seconds (RFC 2328 §A.4.1); defaults to 0.
    ls_age: Field<u16>,
    /// Optional capabilities (RFC 2328 §A.2); defaults to 0.
    options: Field<u8>,
    /// LS type (RFC 2328 §A.4.1); left unset until a typed body sets it.
    ls_type: Field<u8>,
    /// Link State ID (RFC 2328 §A.4.1); defaults to the unspecified address.
    link_state_id: Field<Ipv4Addr>,
    /// Advertising Router (RFC 2328 §A.4.1); defaults to the unspecified address.
    advertising_router: Field<Ipv4Addr>,
    /// LS sequence number (RFC 2328 §A.4.1); defaults to the initial sequence
    /// number `0x80000001`.
    ls_sequence_number: Field<u32>,
    /// LS checksum, the Fletcher-16 checksum (RFC 2328 §A.4.1); auto-filled.
    ls_checksum: Field<u16>,
    /// LSA length, in octets, including the 20-octet header (RFC 2328 §A.4.1);
    /// auto-filled to cover the header plus the body.
    length: Field<u16>,
}

impl OspfLsaHeader {
    /// Build a new LSA header with RFC defaults: LS age 0, Options 0, the LS
    /// sequence number set to the initial sequence number `0x80000001`, the LS
    /// type, Link State ID, and Advertising Router left unset, and the LS
    /// checksum and length unset so `encode_with_body()` fills them.
    pub fn new() -> Self {
        Self {
            ls_age: Field::defaulted(0),
            options: Field::defaulted(0),
            ls_type: Field::unset(),
            link_state_id: Field::unset(),
            advertising_router: Field::unset(),
            ls_sequence_number: Field::defaulted(OSPF_LSA_INITIAL_SEQUENCE_NUMBER),
            ls_checksum: Field::unset(),
            length: Field::unset(),
        }
    }

    /// Construct an LSA header from decoded wire fields, marking every field as
    /// caller-supplied so re-compilation preserves the decoded values
    /// byte-for-byte.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_decoded_parts(
        ls_age: u16,
        options: u8,
        ls_type: u8,
        link_state_id: Ipv4Addr,
        advertising_router: Ipv4Addr,
        ls_sequence_number: u32,
        ls_checksum: u16,
        length: u16,
    ) -> Self {
        Self {
            ls_age: Field::user(ls_age),
            options: Field::user(options),
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

    /// Set the Options field (RFC 2328 §A.2 capability bits).
    pub fn options(mut self, options: u8) -> Self {
        self.options.set_user(options);
        self
    }

    /// Set the LS type field (e.g. [`OSPF_LSA_ROUTER`]).
    pub fn ls_type(mut self, ls_type: u8) -> Self {
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
        self.advertising_router
            .set_user(advertising_router.into());
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

    /// The effective Options field (the caller value, else 0).
    pub fn options_value(&self) -> u8 {
        self.options.value().copied().unwrap_or(0)
    }

    /// The effective LS type (the caller value, else 0).
    pub fn ls_type_value(&self) -> u8 {
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
            .unwrap_or(OSPF_LSA_INITIAL_SEQUENCE_NUMBER)
    }

    /// The pinned LS checksum, if the caller set it.
    pub fn ls_checksum_value(&self) -> Option<u16> {
        self.ls_checksum.value().copied()
    }

    /// The pinned LSA length, if the caller set it.
    pub fn length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// A one-line summary of the LSA header for `summary()` /
    /// `inspection_fields()`, like
    /// `LSA(type=Router, id=192.0.2.1, adv=192.0.2.1, seq=0x80000001, age=0, len=...)`.
    ///
    /// The LS type renders through [`ospf_lsa_type_name`]; the length shows the
    /// pinned value when the caller set one and `auto` otherwise (the effective
    /// length depends on the LSA body, which the header alone does not hold).
    pub fn summary(&self) -> String {
        let length = match self.length_value() {
            Some(length) => length.to_string(),
            None => "auto".to_string(),
        };
        format!(
            "LSA(type={}, id={}, adv={}, seq=0x{:08x}, age={}, len={})",
            ospf_lsa_type_name(self.ls_type_value()),
            self.link_state_id_value(),
            self.advertising_router_value(),
            self.ls_sequence_number_value(),
            self.ls_age_value(),
            length,
        )
    }

    /// Append the 20-octet LSA header followed by `body` to `out`.
    ///
    /// The `length` field is filled with `20 + body.len()` unless the caller
    /// pinned it, and the LS checksum is filled with the Fletcher-16 checksum
    /// (RFC 905 Annex B) over the LSA from the Options octet to the end (LS age
    /// excluded), with the checksum field zeroed, unless the caller pinned it.
    pub fn encode_with_body(&self, body: &[u8], out: &mut Vec<u8>) {
        let start = out.len();

        // LS age (octets 0..2).
        out.extend_from_slice(&self.ls_age_value().to_be_bytes());
        // Options (octet 2) and LS type (octet 3).
        out.push(self.options_value());
        out.push(self.ls_type_value());
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
            .unwrap_or((OSPF_LSA_HEADER_LEN + body.len()) as u16);
        out.extend_from_slice(&length.to_be_bytes());

        // LSA body follows the 20-octet header.
        out.extend_from_slice(body);

        // Auto-fill the LS checksum unless the caller pinned it. The checksum is
        // the Fletcher-16 checksum over the LSA from the Options octet (offset 2,
        // LS age excluded) to the end, with the checksum field zeroed (already
        // zeroed by the placeholder above). The checksum field sits at offset 16
        // of the full LSA, i.e. offset 14 within the offset-2 protected slice.
        if pinned_checksum.is_none() {
            let protected = &out[start + OSPF_LSA_CHECKSUM_START..];
            let checkbytes = fletcher16_checkbytes(
                protected,
                OSPF_LSA_CHECKSUM_OFFSET - OSPF_LSA_CHECKSUM_START,
            );
            out[start + OSPF_LSA_CHECKSUM_OFFSET..start + OSPF_LSA_CHECKSUM_OFFSET + 2]
                .copy_from_slice(&checkbytes);
        }
    }

    /// Decode a 20-octet LSA header from the front of `bytes`.
    ///
    /// Returns the parsed [`OspfLsaHeader`] (with every field marked
    /// caller-supplied so the LSA round-trips byte-for-byte) and the declared
    /// LSA length read from the header, which spans the header plus the body.
    /// A buffer shorter than 20 octets yields a structured
    /// [`buffer_too_short`](CrafterError::buffer_too_short) error rather than a
    /// panic.
    pub fn decode(bytes: &[u8]) -> Result<(OspfLsaHeader, usize)> {
        if bytes.len() < OSPF_LSA_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ospf lsa header",
                OSPF_LSA_HEADER_LEN,
                bytes.len(),
            ));
        }

        let ls_age = u16::from_be_bytes([bytes[0], bytes[1]]);
        let options = bytes[2];
        let ls_type = bytes[3];
        let link_state_id = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let advertising_router = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);
        let ls_sequence_number =
            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let ls_checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
        let length = u16::from_be_bytes([bytes[18], bytes[19]]);

        let header = OspfLsaHeader::from_decoded_parts(
            ls_age,
            options,
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

impl Default for OspfLsaHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// The type-specific body of a link-state advertisement, following the 20-octet
/// [`OspfLsaHeader`] (RFC 2328 §A.4).
///
/// This block starts with only the [`OspfLsaBody::Raw`] variant, which carries
/// the LSA body bytes verbatim for an LSA type the builder/decoder does not
/// (yet) model so they round-trip byte-for-byte (mirroring how
/// [`OspfBody`](crate::protocols::ospf::OspfBody) started with only
/// `Unknown`). The typed bodies (Router, Network, Summary, AS-External, NSSA,
/// Opaque) are added by subsequent steps.
#[derive(Debug, Clone)]
pub enum OspfLsaBody {
    /// An LSA body the container does not (yet) model, preserved verbatim. The
    /// bytes are everything after the 20-octet LSA header.
    Raw(Vec<u8>),
    // Typed LSA bodies (Router, Network, Summary, AS-External, NSSA, Opaque)
    // arrive in later steps.
}

impl OspfLsaBody {
    /// The on-wire length of this LSA body, in octets (the bytes after the
    /// 20-octet header).
    pub(crate) fn encoded_len(&self) -> usize {
        match self {
            OspfLsaBody::Raw(body) => body.len(),
        }
    }

    /// Append this LSA body's bytes to `out`. The [`OspfLsaBody::Raw`] variant
    /// writes its bytes verbatim.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match self {
            OspfLsaBody::Raw(body) => out.extend_from_slice(body),
        }
    }
}

/// A complete link-state advertisement: the 20-octet [`OspfLsaHeader`]
/// (RFC 2328 §A.4.1) immediately followed by its type-specific
/// [`OspfLsaBody`].
///
/// The header's `length` field spans the header plus the body, and the LS
/// checksum is the Fletcher-16 checksum over the header (from the Options
/// octet) plus the body. [`OspfLsa::encode`] auto-fills both over header + body
/// unless the caller pinned them, so an LSA built with the crate is
/// protocol-correct by default while deliberately malformed length/checksum
/// values survive untouched.
#[derive(Debug, Clone)]
pub struct OspfLsa {
    /// The 20-octet LSA header (RFC 2328 §A.4.1).
    pub header: OspfLsaHeader,
    /// The type-specific LSA body following the header.
    pub body: OspfLsaBody,
}

impl OspfLsa {
    /// Build an LSA from its header and body.
    pub fn new(header: OspfLsaHeader, body: OspfLsaBody) -> Self {
        Self { header, body }
    }

    /// The on-wire length of this LSA, in octets: the 20-octet header plus the
    /// body.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_LSA_HEADER_LEN + self.body.encoded_len()
    }

    /// Append the complete LSA (header + body) to `out`.
    ///
    /// The body is serialized to a scratch buffer first, then the header is
    /// emitted via [`OspfLsaHeader::encode_with_body`] so the `length` field is
    /// filled with `20 + body.len()` and the LS Fletcher checksum is filled over
    /// the header (from the Options octet) plus the body — each unless the caller
    /// pinned it.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        let mut body_bytes = Vec::with_capacity(self.body.encoded_len());
        self.body.encode(&mut body_bytes);
        self.header.encode_with_body(&body_bytes, out);
    }
}

/// Decode a trailing list of bare 20-octet LSA headers.
///
/// The Database Description (RFC 2328 §A.3.3) and Link State Acknowledgment
/// (RFC 2328 §A.3.6) bodies carry a sequence of LSA headers with no body, so
/// every entry is exactly [`OSPF_LSA_HEADER_LEN`] octets regardless of the
/// declared `length` field (which describes the full LSA only in a Link State
/// Update). This loops while `bytes` is non-empty, decoding one header and
/// advancing the cursor by 20 octets each iteration, mirroring the
/// `decode_path_attributes` list-loop in the BGP decoder. A remainder shorter
/// than 20 octets yields a structured
/// [`buffer_too_short`](CrafterError::buffer_too_short) error rather than a
/// panic.
pub(crate) fn decode_lsa_headers(mut bytes: &[u8]) -> Result<Vec<OspfLsaHeader>> {
    let mut headers = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < OSPF_LSA_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ospf lsa header",
                OSPF_LSA_HEADER_LEN,
                bytes.len(),
            ));
        }
        let (header, _declared_len) = OspfLsaHeader::decode(bytes)?;
        headers.push(header);
        bytes = &bytes[OSPF_LSA_HEADER_LEN..];
    }
    Ok(headers)
}

/// Encode a list of bare LSA headers, each as a header-only 20-octet record.
///
/// Each header is emitted with an empty body via
/// [`OspfLsaHeader::encode_with_body`], so every entry is exactly
/// [`OSPF_LSA_HEADER_LEN`] octets. Shared by the Database Description and Link
/// State Acknowledgment encoders, which carry only LSA headers (RFC 2328
/// §A.3.3, §A.3.6).
pub(crate) fn encode_lsa_headers(headers: &[OspfLsaHeader], out: &mut Vec<u8>) {
    for header in headers {
        header.encode_with_body(&[], out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;

    /// An LSA header built over a small body round-trips through
    /// `encode_with_body` / `decode`: the auto-filled length covers the 20-octet
    /// header plus the body, the Fletcher checksum validates, and the decoded
    /// fields equal the built ones.
    #[test]
    fn ospf_lsa_header_round_trips_with_auto_length_and_checksum() {
        let body = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let header = OspfLsaHeader::new()
            .ls_age(0)
            .options(0x22)
            .ls_type(OSPF_LSA_ROUTER)
            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
            .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
            .ls_sequence_number(0x8000_0001);

        let mut out = Vec::new();
        header.encode_with_body(&body, &mut out);

        // The emitted LSA is the 20-octet header plus the body.
        assert_eq!(out.len(), OSPF_LSA_HEADER_LEN + body.len());

        // The auto-filled length field (octets 18..20) covers header + body.
        let expected_len = (OSPF_LSA_HEADER_LEN + body.len()) as u16;
        assert_eq!(&out[18..20], &expected_len.to_be_bytes());

        // The Fletcher-16 checksum over the whole LSA validates (the placement
        // makes the running sums reduce to zero).
        assert!(
            fletcher16_valid(&out),
            "auto-filled Fletcher checksum should validate over the LSA"
        );

        // Decoding returns the parsed header and the declared LSA length.
        let (decoded, declared_len) = OspfLsaHeader::decode(&out).expect("LSA header decodes");
        assert_eq!(declared_len, OSPF_LSA_HEADER_LEN + body.len());

        // The decoded fields equal the built ones.
        assert_eq!(decoded.ls_age_value(), 0);
        assert_eq!(decoded.options_value(), 0x22);
        assert_eq!(decoded.ls_type_value(), OSPF_LSA_ROUTER);
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
    /// malformed-on-purpose LSAs keep their wrong checksum.
    #[test]
    fn ospf_lsa_header_user_checksum_survives_encode() {
        let body = [0x00, 0x01, 0x02, 0x03];
        let header = OspfLsaHeader::new()
            .ls_type(OSPF_LSA_NETWORK)
            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
            .advertising_router(Ipv4Addr::new(192, 0, 2, 2))
            .ls_checksum(0xBEEF);

        let mut out = Vec::new();
        header.encode_with_body(&body, &mut out);

        // The pinned checksum is written verbatim, not recomputed.
        assert_eq!(&out[16..18], &0xBEEFu16.to_be_bytes());

        // The length still auto-fills to cover the header plus the body.
        assert_eq!(&out[18..20], &((OSPF_LSA_HEADER_LEN + body.len()) as u16).to_be_bytes());
    }

    /// A buffer shorter than the 20-octet LSA header yields a structured
    /// buffer-too-short error rather than a panic.
    #[test]
    fn ospf_lsa_header_decode_rejects_short_buffer() {
        let short = [0u8; OSPF_LSA_HEADER_LEN - 1];
        let err = OspfLsaHeader::decode(&short).expect_err("a short buffer must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf lsa header");
                assert_eq!(required, OSPF_LSA_HEADER_LEN);
                assert_eq!(available, OSPF_LSA_HEADER_LEN - 1);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }

    /// `ospf_lsa_type_name` maps each LSA type constant to its short label and
    /// unknown codes to `"Unknown"`, and the header summary contains the type
    /// name and the advertising router.
    #[test]
    fn ospf_lsa_type_name_and_summary_render_expected_labels() {
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_ROUTER), "Router");
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_NETWORK), "Network");
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_SUMMARY_IP), "Summary-IP");
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_SUMMARY_ASBR), "Summary-ASBR");
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_AS_EXTERNAL), "AS-External");
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_NSSA), "NSSA");
        assert_eq!(
            ospf_lsa_type_name(OSPF_LSA_OPAQUE_LINK_LOCAL),
            "Opaque-LinkLocal"
        );
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_OPAQUE_AREA), "Opaque-Area");
        assert_eq!(ospf_lsa_type_name(OSPF_LSA_OPAQUE_AS), "Opaque-AS");
        assert_eq!(ospf_lsa_type_name(0), "Unknown");
        assert_eq!(ospf_lsa_type_name(6), "Unknown");

        let header = OspfLsaHeader::new()
            .ls_type(OSPF_LSA_ROUTER)
            .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
            .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
            .ls_sequence_number(0x8000_0001)
            .ls_age(0);
        let summary = header.summary();
        assert!(
            summary.contains("Router"),
            "summary should contain the LS type name: {summary}"
        );
        assert!(
            summary.contains("198.51.100.7"),
            "summary should contain the advertising router: {summary}"
        );
    }

    /// A list of three bare LSA headers encodes to 60 octets and round-trips
    /// through `encode_lsa_headers` / `decode_lsa_headers`: the parsed list has
    /// three entries whose fields equal the built ones, and a 50-octet buffer
    /// (two full 20-octet headers plus a 10-octet partial third) yields a
    /// structured buffer-too-short error rather than a panic.
    #[test]
    fn ospf_lsa_headers_list_round_trips_and_rejects_partial_trailer() {
        let headers = [
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_NETWORK)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                .advertising_router(Ipv4Addr::new(198, 51, 100, 7))
                .ls_sequence_number(0x8000_0002),
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_SUMMARY_IP)
                .link_state_id(Ipv4Addr::new(198, 51, 100, 0))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0003),
        ];

        let mut out = Vec::new();
        encode_lsa_headers(&headers, &mut out);

        // Three header-only records, 20 octets each.
        assert_eq!(out.len(), 3 * OSPF_LSA_HEADER_LEN);

        let decoded = decode_lsa_headers(&out).expect("LSA header list decodes");
        assert_eq!(decoded.len(), 3);

        // Every field round-trips for each header.
        for (original, parsed) in headers.iter().zip(decoded.iter()) {
            assert_eq!(parsed.ls_age_value(), original.ls_age_value());
            assert_eq!(parsed.options_value(), original.options_value());
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
            assert_eq!(parsed.length_value(), Some(OSPF_LSA_HEADER_LEN as u16));
        }

        // A 50-octet buffer (two full headers plus a 10-octet partial third)
        // surfaces a structured error on the trailing remainder.
        let partial = &out[..2 * OSPF_LSA_HEADER_LEN + 10];
        assert_eq!(partial.len(), 50);
        let err = decode_lsa_headers(partial).expect_err("a partial trailing header must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf lsa header");
                assert_eq!(required, OSPF_LSA_HEADER_LEN);
                assert_eq!(available, 10);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}
