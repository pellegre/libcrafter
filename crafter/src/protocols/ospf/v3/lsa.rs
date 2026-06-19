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
/// The typed OSPFv3 body decoder consuming this parser lands in a later step;
/// until then it is exercised only by the in-module round-trip tests.
#[allow(dead_code)]
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
}
