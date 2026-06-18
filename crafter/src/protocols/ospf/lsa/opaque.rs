//! OSPFv2 Opaque-LSA framing and a generic TLV body (RFC 5250 §3).
//!
//! Opaque-LSAs (LS types 9, 10, 11) provide a generalized mechanism to extend
//! OSPF: rather than a fixed body layout, an Opaque-LSA carries
//! application-specific information whose interpretation is governed by the
//! Opaque Type. The flooding scope is selected by the LS type — 9 (link-local,
//! a single subnet), 10 (area-local, a single area), 11 (AS-wide, the whole
//! autonomous system) — matching the
//! [`OSPF_LSA_OPAQUE_LINK_LOCAL`](crate::protocols::ospf::lsa::OSPF_LSA_OPAQUE_LINK_LOCAL),
//! [`OSPF_LSA_OPAQUE_AREA`](crate::protocols::ospf::lsa::OSPF_LSA_OPAQUE_AREA),
//! and [`OSPF_LSA_OPAQUE_AS`](crate::protocols::ospf::lsa::OSPF_LSA_OPAQUE_AS)
//! type constants.
//!
//! The 32-bit Link State ID of the enclosing 20-octet
//! [`OspfLsaHeader`](crate::protocols::ospf::lsa::OspfLsaHeader) is reinterpreted
//! (RFC 5250 §3) as an 8-bit Opaque Type followed by a 24-bit
//! type-specific Opaque ID:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |  Opaque Type  |               Opaque ID                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The Link State ID is stored as an `Ipv4Addr` in the LSA header, so the Opaque
//! Type is its first octet and the Opaque ID is the remaining three octets read
//! as a big-endian 24-bit value.
//!
//! The Opaque-LSA body is application-specific. The most common encoding — used
//! by the Traffic Engineering (RFC 3630) and Router Information (RFC 7770)
//! Opaque-LSAs added in later steps — is a list of TLVs, each a 2-octet Type, a
//! 2-octet Length (the length of the Value alone, excluding the type, length,
//! and padding), the Value, and zero padding to the next 4-octet boundary:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |              Type             |             Length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            Value...                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! [`OspfOpaqueLsa`] models this generic TLV body. Like the other LSA bodies, it
//! rides inside an [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
//! [`OspfLsaBody::Opaque`](crate::protocols::ospf::lsa::OspfLsaBody::Opaque)
//! variant, and [`OspfLsa::encode`](crate::protocols::ospf::lsa::OspfLsa::encode)
//! auto-fills the enclosing LSA `length` and the Fletcher-16 checksum over the
//! header plus this body.

use core::net::Ipv4Addr;

use super::OspfLsaHeader;
use crate::{CrafterError, Result};

// ---------------------------------------------------------------------------
// Fixed lengths (RFC 5250 §3)
// ---------------------------------------------------------------------------

/// The length of a TLV's fixed Type + Length prefix, in octets (RFC 5250 §3): a
/// 2-octet Type and a 2-octet Length.
const OSPF_OPAQUE_TLV_HEADER_LEN: usize = 4;

/// The boundary, in octets, that each TLV is zero-padded up to (RFC 5250 §3).
const OSPF_OPAQUE_TLV_ALIGNMENT: usize = 4;

/// Round `len` up to the next multiple of [`OSPF_OPAQUE_TLV_ALIGNMENT`].
fn padded_value_len(len: usize) -> usize {
    len.div_ceil(OSPF_OPAQUE_TLV_ALIGNMENT) * OSPF_OPAQUE_TLV_ALIGNMENT
}

/// Read the 8-bit Opaque Type from an LSA header's Link State ID (RFC 5250 §3):
/// the first octet of the 32-bit Link State ID.
pub fn opaque_type(header: &OspfLsaHeader) -> u8 {
    header.link_state_id_value().octets()[0]
}

/// Read the 24-bit Opaque ID from an LSA header's Link State ID (RFC 5250 §3):
/// the last three octets of the 32-bit Link State ID, as a big-endian value in
/// the range `0..=0x00ff_ffff`.
pub fn opaque_id(header: &OspfLsaHeader) -> u32 {
    let octets = header.link_state_id_value().octets();
    u32::from_be_bytes([0, octets[1], octets[2], octets[3]])
}

/// Pack an Opaque Type and a 24-bit Opaque ID into the 32-bit Link State ID
/// `Ipv4Addr` of an Opaque-LSA header (RFC 5250 §3).
///
/// The Opaque Type becomes the first octet and the low 24 bits of `opaque_id`
/// become the remaining three octets, big-endian. Bits of `opaque_id` above the
/// low 24 are ignored, matching the on-wire 24-bit field.
pub fn opaque_link_state_id(opaque_type: u8, opaque_id: u32) -> Ipv4Addr {
    let id = opaque_id.to_be_bytes();
    Ipv4Addr::new(opaque_type, id[1], id[2], id[3])
}

impl OspfLsaHeader {
    /// Set the Link State ID from an Opaque Type and a 24-bit Opaque ID
    /// (RFC 5250 §3), packing the Opaque Type into the first octet and the low
    /// 24 bits of `opaque_id` into the remaining three octets.
    ///
    /// This is a convenience over [`OspfLsaHeader::link_state_id`] for the
    /// Opaque-LSA framing; it marks the Link State ID as caller-supplied like any
    /// other builder setter.
    pub fn opaque_link_state_id(self, opaque_type: u8, opaque_id: u32) -> Self {
        self.link_state_id(opaque_link_state_id(opaque_type, opaque_id))
    }
}

/// A single Opaque-LSA TLV (RFC 5250 §3): a 2-octet Type, a 2-octet Length, the
/// Value, and zero padding to the next 4-octet boundary.
///
/// The `Length` field on the wire is the length of `value` alone, excluding the
/// 4-octet Type/Length prefix and any padding. [`OspfOpaqueTlv::encode`] writes
/// the padding so the next TLV starts on a 4-octet boundary, and
/// [`OspfOpaqueTlv::decode`] consumes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OspfOpaqueTlv {
    /// The TLV type code (RFC 5250 §3); application-specific.
    tlv_type: u16,
    /// The TLV value, excluding the type, length, and padding.
    value: Vec<u8>,
}

impl OspfOpaqueTlv {
    /// Build a TLV from its type code and value.
    pub fn new(tlv_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            tlv_type,
            value: value.into(),
        }
    }

    /// The TLV type code (RFC 5250 §3).
    pub fn tlv_type(&self) -> u16 {
        self.tlv_type
    }

    /// The TLV value, excluding the type, length, and padding.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The on-wire length of this TLV, in octets: the 4-octet Type/Length prefix
    /// plus the value padded up to the next 4-octet boundary (RFC 5250 §3).
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_OPAQUE_TLV_HEADER_LEN + padded_value_len(self.value.len())
    }

    /// Append this TLV to `out`: the 2-octet Type, the 2-octet Length (the length
    /// of the value alone), the value, and zero padding to the next 4-octet
    /// boundary (RFC 5250 §3).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tlv_type.to_be_bytes());
        out.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
        let pad = padded_value_len(self.value.len()) - self.value.len();
        out.extend(core::iter::repeat(0u8).take(pad));
    }

    /// Decode one TLV from the front of `bytes`, returning the parsed TLV and the
    /// number of octets it consumed (the 4-octet Type/Length prefix plus the
    /// value padded to a 4-octet boundary, RFC 5250 §3).
    ///
    /// A buffer shorter than the 4-octet prefix, or one whose declared Value
    /// length (including padding) runs past the end of `bytes`, yields a
    /// structured [`buffer_too_short`](CrafterError::buffer_too_short) error
    /// rather than a panic.
    pub fn decode(bytes: &[u8]) -> Result<(OspfOpaqueTlv, usize)> {
        if bytes.len() < OSPF_OPAQUE_TLV_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "ospf opaque tlv",
                OSPF_OPAQUE_TLV_HEADER_LEN,
                bytes.len(),
            ));
        }

        let tlv_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let value_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let padded = padded_value_len(value_len);
        let consumed = OSPF_OPAQUE_TLV_HEADER_LEN + padded;

        if bytes.len() < consumed {
            return Err(CrafterError::buffer_too_short(
                "ospf opaque tlv value",
                consumed,
                bytes.len(),
            ));
        }

        let value = bytes[OSPF_OPAQUE_TLV_HEADER_LEN..OSPF_OPAQUE_TLV_HEADER_LEN + value_len].to_vec();
        Ok((OspfOpaqueTlv::new(tlv_type, value), consumed))
    }
}

/// OSPFv2 Opaque-LSA body as a generic TLV list (RFC 5250 §3).
///
/// Models the Opaque-LSA body (LS types 9, 10, 11) as an ordered list of
/// [`OspfOpaqueTlv`]s. The flooding scope and the Opaque Type/Opaque ID live on
/// the enclosing 20-octet [`OspfLsaHeader`] (the LS type and the reinterpreted
/// Link State ID, set via [`OspfLsaHeader::opaque_link_state_id`]); this body
/// carries only the TLVs. Specific TLV families (Traffic Engineering RFC 3630,
/// Router Information RFC 7770) build on this generic framing in later steps.
///
/// This rides inside an [`OspfLsa`](crate::protocols::ospf::lsa::OspfLsa) as an
/// [`OspfLsaBody::Opaque`](crate::protocols::ospf::lsa::OspfLsaBody::Opaque)
/// variant.
#[derive(Debug, Clone, Default)]
pub struct OspfOpaqueLsa {
    /// The Opaque-LSA TLVs, in order (RFC 5250 §3).
    tlvs: Vec<OspfOpaqueTlv>,
}

impl OspfOpaqueLsa {
    /// Build an empty Opaque-LSA body with no TLVs.
    pub fn new() -> Self {
        Self { tlvs: Vec::new() }
    }

    /// Construct an Opaque-LSA body from a decoded list of TLVs, used by the
    /// Opaque-LSA decode arm in `decode.rs`.
    pub(crate) fn from_decoded_parts(tlvs: Vec<OspfOpaqueTlv>) -> Self {
        Self { tlvs }
    }

    /// Append a single TLV to the Opaque-LSA body.
    pub fn tlv(mut self, tlv: OspfOpaqueTlv) -> Self {
        self.tlvs.push(tlv);
        self
    }

    /// The Opaque-LSA TLVs, in order.
    pub fn tlvs_value(&self) -> &[OspfOpaqueTlv] {
        &self.tlvs
    }

    /// A one-line summary of the Opaque-LSA body for `summary()` /
    /// `inspection_fields()`, like `tlvs=2`.
    pub fn summary(&self) -> String {
        format!("tlvs={}", self.tlvs.len())
    }

    /// The on-wire length of this Opaque-LSA body, in octets: the sum of each
    /// TLV's encoded length, including its 4-octet prefix and 4-octet-boundary
    /// padding (RFC 5250 §3).
    pub(crate) fn encoded_len(&self) -> usize {
        self.tlvs.iter().map(OspfOpaqueTlv::encoded_len).sum()
    }

    /// Append the RFC 5250 §3 Opaque-LSA body to `out`: each TLV in order, each
    /// padded to a 4-octet boundary.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        for tlv in &self.tlvs {
            tlv.encode(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::fletcher16_valid;
    use crate::protocols::ospf::lsa::{
        OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_LSA_HEADER_LEN, OSPF_LSA_OPAQUE_AREA,
    };
    use crate::protocols::ospf::packet::link_state_update::OspfLinkStateUpdate;

    /// An area-scope (LS type 10) Opaque-LSA built with two TLVs — one whose value
    /// length is not a multiple of 4, to exercise the zero padding — encodes to
    /// the RFC 5250 §3 layout. Wrapped in an `OspfLsa` whose Link State ID packs
    /// the Opaque Type/Opaque ID, inside a Link State Update, the TLVs are padded
    /// to 4-octet boundaries, the Link State ID encodes the Opaque Type and Opaque
    /// ID, the enclosing LSA `length` auto-fills to cover the 20-octet header plus
    /// the body, and the LSA's Fletcher-16 checksum validates.
    #[test]
    fn ospf_opaque_lsa_area_scope_two_tlvs_round_trips_in_lsu() {
        // TLV 1: type 1, a 4-octet (already aligned) value.
        let tlv_aligned = OspfOpaqueTlv::new(0x0001, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        // TLV 2: type 2, a 5-octet value that needs 3 octets of padding to reach
        // the next 4-octet boundary (8 octets total value+pad).
        let tlv_padded = OspfOpaqueTlv::new(0x0002, vec![0x11, 0x22, 0x33, 0x44, 0x55]);

        // The aligned TLV needs no padding; the 5-octet TLV pads up to 8 octets.
        assert_eq!(tlv_aligned.encoded_len(), OSPF_OPAQUE_TLV_HEADER_LEN + 4);
        assert_eq!(tlv_padded.encoded_len(), OSPF_OPAQUE_TLV_HEADER_LEN + 8);

        let opaque = OspfOpaqueLsa::new()
            .tlv(tlv_aligned.clone())
            .tlv(tlv_padded.clone());
        assert_eq!(opaque.tlvs_value().len(), 2);

        // Encode the body alone and check the exact RFC 5250 §3 TLV layout,
        // including the zero padding after the 5-octet value.
        let mut body = Vec::new();
        opaque.encode(&mut body);
        assert_eq!(body.len(), opaque.encoded_len());

        let expected: Vec<u8> = vec![
            // TLV 1: type 0x0001, length 4, value, no padding.
            0x00, 0x01, 0x00, 0x04, //
            0xaa, 0xbb, 0xcc, 0xdd, //
            // TLV 2: type 0x0002, length 5, 5-octet value, 3 octets of zero pad.
            0x00, 0x02, 0x00, 0x05, //
            0x11, 0x22, 0x33, 0x44, //
            0x55, 0x00, 0x00, 0x00,
        ];
        assert_eq!(body, expected);

        // The second TLV's 5-octet value (at offset 12 after the first 8-octet
        // TLV and the 4-octet prefix) is followed by exactly three zero padding
        // octets, bringing the body to 20 octets.
        assert_eq!(&body[12..17], &[0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&body[17..20], &[0x00, 0x00, 0x00]);
        assert_eq!(body.len(), 20);

        // A single TLV decodes back, consuming the padded length, and equals the
        // built TLV (the padding is consumed but not part of the value).
        let (decoded_aligned, consumed_aligned) =
            OspfOpaqueTlv::decode(&body).expect("the first TLV decodes");
        assert_eq!(consumed_aligned, tlv_aligned.encoded_len());
        assert_eq!(decoded_aligned, tlv_aligned);
        let (decoded_padded, consumed_padded) =
            OspfOpaqueTlv::decode(&body[consumed_aligned..]).expect("the second TLV decodes");
        assert_eq!(consumed_padded, tlv_padded.encoded_len());
        assert_eq!(decoded_padded, tlv_padded);

        // Wrap the Opaque-LSA in an OspfLsa whose Link State ID packs the Opaque
        // Type (10) and a 24-bit Opaque ID (0x010203), and a Link State Update.
        let opaque_type = 10u8;
        let opaque_id = 0x0001_0203u32;
        let lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_OPAQUE_AREA)
                .opaque_link_state_id(opaque_type, opaque_id)
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1))
                .ls_sequence_number(0x8000_0001),
            OspfLsaBody::Opaque(opaque),
        );

        // The free-function accessors read the Opaque Type and Opaque ID back from
        // the packed Link State ID.
        assert_eq!(opaque_type_of(&lsa.header), opaque_type);
        assert_eq!(opaque_id_of(&lsa.header), opaque_id);

        let lsu = OspfLinkStateUpdate::new().lsa(lsa);

        let mut update = Vec::new();
        lsu.encode(&mut update);

        // # LSAs field (octets 0..4) reports one LSA.
        assert_eq!(&update[0..4], &1u32.to_be_bytes());

        // The single LSA follows the count: 20-octet header plus the Opaque body.
        let lsa_bytes = &update[4..];
        assert_eq!(lsa_bytes.len(), OSPF_LSA_HEADER_LEN + expected.len());

        // The LSA header carries the area-scope LS type 10 (octet 3).
        assert_eq!(lsa_bytes[3], OSPF_LSA_OPAQUE_AREA);

        // The Link State ID (octets 4..8) packs the Opaque Type into the first
        // octet and the 24-bit Opaque ID into the remaining three octets.
        assert_eq!(lsa_bytes[4], opaque_type);
        assert_eq!(&lsa_bytes[5..8], &[0x01, 0x02, 0x03]);

        // The enclosing LSA `length` field (octets 18..20 within the LSA)
        // auto-fills to cover the 20-octet header plus the body.
        let expected_lsa_len = (OSPF_LSA_HEADER_LEN + expected.len()) as u16;
        assert_eq!(&lsa_bytes[18..20], &expected_lsa_len.to_be_bytes());

        // The Opaque body bytes follow the 20-octet header verbatim.
        assert_eq!(&lsa_bytes[OSPF_LSA_HEADER_LEN..], expected.as_slice());

        // The LSA's Fletcher-16 checksum validates over the whole LSA.
        assert!(
            fletcher16_valid(lsa_bytes),
            "auto-filled Fletcher checksum should validate over the Opaque-LSA"
        );
    }

    // The free functions are named `opaque_type`/`opaque_id` at module scope;
    // alias them inside the test to avoid shadowing the local `opaque_type`
    // variable used above.
    fn opaque_type_of(header: &OspfLsaHeader) -> u8 {
        super::opaque_type(header)
    }
    fn opaque_id_of(header: &OspfLsaHeader) -> u32 {
        super::opaque_id(header)
    }

    /// A TLV decode rejects a buffer shorter than the 4-octet Type/Length prefix,
    /// and one whose declared (padded) value length runs past the buffer end,
    /// with a structured buffer-too-short error rather than a panic (RFC 5250 §3).
    #[test]
    fn ospf_opaque_tlv_decode_rejects_short_buffers() {
        // Shorter than the 4-octet prefix.
        let short_prefix = [0x00, 0x01, 0x00];
        let err = OspfOpaqueTlv::decode(&short_prefix).expect_err("a short prefix must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf opaque tlv");
                assert_eq!(required, OSPF_OPAQUE_TLV_HEADER_LEN);
                assert_eq!(available, 3);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }

        // A prefix declaring a 5-octet value (8 padded) but only 2 trailing
        // octets present.
        let short_value = [0x00, 0x02, 0x00, 0x05, 0x11, 0x22];
        let err = OspfOpaqueTlv::decode(&short_value).expect_err("a short value must error");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospf opaque tlv value");
                // 4-octet prefix plus 8 padded value octets.
                assert_eq!(required, OSPF_OPAQUE_TLV_HEADER_LEN + 8);
                assert_eq!(available, 6);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}
