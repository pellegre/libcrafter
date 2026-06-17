//! OSPF (Open Shortest Path First) protocol support.
//!
//! This module hosts the OSPFv2 (RFC 2328) wire-level layer and, in later
//! blocks, its packet bodies, link-state advertisements, authentication, and a
//! base OSPFv3 layer. OSPF runs directly over IP (protocol 89).
//!
//! This block defines the [`Ospfv2`] layer: the 24-octet common header
//! (RFC 2328 §A.3.1) plus an opaque [`OspfBody`]. `compile()` writes the header,
//! appends the body, and auto-fills the Packet Length and Checksum fields unless
//! the caller pinned them — so an OSPF packet built with the crate is
//! protocol-correct by default while deliberately malformed values survive
//! untouched. The decode entrypoint, registry wiring, typed packet bodies, and
//! the curated exports (including the deprecated neutral `Ospf` alias) are added
//! by subsequent steps.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;

use crate::checksum::internet_checksum_chunks;
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use crate::Result;

#[allow(unused_imports)]
pub mod constants;

pub(crate) mod decode;

#[allow(unused_imports)]
pub use constants::*;

macro_rules! impl_layer_object {
    ($type:ty) => {
        fn clone_layer(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    };
}

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> Div<R> for $type
        where
            R: IntoPacket,
        {
            type Output = Packet;

            fn div(self, rhs: R) -> Self::Output {
                Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

/// The body of an OSPFv2 packet (RFC 2328 §A.3), following the shared 24-octet
/// common header.
///
/// This block models only the [`OspfBody::Unknown`] variant, which preserves the
/// raw body bytes of a packet type the builder/decoder does not (yet) model so
/// the bytes round-trip verbatim. The typed Hello, Database Description, Link
/// State Request, Link State Update, and Link State Acknowledgment bodies are
/// added in later steps.
#[derive(Debug, Clone)]
pub enum OspfBody {
    /// A packet body the layer does not (yet) model, preserved verbatim.
    Unknown {
        /// The OSPF packet Type code this body belongs to.
        type_code: u8,
        /// The raw body bytes following the 24-octet common header.
        body: Vec<u8>,
    },
}

impl OspfBody {
    /// The on-wire length of this body, in octets (the bytes after the header).
    fn encoded_len(&self) -> usize {
        match self {
            OspfBody::Unknown { body, .. } => body.len(),
        }
    }

    /// Append this body's bytes to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            OspfBody::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }

    /// The OSPF packet Type code this body carries.
    fn type_code(&self) -> u8 {
        match self {
            OspfBody::Unknown { type_code, .. } => *type_code,
        }
    }

    /// Track the OSPF packet Type code on the body so the header and body agree
    /// by default.
    fn set_type_code(&mut self, type_code: u8) {
        match self {
            OspfBody::Unknown { type_code: tc, .. } => *tc = type_code,
        }
    }
}

/// OSPFv2 packet layer (RFC 2328).
///
/// An `Ospfv2` layer is the shared 24-octet common header (Version, Type, Packet
/// Length, Router ID, Area ID, Checksum, AuType, Authentication) followed by a
/// typed [`OspfBody`]. `compile()` writes the header — auto-filling the Packet
/// Length from the total OSPF byte count and the Checksum (the standard Internet
/// checksum over the whole packet excluding the 8-octet authentication field)
/// unless the caller pinned them — then the body bytes.
///
/// Per the repo's version-suffix naming convention the layer is named `Ospfv2`;
/// the deprecated neutral `Ospf` alias is added in a later step.
#[derive(Debug, Clone)]
pub struct Ospfv2 {
    /// OSPF version (RFC 2328 §A.3.1); defaults to [`OSPF_VERSION_2`].
    version: Field<u8>,
    /// OSPF packet Type code (RFC 2328 §A.3.1).
    packet_type: Field<u8>,
    /// Packet Length, in octets, of the OSPF packet (RFC 2328 §A.3.1).
    packet_length: Field<u16>,
    /// Router ID of the originating router (RFC 2328 §A.3.1).
    router_id: Field<Ipv4Addr>,
    /// Area ID this packet belongs to (RFC 2328 §A.3.1).
    area_id: Field<Ipv4Addr>,
    /// Standard Internet checksum over the packet excluding the auth field.
    checksum: Field<u16>,
    /// Authentication type (RFC 2328 §A.3.1); defaults to [`OSPF_AUTYPE_NULL`].
    autype: Field<u16>,
    /// 8-octet authentication field (RFC 2328 §A.3.1); defaults to all zeros.
    authentication: Field<[u8; OSPF_AUTH_LEN]>,
    /// The typed packet body following the common header.
    body: OspfBody,
}

impl Ospfv2 {
    /// Build a new OSPFv2 packet with default common-header values and an empty
    /// opaque body.
    ///
    /// Version defaults to [`OSPF_VERSION_2`], AuType to [`OSPF_AUTYPE_NULL`],
    /// and the authentication field to all zeros. The Packet Length and Checksum
    /// are left unset so `compile()` fills them. The body defaults to an empty
    /// [`OspfBody::Unknown`] with a zero type code; set the packet type with
    /// [`Ospfv2::packet_type`] and the body with [`Ospfv2::raw_body`].
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(OSPF_VERSION_2),
            packet_type: Field::unset(),
            packet_length: Field::unset(),
            router_id: Field::unset(),
            area_id: Field::unset(),
            checksum: Field::unset(),
            autype: Field::defaulted(OSPF_AUTYPE_NULL),
            authentication: Field::defaulted([0; OSPF_AUTH_LEN]),
            body: OspfBody::Unknown {
                type_code: 0,
                body: Vec::new(),
            },
        }
    }

    /// Force the OSPF Version field.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the OSPF packet Type code (RFC 2328 §A.3.1).
    ///
    /// The opaque body's type code tracks this value so the body and header
    /// agree by default.
    pub fn packet_type(mut self, packet_type: u8) -> Self {
        self.packet_type.set_user(packet_type);
        self.body.set_type_code(packet_type);
        self
    }

    /// Force the OSPF Packet Length field.
    ///
    /// This preserves malformed-on-purpose packets whose declared length differs
    /// from the emitted byte count.
    pub fn packet_length(mut self, packet_length: u16) -> Self {
        self.packet_length.set_user(packet_length);
        self
    }

    /// Set the originating Router ID field.
    pub fn router_id(mut self, router_id: impl Into<Ipv4Addr>) -> Self {
        self.router_id.set_user(router_id.into());
        self
    }

    /// Set the Area ID field.
    pub fn area_id(mut self, area_id: impl Into<Ipv4Addr>) -> Self {
        self.area_id.set_user(area_id.into());
        self
    }

    /// Force the OSPF Checksum field.
    ///
    /// This preserves malformed-on-purpose packets whose checksum is not the
    /// computed Internet checksum.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Set the Authentication Type (AuType) field (RFC 2328 §A.3.1).
    pub fn autype(mut self, autype: u16) -> Self {
        self.autype.set_user(autype);
        self
    }

    /// Set the 8-octet Authentication field (RFC 2328 §A.3.1).
    pub fn authentication(mut self, authentication: [u8; OSPF_AUTH_LEN]) -> Self {
        self.authentication.set_user(authentication);
        self
    }

    /// Replace the opaque body bytes that follow the common header.
    ///
    /// The body's stored type code tracks the current packet type so the header
    /// and body agree by default.
    pub fn raw_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        let type_code = self.packet_type.value().copied().unwrap_or(0);
        self.body = OspfBody::Unknown {
            type_code,
            body: body.into(),
        };
        self
    }

    /// The effective OSPF Version (the caller value, else [`OSPF_VERSION_2`]).
    pub fn version_value(&self) -> u8 {
        self.version.value().copied().unwrap_or(OSPF_VERSION_2)
    }

    /// The effective OSPF packet Type code (the caller value, else the body's).
    pub fn packet_type_value(&self) -> u8 {
        self.packet_type
            .value()
            .copied()
            .unwrap_or_else(|| self.body.type_code())
    }

    /// The pinned Packet Length, if the caller set it.
    pub fn packet_length_value(&self) -> Option<u16> {
        self.packet_length.value().copied()
    }

    /// The effective Router ID (the caller value, else the unspecified address).
    pub fn router_id_value(&self) -> Ipv4Addr {
        self.router_id
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The effective Area ID (the caller value, else the unspecified address).
    pub fn area_id_value(&self) -> Ipv4Addr {
        self.area_id
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The pinned Checksum, if the caller set it.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// The effective AuType (the caller value, else [`OSPF_AUTYPE_NULL`]).
    pub fn autype_value(&self) -> u16 {
        self.autype.value().copied().unwrap_or(OSPF_AUTYPE_NULL)
    }

    /// The effective Authentication field (the caller value, else all zeros).
    pub fn authentication_value(&self) -> [u8; OSPF_AUTH_LEN] {
        self.authentication
            .value()
            .copied()
            .unwrap_or([0; OSPF_AUTH_LEN])
    }
}

impl Default for Ospfv2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ospfv2 {
    fn name(&self) -> &'static str {
        "Ospf"
    }

    fn encoded_len(&self) -> usize {
        OSPF_HEADER_LEN + self.body.encoded_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        let total_len = OSPF_HEADER_LEN + self.body.encoded_len();

        // Common header (RFC 2328 §A.3.1). The Packet Length and Checksum are
        // written as placeholders first, then back-filled below unless pinned.
        out.push(self.version_value());
        out.push(self.packet_type_value());

        // Packet Length placeholder (octets 2..4).
        let packet_length = self
            .packet_length
            .value()
            .copied()
            .unwrap_or(total_len as u16);
        out.extend_from_slice(&packet_length.to_be_bytes());

        out.extend_from_slice(&self.router_id_value().octets());
        out.extend_from_slice(&self.area_id_value().octets());

        // Checksum placeholder (octets 12..14): zeroed so the auto-fill below can
        // compute over the header-with-hole; a pinned checksum is written verbatim.
        let pinned_checksum = self.checksum.value().copied();
        out.extend_from_slice(&pinned_checksum.unwrap_or(0).to_be_bytes());

        out.extend_from_slice(&self.autype_value().to_be_bytes());
        out.extend_from_slice(&self.authentication_value());

        // Body bytes follow the 24-octet common header.
        self.body.encode(out);

        // Auto-fill the Checksum unless the caller pinned it. The OSPF checksum is
        // the standard Internet checksum over the whole packet EXCLUDING the
        // 8-octet authentication field (octets 16..24), computed with the checksum
        // field itself zeroed (RFC 2328 §A.3.1). The placeholder above already
        // wrote zero for the checksum when it is unset.
        if pinned_checksum.is_none() {
            let checksum =
                internet_checksum_chunks([&out[start..start + 16], &out[start + 24..]]);
            out[start + 12..start + 14].copy_from_slice(&checksum.to_be_bytes());
        }

        Ok(())
    }

    impl_layer_object!(Ospfv2);
}

impl_layer_div!(Ospfv2);

/// Deprecated neutral alias for the OSPFv2 layer struct, renamed to [`Ospfv2`].
///
/// Per the repo's version-suffix naming convention (mirroring `Icmp` ->
/// `Icmpv4`), the OSPF layer is the version-explicit [`Ospfv2`]. This alias is
/// kept so downstream code that imported the neutral `Ospf` name keeps compiling
/// (with a deprecation warning). Prefer the version-explicit [`Ospfv2`] name; a
/// distinct `Ospfv3` layer is added in a later block.
#[deprecated(note = "renamed to Ospfv2")]
pub type Ospf = Ospfv2;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    #[test]
    fn ospf_new_defaults_common_header() {
        let ospf = Ospfv2::new();
        assert_eq!(ospf.name(), "Ospf");
        assert_eq!(ospf.version_value(), OSPF_VERSION_2);
        assert_eq!(ospf.autype_value(), OSPF_AUTYPE_NULL);
        assert_eq!(ospf.authentication_value(), [0; OSPF_AUTH_LEN]);
        assert_eq!(ospf.checksum_value(), None);
        assert_eq!(ospf.packet_length_value(), None);
        assert_eq!(ospf.encoded_len(), OSPF_HEADER_LEN);
    }

    #[test]
    fn ospf_common_header_compiles_with_auto_length_and_checksum() {
        let body = [0xde, 0xad, 0xbe, 0xef];
        let ospf = Ospfv2::new()
            .packet_type(OSPF_TYPE_HELLO)
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .raw_body(body);

        let bytes = Packet::from_layer(ospf).compile().unwrap();

        // 24-octet header + 4-octet body.
        let total = OSPF_HEADER_LEN + body.len();
        assert_eq!(bytes.len(), total);

        // Version octet (RFC 2328 §A.3.1) defaults to 2.
        assert_eq!(bytes[0], OSPF_VERSION_2);
        // Type octet carries the requested packet type.
        assert_eq!(bytes[1], OSPF_TYPE_HELLO);
        // Packet Length field (octets 2..4) auto-fills to the total OSPF length.
        assert_eq!(&bytes[2..4], &(total as u16).to_be_bytes());
        // Router ID (octets 4..8) and Area ID (octets 8..12).
        assert_eq!(&bytes[4..8], &[192, 0, 2, 1]);
        assert_eq!(&bytes[8..12], &[0, 0, 0, 0]);
        // AuType (octets 14..16) defaults to null.
        assert_eq!(&bytes[14..16], &OSPF_AUTYPE_NULL.to_be_bytes());
        // Authentication field (octets 16..24) defaults to zeros.
        assert_eq!(&bytes[16..24], &[0u8; OSPF_AUTH_LEN]);
        // Body bytes follow the header verbatim.
        assert_eq!(&bytes[OSPF_HEADER_LEN..], &body);

        // The auto-filled checksum is the Internet checksum over the packet with
        // the 8-octet auth field excluded and the checksum field zeroed; verify it
        // by recomputing the same way (over a copy with the checksum field zeroed)
        // and confirming the field matches.
        let mut zeroed = bytes.as_bytes().to_vec();
        zeroed[12] = 0;
        zeroed[13] = 0;
        let expected = internet_checksum_chunks([&zeroed[0..16], &zeroed[24..]]);
        assert_eq!(&bytes[12..14], &expected.to_be_bytes());
        // The auto-filled checksum is nonzero for this packet.
        assert_ne!(&bytes[12..14], &[0, 0]);
    }

    #[test]
    fn ospf_caller_set_checksum_survives_compile() {
        let ospf = Ospfv2::new()
            .packet_type(OSPF_TYPE_HELLO)
            .raw_body([0x01, 0x02])
            .checksum(0x1234);

        let bytes = Packet::from_layer(ospf).compile().unwrap();

        // The pinned checksum is written verbatim, not recomputed.
        assert_eq!(&bytes[12..14], &0x1234u16.to_be_bytes());
        // The packet type still rides in the Type octet.
        assert_eq!(bytes[1], OSPF_TYPE_HELLO);
        // Version octet is still the default.
        assert_eq!(bytes[0], OSPF_VERSION_2);
    }

    #[test]
    fn ospf_caller_set_packet_length_survives_compile() {
        let ospf = Ospfv2::new()
            .packet_type(OSPF_TYPE_HELLO)
            .raw_body([0x00])
            .packet_length(0xbeef);

        let bytes = Packet::from_layer(ospf).compile().unwrap();
        assert_eq!(&bytes[2..4], &0xbeefu16.to_be_bytes());
    }

    /// The `Ospfv2` layer, `OspfBody`, and the OSPF constants are reachable
    /// through the curated `crafter::prelude` exports (the crate's public
    /// surface), not just the crate-internal module path.
    #[test]
    fn ospf_types_and_constants_reach_the_prelude() {
        use crate::prelude::*;

        // Build an OSPF Hello using only prelude-surfaced symbols and confirm the
        // constants are reachable as named values.
        let ospf = Ospfv2::new()
            .packet_type(OSPF_TYPE_HELLO)
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .autype(OSPF_AUTYPE_NULL);

        assert_eq!(ospf.version_value(), OSPF_VERSION_2);
        assert_eq!(ospf.packet_type_value(), OSPF_TYPE_HELLO);
        assert_eq!(ospf.autype_value(), OSPF_AUTYPE_NULL);

        // The remaining packet-type, length, and AuType constants are reachable.
        let _ = (
            OSPF_TYPE_DATABASE_DESCRIPTION,
            OSPF_TYPE_LINK_STATE_REQUEST,
            OSPF_TYPE_LINK_STATE_UPDATE,
            OSPF_TYPE_LINK_STATE_ACK,
            OSPF_HEADER_LEN,
            OSPF_AUTH_LEN,
            OSPF_AUTYPE_SIMPLE,
            OSPF_AUTYPE_CRYPTOGRAPHIC,
        );

        // The `OspfBody` enum and the deprecated neutral `Ospf` alias surface too.
        let body = OspfBody::Unknown {
            type_code: OSPF_TYPE_HELLO,
            body: Vec::new(),
        };
        assert_eq!(body.type_code(), OSPF_TYPE_HELLO);
        #[allow(deprecated)]
        let _alias: Ospf = Ospfv2::new();

        // The packet compiles through the public `Packet` surface.
        let bytes = Packet::from_layer(ospf).compile().unwrap();
        assert_eq!(bytes[1], OSPF_TYPE_HELLO);
    }
}
