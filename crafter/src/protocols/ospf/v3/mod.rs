//! OSPFv3 (RFC 5340) wire-level layer.
//!
//! OSPFv3 is OSPF for IPv6. It runs directly over IPv6 (next header 89, RFC 5340
//! §2.5) and carries a distinct 16-octet common header (RFC 5340 §A.3.1):
//! Version(1)=3, Type(1), Packet Length(2), Router ID(4), Area ID(4),
//! Checksum(2), Instance ID(1), Reserved(1). Unlike OSPFv2 there is no
//! authentication field — OSPFv3 relies on the IPv6 Authentication and ESP
//! headers for integrity and confidentiality (RFC 5340 §2.5).
//!
//! Per the repo's version-suffix naming convention (mirroring `Icmp` ->
//! `Icmpv4`), the OSPFv3 layer is the distinct [`Ospfv3`] struct rather than a
//! mode of [`Ospfv2`](crate::protocols::ospf::Ospfv2).
//!
//! This block defines the [`Ospfv3`] layer: the 16-octet common header plus an
//! opaque [`Ospfv3Body`]. `compile()` writes the header, appends the body, and
//! auto-fills the Packet Length and the IPv6 upper-layer Checksum (RFC 5340 §2.7)
//! unless the caller pinned them. The checksum is the standard IPv6 upper-layer
//! checksum (the same computation UDP and ICMPv6 use) over the OSPFv3
//! header+body, formed with the enclosing IPv6 pseudo-header and next-header 89.
//! Typed packet bodies and the inspection surface are added by later steps.

use core::any::Any;
use core::net::Ipv4Addr;
use core::ops::Div;

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, TransportChecksumContext};
use crate::protocols::ip::shared::IPPROTO_OSPF;

pub mod constants;
pub mod hello;

pub use constants::*;
pub use hello::Ospfv3Hello;

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

/// The body of an OSPFv3 packet (RFC 5340 §A.3), following the 16-octet common
/// header.
///
/// This block models the typed [`Ospfv3Body::Hello`] body (RFC 5340 §A.3.2) and
/// the [`Ospfv3Body::Unknown`] variant, which preserves the raw body bytes
/// verbatim so a packet type the builder/decoder does not (yet) model round-trips
/// byte-for-byte. Further typed bodies are added by later steps.
#[derive(Debug, Clone)]
pub enum Ospfv3Body {
    /// An OSPFv3 Hello body (RFC 5340 §A.3.2).
    Hello(Ospfv3Hello),
    /// A packet body the layer does not (yet) model, preserved verbatim.
    Unknown {
        /// The OSPFv3 packet Type code this body belongs to.
        type_code: u8,
        /// The raw body bytes following the 16-octet common header.
        body: Vec<u8>,
    },
}

impl Ospfv3Body {
    /// The on-wire length of this body, in octets (the bytes after the header).
    fn encoded_len(&self) -> usize {
        match self {
            Ospfv3Body::Hello(hello) => hello.encoded_len(),
            Ospfv3Body::Unknown { body, .. } => body.len(),
        }
    }

    /// Append this body's bytes to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Ospfv3Body::Hello(hello) => hello.encode(out),
            Ospfv3Body::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }

    /// The OSPFv3 packet Type code this body carries.
    fn type_code(&self) -> u8 {
        match self {
            Ospfv3Body::Hello(_) => OSPFV3_TYPE_HELLO,
            Ospfv3Body::Unknown { type_code, .. } => *type_code,
        }
    }

    /// Track the OSPFv3 packet Type code on the opaque body so the header and
    /// body agree by default. Typed bodies carry a fixed Type code, so this only
    /// affects the opaque [`Ospfv3Body::Unknown`] variant.
    fn set_type_code(&mut self, type_code: u8) {
        match self {
            Ospfv3Body::Hello(_) => {}
            Ospfv3Body::Unknown { type_code: tc, .. } => *tc = type_code,
        }
    }
}

/// OSPFv3 packet layer (RFC 5340).
///
/// An `Ospfv3` layer is the 16-octet common header (Version, Type, Packet
/// Length, Router ID, Area ID, Checksum, Instance ID, Reserved) followed by a
/// typed [`Ospfv3Body`]. `compile()` writes the header — auto-filling the Packet
/// Length from the total OSPFv3 byte count and the Checksum (the IPv6
/// upper-layer checksum, RFC 5340 §2.7, computed with the enclosing IPv6
/// pseudo-header and next-header 89) unless the caller pinned them — then the
/// body bytes.
///
/// Per the repo's version-suffix naming convention this layer is distinct from
/// [`Ospfv2`](crate::protocols::ospf::Ospfv2); it has no authentication field
/// because OSPFv3 relies on IPsec (RFC 5340 §2.5).
#[derive(Debug, Clone)]
pub struct Ospfv3 {
    /// OSPF version (RFC 5340 §A.3.1); defaults to [`OSPF_VERSION_3`].
    version: Field<u8>,
    /// OSPFv3 packet Type code (RFC 5340 §A.3.1).
    packet_type: Field<u8>,
    /// Packet Length, in octets, of the OSPFv3 packet (RFC 5340 §A.3.1).
    packet_length: Field<u16>,
    /// Router ID of the originating router (RFC 5340 §A.3.1).
    router_id: Field<Ipv4Addr>,
    /// Area ID this packet belongs to (RFC 5340 §A.3.1).
    area_id: Field<Ipv4Addr>,
    /// IPv6 upper-layer checksum over the OSPFv3 packet (RFC 5340 §2.7).
    checksum: Field<u16>,
    /// Instance ID (RFC 5340 §A.3.1); defaults to zero.
    instance_id: Field<u8>,
    /// Reserved octet (RFC 5340 §A.3.1); defaults to zero.
    reserved: Field<u8>,
    /// The typed packet body following the common header.
    body: Ospfv3Body,
}

impl Ospfv3 {
    /// Build a new OSPFv3 packet with default common-header values and an empty
    /// opaque body.
    ///
    /// Version defaults to [`OSPF_VERSION_3`], Instance ID and Reserved to zero.
    /// The Packet Length and Checksum are left unset so `compile()` fills them.
    /// The body defaults to an empty [`Ospfv3Body::Unknown`] with a zero type
    /// code; set the packet type with [`Ospfv3::packet_type`] and the body with
    /// [`Ospfv3::raw_body`].
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(OSPF_VERSION_3),
            packet_type: Field::unset(),
            packet_length: Field::unset(),
            router_id: Field::unset(),
            area_id: Field::unset(),
            checksum: Field::unset(),
            instance_id: Field::defaulted(0),
            reserved: Field::defaulted(0),
            body: Ospfv3Body::Unknown {
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

    /// Set the OSPFv3 packet Type code (RFC 5340 §A.3.1).
    ///
    /// The opaque body's type code tracks this value so the body and header
    /// agree by default.
    pub fn packet_type(mut self, packet_type: u8) -> Self {
        self.packet_type.set_user(packet_type);
        self.body.set_type_code(packet_type);
        self
    }

    /// Force the OSPFv3 Packet Length field.
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

    /// Force the OSPFv3 Checksum field.
    ///
    /// This preserves malformed-on-purpose packets whose checksum is not the
    /// computed IPv6 upper-layer checksum.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Set the Instance ID field (RFC 5340 §A.3.1).
    pub fn instance_id(mut self, instance_id: u8) -> Self {
        self.instance_id.set_user(instance_id);
        self
    }

    /// Set the Reserved octet (RFC 5340 §A.3.1).
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Replace the opaque body bytes that follow the common header.
    ///
    /// The body's stored type code tracks the current packet type so the header
    /// and body agree by default.
    pub fn raw_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        let type_code = self.packet_type.value().copied().unwrap_or(0);
        self.body = Ospfv3Body::Unknown {
            type_code,
            body: body.into(),
        };
        self
    }

    /// Build an OSPFv3 Hello packet (RFC 5340 §A.3.2).
    ///
    /// Sets the packet Type to [`OSPFV3_TYPE_HELLO`] and installs a default
    /// [`Ospfv3Hello`] body. Set the Hello fields fluently with
    /// [`Ospfv3::with_hello`] or replace the whole body with
    /// [`Ospfv3::hello_body`].
    pub fn hello() -> Self {
        Self::new().hello_body(Ospfv3Hello::new())
    }

    /// Replace the packet body with the given [`Ospfv3Hello`] body and set the
    /// packet Type to [`OSPFV3_TYPE_HELLO`].
    pub fn hello_body(mut self, hello: Ospfv3Hello) -> Self {
        self.packet_type.set_user(OSPFV3_TYPE_HELLO);
        self.body = Ospfv3Body::Hello(hello);
        self
    }

    /// Mutate the Hello body in place through a closure, returning `self` for
    /// fluent chaining (e.g. `Ospfv3::hello().with_hello(|h| ...)`).
    ///
    /// If the current body is not a Hello it is replaced with a default one
    /// (and the packet Type set to [`OSPFV3_TYPE_HELLO`]) before the closure
    /// runs, so the accessor always yields a Hello body to configure.
    pub fn with_hello(mut self, configure: impl FnOnce(&mut Ospfv3Hello)) -> Self {
        configure(self.hello_mut());
        self
    }

    /// Borrow the Hello body mutably, installing a default Hello body (and
    /// setting the packet Type to [`OSPFV3_TYPE_HELLO`]) when the current body
    /// is not already a Hello.
    pub fn hello_mut(&mut self) -> &mut Ospfv3Hello {
        if !matches!(self.body, Ospfv3Body::Hello(_)) {
            self.packet_type.set_user(OSPFV3_TYPE_HELLO);
            self.body = Ospfv3Body::Hello(Ospfv3Hello::new());
        }
        match &mut self.body {
            Ospfv3Body::Hello(hello) => hello,
            // Unreachable: the body was just normalized to a Hello above.
            _ => unreachable!("hello body installed above"),
        }
    }

    /// The effective OSPF Version (the caller value, else [`OSPF_VERSION_3`]).
    pub fn version_value(&self) -> u8 {
        self.version.value().copied().unwrap_or(OSPF_VERSION_3)
    }

    /// The effective OSPFv3 packet Type code (the caller value, else the body's).
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
        self.area_id.value().copied().unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The pinned Checksum, if the caller set it.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    /// The effective Instance ID (the caller value, else zero).
    pub fn instance_id_value(&self) -> u8 {
        self.instance_id.value().copied().unwrap_or(0)
    }

    /// The effective Reserved octet (the caller value, else zero).
    pub fn reserved_value(&self) -> u8 {
        self.reserved.value().copied().unwrap_or(0)
    }

    /// Recover an enclosing IPv6 pseudo-header context for the OSPFv3 upper-layer
    /// checksum (RFC 5340 §2.7), walking outward from the OSPFv3 layer toward the
    /// network header, exactly as the UDP/ICMPv6 checksum path does.
    ///
    /// Returns `None` when there is no enclosing IPv6 layer (for example a bare
    /// `Ospfv3` compiled on its own), in which case `compile()` leaves the
    /// checksum field zero rather than computing a pseudo-header-less value.
    fn checksum_context(ctx: &LayerContext<'_>) -> Option<TransportChecksumContext> {
        (0..ctx.index()).rev().find_map(|index| {
            ctx.packet()
                .get(index)
                .and_then(|layer| layer.transport_checksum_context(IPPROTO_OSPF))
        })
    }
}

impl Default for Ospfv3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ospfv3 {
    fn name(&self) -> &'static str {
        "Ospfv3"
    }

    fn summary(&self) -> String {
        // The effective Packet Length is the caller value, else the total OSPFv3
        // byte count (16-octet header + body) that `compile()` would emit.
        let len = self
            .packet_length_value()
            .map(usize::from)
            .unwrap_or(OSPFV3_HEADER_LEN + self.body.encoded_len());
        format!(
            "Ospfv3(type={}, rid={}, area={}, len={})",
            self.packet_type_value(),
            self.router_id_value(),
            self.area_id_value(),
            len
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        // Stable field/value pairs for `show()`. Auto-filled Packet Length and
        // Checksum print as `auto` when the caller left them unset; the checksum
        // prints as hex. Full body inspection is added by later steps.
        vec![
            ("version", self.version_value().to_string()),
            ("type", self.packet_type_value().to_string()),
            (
                "length",
                self.packet_length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("router_id", self.router_id_value().to_string()),
            ("area_id", self.area_id_value().to_string()),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("instance_id", self.instance_id_value().to_string()),
            ("reserved", self.reserved_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        OSPFV3_HEADER_LEN + self.body.encoded_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        // The OSPFv3 Packet Length field covers the common header plus the body
        // (RFC 5340 §A.3.1).
        let total_len = OSPFV3_HEADER_LEN + self.body.encoded_len();

        // Common header (RFC 5340 §A.3.1). The Packet Length and Checksum are
        // written as placeholders first, then back-filled below unless pinned.
        out.push(self.version_value());
        out.push(self.packet_type_value());

        // Packet Length (octets 2..4): the caller value, else the total byte
        // count.
        let packet_length = self
            .packet_length
            .value()
            .copied()
            .unwrap_or(total_len as u16);
        out.extend_from_slice(&packet_length.to_be_bytes());

        out.extend_from_slice(&self.router_id_value().octets());
        out.extend_from_slice(&self.area_id_value().octets());

        // Checksum placeholder (octets 12..14): zeroed so the upper-layer
        // checksum below covers a zeroed field; a pinned checksum is written
        // verbatim.
        let pinned_checksum = self.checksum.value().copied();
        out.extend_from_slice(&pinned_checksum.unwrap_or(0).to_be_bytes());

        out.push(self.instance_id_value());
        out.push(self.reserved_value());

        // Body bytes follow the 16-octet common header.
        self.body.encode(out);

        if pinned_checksum.is_none() {
            // Auto-fill the IPv6 upper-layer checksum (RFC 5340 §2.7): the same
            // computation UDP and ICMPv6 use, over the OSPFv3 header+body with the
            // checksum field zeroed (the placeholder above already wrote zero) and
            // the enclosing IPv6 pseudo-header (source, destination, next-header
            // 89). When there is no enclosing IPv6 layer the pseudo-header is
            // unavailable, so the checksum field is left zero rather than computing
            // a pseudo-header-less value.
            if let Some(pseudo_header) = Self::checksum_context(ctx) {
                let checksum = pseudo_header.checksum(&out[start..]);
                out[start + 12..start + 14].copy_from_slice(&checksum.to_be_bytes());
            }
        }

        Ok(())
    }

    impl_layer_object!(Ospfv3);
}

impl_layer_div!(Ospfv3);

/// Decode an OSPFv3 packet (RFC 5340 §A.3.1) from the IPv6 payload at next-header
/// 89, appending a typed [`Ospfv3`] layer.
///
/// This block parses only the 16-octet common header; the body bytes that follow
/// are preserved verbatim in [`Ospfv3Body::Unknown`] so an unrecognized (or
/// not-yet-typed) packet type round-trips byte-for-byte. Later steps dispatch the
/// body by packet type. Every recovered header field is marked user-set
/// (`Field::user(...)`) so a decoded packet re-compiles to the same bytes. A
/// buffer shorter than the 16-octet common header surfaces a structured
/// [`CrafterError::BufferTooShort`] rather than a panic.
pub(crate) fn append_ospfv3_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    if bytes.len() < OSPFV3_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ospfv3 header",
            OSPFV3_HEADER_LEN,
            bytes.len(),
        ));
    }

    // Common header (RFC 5340 §A.3.1), read from fixed offsets. The length check
    // above guarantees every slice below is in bounds, so this cannot panic.
    let version = bytes[0];
    let packet_type = bytes[1];
    let packet_length = u16::from_be_bytes([bytes[2], bytes[3]]);
    let router_id = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    let area_id = Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]);
    let checksum = u16::from_be_bytes([bytes[12], bytes[13]]);
    let instance_id = bytes[14];
    let reserved = bytes[15];

    // The body follows the 16-octet header. Prefer the declared Packet Length
    // when it is within [OSPFV3_HEADER_LEN, bytes.len()]; otherwise fall back to
    // the remaining bytes so a malformed length neither overruns the buffer nor
    // discards trailing octets.
    let declared = packet_length as usize;
    let body_end = if (OSPFV3_HEADER_LEN..=bytes.len()).contains(&declared) {
        declared
    } else {
        bytes.len()
    };
    let body_bytes = &bytes[OSPFV3_HEADER_LEN..body_end];

    let ospfv3 = Ospfv3 {
        version: Field::user(version),
        packet_type: Field::user(packet_type),
        packet_length: Field::user(packet_length),
        router_id: Field::user(router_id),
        area_id: Field::user(area_id),
        checksum: Field::user(checksum),
        instance_id: Field::user(instance_id),
        reserved: Field::user(reserved),
        body: Ospfv3Body::Unknown {
            type_code: packet_type,
            body: body_bytes.to_vec(),
        },
    };

    packet = packet.push(ospfv3);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NetworkLayer, Packet};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::ospf::OSPF_TYPE_HELLO;
    use core::net::Ipv6Addr;

    /// An `Ipv6 / Ospfv3` packet compiles with auto-filled Packet Length and the
    /// IPv6 upper-layer checksum (RFC 5340 §2.7), decodes back through the default
    /// registry into a typed `Ospfv3` layer over IPv6 next-header 89, and
    /// round-trips byte-for-byte. Uses `2001:db8::/32` documentation addresses.
    #[test]
    fn ospfv3_over_ipv6_round_trips_through_the_registry() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let bytes = (Ipv6::new().src(src).dst(dst)
            / Ospfv3::new()
                .packet_type(OSPF_TYPE_HELLO)
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0]))
        .compile()
        .expect("Ipv6 / Ospfv3 compiles");

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("the default registry decodes OSPFv3 over IPv6");

        // The decoded packet exposes a typed Ospfv3 layer with version 3.
        let ospfv3 = decoded
            .layer::<Ospfv3>()
            .expect("the decoded packet exposes a typed Ospfv3 layer");
        assert_eq!(ospfv3.version_value(), OSPF_VERSION_3);
        assert_eq!(ospfv3.version_value(), 3);
        assert_eq!(ospfv3.packet_type_value(), OSPF_TYPE_HELLO);

        // The IPv6 layer carries next header 89 (OSPF), auto-derived from the
        // following Ospfv3 layer.
        let ipv6 = decoded
            .layer::<Ipv6>()
            .expect("the decoded packet exposes a typed Ipv6 layer");
        assert_eq!(ipv6.next_header_value(), IPPROTO_OSPF);
        assert_eq!(ipv6.next_header_value(), 89);

        // The decoded packet re-compiles byte-for-byte.
        let recompiled = decoded.compile().expect("decoded OSPFv3 re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A buffer shorter than the 16-octet OSPFv3 common header surfaces a
    /// structured buffer-too-short error (RFC 5340 §A.3.1) rather than a panic.
    #[test]
    fn ospfv3_short_header_is_a_structured_error() {
        let err = append_ospfv3_packet(Packet::new(), &[0u8; 8])
            .expect_err("a short OSPFv3 header is rejected");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ospfv3 header");
                assert_eq!(required, OSPFV3_HEADER_LEN);
                assert_eq!(available, 8);
            }
            other => panic!("expected BufferTooShort, got {other:?}"),
        }
    }
}
