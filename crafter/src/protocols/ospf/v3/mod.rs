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

use crate::error::Result;
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, TransportChecksumContext};
use crate::protocols::ip::shared::IPPROTO_OSPF;
use crate::protocols::ospf::{ospf_type_name, OspfChecksumStatus};

pub mod constants;
pub mod decode;
pub mod hello;
pub mod lsa;
pub mod packet;

pub(crate) use decode::append_ospfv3_packet_with_checksum_validation;

pub use constants::*;
pub use hello::Ospfv3Hello;
pub use lsa::{
    Ospfv3LinkStateUpdate, Ospfv3Lsa, Ospfv3LsaBody, Ospfv3LsaHeader, Ospfv3NetworkLsa,
    Ospfv3RouterInterface, Ospfv3RouterLsa, OSPFV3_LSA_HEADER_LEN,
};
pub use packet::{
    Ospfv3DatabaseDescription, Ospfv3LinkStateAck, Ospfv3LinkStateRequest,
    Ospfv3LinkStateRequestEntry,
};

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
/// This block models the typed [`Ospfv3Body::Hello`] body (RFC 5340 §A.3.2), the
/// [`Ospfv3Body::DatabaseDescription`] (RFC 5340 §A.3.3), the
/// [`Ospfv3Body::LinkStateRequest`] (RFC 5340 §A.3.4), and the
/// [`Ospfv3Body::LinkStateAck`] (RFC 5340 §A.3.6) bodies, plus the
/// [`Ospfv3Body::Unknown`] variant, which preserves the raw body bytes verbatim
/// so a packet type the builder/decoder does not (yet) model round-trips
/// byte-for-byte. Further typed bodies are added by later steps.
#[derive(Debug, Clone)]
pub enum Ospfv3Body {
    /// An OSPFv3 Hello body (RFC 5340 §A.3.2).
    Hello(Ospfv3Hello),
    /// An OSPFv3 Database Description body (RFC 5340 §A.3.3).
    DatabaseDescription(Ospfv3DatabaseDescription),
    /// An OSPFv3 Link State Request body (RFC 5340 §A.3.4).
    LinkStateRequest(Ospfv3LinkStateRequest),
    /// An OSPFv3 Link State Update body (RFC 5340 §A.3.5).
    LinkStateUpdate(Ospfv3LinkStateUpdate),
    /// An OSPFv3 Link State Acknowledgment body (RFC 5340 §A.3.6).
    LinkStateAck(Ospfv3LinkStateAck),
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
            Ospfv3Body::DatabaseDescription(dd) => dd.encoded_len(),
            Ospfv3Body::LinkStateRequest(lsr) => lsr.encoded_len(),
            Ospfv3Body::LinkStateUpdate(lsu) => lsu.encoded_len(),
            Ospfv3Body::LinkStateAck(ack) => ack.encoded_len(),
            Ospfv3Body::Unknown { body, .. } => body.len(),
        }
    }

    /// Append this body's bytes to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Ospfv3Body::Hello(hello) => hello.encode(out),
            Ospfv3Body::DatabaseDescription(dd) => dd.encode(out),
            Ospfv3Body::LinkStateRequest(lsr) => lsr.encode(out),
            Ospfv3Body::LinkStateUpdate(lsu) => lsu.encode(out),
            Ospfv3Body::LinkStateAck(ack) => ack.encode(out),
            Ospfv3Body::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }

    /// The OSPFv3 packet Type code this body carries.
    fn type_code(&self) -> u8 {
        match self {
            Ospfv3Body::Hello(_) => OSPFV3_TYPE_HELLO,
            Ospfv3Body::DatabaseDescription(_) => OSPFV3_TYPE_DATABASE_DESCRIPTION,
            Ospfv3Body::LinkStateRequest(_) => OSPFV3_TYPE_LINK_STATE_REQUEST,
            Ospfv3Body::LinkStateUpdate(_) => OSPFV3_TYPE_LINK_STATE_UPDATE,
            Ospfv3Body::LinkStateAck(_) => OSPFV3_TYPE_LINK_STATE_ACK,
            Ospfv3Body::Unknown { type_code, .. } => *type_code,
        }
    }

    /// Track the OSPFv3 packet Type code on the opaque body so the header and
    /// body agree by default. Typed bodies carry a fixed Type code, so this only
    /// affects the opaque [`Ospfv3Body::Unknown`] variant.
    fn set_type_code(&mut self, type_code: u8) {
        match self {
            Ospfv3Body::Hello(_)
            | Ospfv3Body::DatabaseDescription(_)
            | Ospfv3Body::LinkStateRequest(_)
            | Ospfv3Body::LinkStateUpdate(_)
            | Ospfv3Body::LinkStateAck(_) => {}
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
    /// Decode-time IPv6 upper-layer checksum status (RFC 5340 §2.7).
    ///
    /// [`OspfChecksumStatus::NotChecked`] on builder-constructed packets; set on
    /// decode to [`OspfChecksumStatus::Valid`] / [`OspfChecksumStatus::Invalid`]
    /// when checksum validation is enabled and the enclosing IPv6 pseudo-header is
    /// available. This is decode metadata only and never affects compiled bytes.
    checksum_status: OspfChecksumStatus,
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
            checksum_status: OspfChecksumStatus::NotChecked,
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

    /// Build an OSPFv3 Database Description packet (RFC 5340 §A.3.3).
    ///
    /// Sets the packet Type to [`OSPFV3_TYPE_DATABASE_DESCRIPTION`] and installs a
    /// default [`Ospfv3DatabaseDescription`] body. Configure it fluently with
    /// [`Ospfv3::with_database_description`] or replace the whole body with
    /// [`Ospfv3::database_description_body`].
    pub fn database_description() -> Self {
        Self::new().database_description_body(Ospfv3DatabaseDescription::new())
    }

    /// Replace the packet body with the given [`Ospfv3DatabaseDescription`] body
    /// and set the packet Type to [`OSPFV3_TYPE_DATABASE_DESCRIPTION`].
    pub fn database_description_body(mut self, dd: Ospfv3DatabaseDescription) -> Self {
        self.packet_type.set_user(OSPFV3_TYPE_DATABASE_DESCRIPTION);
        self.body = Ospfv3Body::DatabaseDescription(dd);
        self
    }

    /// Mutate the Database Description body in place through a closure, returning
    /// `self` for fluent chaining. Installs a default body (and sets the packet
    /// Type) when the current body is not already a Database Description.
    pub fn with_database_description(
        mut self,
        configure: impl FnOnce(&mut Ospfv3DatabaseDescription),
    ) -> Self {
        configure(self.database_description_mut());
        self
    }

    /// Borrow the Database Description body mutably, installing a default body
    /// (and setting the packet Type to [`OSPFV3_TYPE_DATABASE_DESCRIPTION`]) when
    /// the current body is not already a Database Description.
    pub fn database_description_mut(&mut self) -> &mut Ospfv3DatabaseDescription {
        if !matches!(self.body, Ospfv3Body::DatabaseDescription(_)) {
            self.packet_type.set_user(OSPFV3_TYPE_DATABASE_DESCRIPTION);
            self.body = Ospfv3Body::DatabaseDescription(Ospfv3DatabaseDescription::new());
        }
        match &mut self.body {
            Ospfv3Body::DatabaseDescription(dd) => dd,
            // Unreachable: the body was just normalized above.
            _ => unreachable!("database description body installed above"),
        }
    }

    /// Build an OSPFv3 Link State Request packet (RFC 5340 §A.3.4).
    ///
    /// Sets the packet Type to [`OSPFV3_TYPE_LINK_STATE_REQUEST`] and installs a
    /// default [`Ospfv3LinkStateRequest`] body. Configure it fluently with
    /// [`Ospfv3::with_link_state_request`] or replace the whole body with
    /// [`Ospfv3::link_state_request_body`].
    pub fn link_state_request() -> Self {
        Self::new().link_state_request_body(Ospfv3LinkStateRequest::new())
    }

    /// Replace the packet body with the given [`Ospfv3LinkStateRequest`] body and
    /// set the packet Type to [`OSPFV3_TYPE_LINK_STATE_REQUEST`].
    pub fn link_state_request_body(mut self, lsr: Ospfv3LinkStateRequest) -> Self {
        self.packet_type.set_user(OSPFV3_TYPE_LINK_STATE_REQUEST);
        self.body = Ospfv3Body::LinkStateRequest(lsr);
        self
    }

    /// Mutate the Link State Request body in place through a closure, returning
    /// `self` for fluent chaining. Installs a default body (and sets the packet
    /// Type) when the current body is not already a Link State Request.
    pub fn with_link_state_request(
        mut self,
        configure: impl FnOnce(&mut Ospfv3LinkStateRequest),
    ) -> Self {
        configure(self.link_state_request_mut());
        self
    }

    /// Borrow the Link State Request body mutably, installing a default body (and
    /// setting the packet Type to [`OSPFV3_TYPE_LINK_STATE_REQUEST`]) when the
    /// current body is not already a Link State Request.
    pub fn link_state_request_mut(&mut self) -> &mut Ospfv3LinkStateRequest {
        if !matches!(self.body, Ospfv3Body::LinkStateRequest(_)) {
            self.packet_type.set_user(OSPFV3_TYPE_LINK_STATE_REQUEST);
            self.body = Ospfv3Body::LinkStateRequest(Ospfv3LinkStateRequest::new());
        }
        match &mut self.body {
            Ospfv3Body::LinkStateRequest(lsr) => lsr,
            // Unreachable: the body was just normalized above.
            _ => unreachable!("link state request body installed above"),
        }
    }

    /// Build an OSPFv3 Link State Update packet (RFC 5340 §A.3.5).
    ///
    /// Sets the packet Type to [`OSPFV3_TYPE_LINK_STATE_UPDATE`] and installs a
    /// default [`Ospfv3LinkStateUpdate`] body. Configure it fluently with
    /// [`Ospfv3::with_link_state_update`] or replace the whole body with
    /// [`Ospfv3::link_state_update_body`].
    pub fn link_state_update() -> Self {
        Self::new().link_state_update_body(Ospfv3LinkStateUpdate::new())
    }

    /// Replace the packet body with the given [`Ospfv3LinkStateUpdate`] body and
    /// set the packet Type to [`OSPFV3_TYPE_LINK_STATE_UPDATE`].
    pub fn link_state_update_body(mut self, lsu: Ospfv3LinkStateUpdate) -> Self {
        self.packet_type.set_user(OSPFV3_TYPE_LINK_STATE_UPDATE);
        self.body = Ospfv3Body::LinkStateUpdate(lsu);
        self
    }

    /// Mutate the Link State Update body in place through a closure, returning
    /// `self` for fluent chaining. Installs a default body (and sets the packet
    /// Type) when the current body is not already a Link State Update.
    pub fn with_link_state_update(
        mut self,
        configure: impl FnOnce(&mut Ospfv3LinkStateUpdate),
    ) -> Self {
        configure(self.link_state_update_mut());
        self
    }

    /// Borrow the Link State Update body mutably, installing a default body (and
    /// setting the packet Type to [`OSPFV3_TYPE_LINK_STATE_UPDATE`]) when the
    /// current body is not already a Link State Update.
    pub fn link_state_update_mut(&mut self) -> &mut Ospfv3LinkStateUpdate {
        if !matches!(self.body, Ospfv3Body::LinkStateUpdate(_)) {
            self.packet_type.set_user(OSPFV3_TYPE_LINK_STATE_UPDATE);
            self.body = Ospfv3Body::LinkStateUpdate(Ospfv3LinkStateUpdate::new());
        }
        match &mut self.body {
            Ospfv3Body::LinkStateUpdate(lsu) => lsu,
            // Unreachable: the body was just normalized above.
            _ => unreachable!("link state update body installed above"),
        }
    }

    /// Build an OSPFv3 Link State Acknowledgment packet (RFC 5340 §A.3.6).
    ///
    /// Sets the packet Type to [`OSPFV3_TYPE_LINK_STATE_ACK`] and installs a
    /// default [`Ospfv3LinkStateAck`] body. Configure it fluently with
    /// [`Ospfv3::with_link_state_ack`] or replace the whole body with
    /// [`Ospfv3::link_state_ack_body`].
    pub fn link_state_ack() -> Self {
        Self::new().link_state_ack_body(Ospfv3LinkStateAck::new())
    }

    /// Replace the packet body with the given [`Ospfv3LinkStateAck`] body and set
    /// the packet Type to [`OSPFV3_TYPE_LINK_STATE_ACK`].
    pub fn link_state_ack_body(mut self, ack: Ospfv3LinkStateAck) -> Self {
        self.packet_type.set_user(OSPFV3_TYPE_LINK_STATE_ACK);
        self.body = Ospfv3Body::LinkStateAck(ack);
        self
    }

    /// Mutate the Link State Acknowledgment body in place through a closure,
    /// returning `self` for fluent chaining. Installs a default body (and sets
    /// the packet Type) when the current body is not already a Link State
    /// Acknowledgment.
    pub fn with_link_state_ack(
        mut self,
        configure: impl FnOnce(&mut Ospfv3LinkStateAck),
    ) -> Self {
        configure(self.link_state_ack_mut());
        self
    }

    /// Borrow the Link State Acknowledgment body mutably, installing a default
    /// body (and setting the packet Type to [`OSPFV3_TYPE_LINK_STATE_ACK`]) when
    /// the current body is not already a Link State Acknowledgment.
    pub fn link_state_ack_mut(&mut self) -> &mut Ospfv3LinkStateAck {
        if !matches!(self.body, Ospfv3Body::LinkStateAck(_)) {
            self.packet_type.set_user(OSPFV3_TYPE_LINK_STATE_ACK);
            self.body = Ospfv3Body::LinkStateAck(Ospfv3LinkStateAck::new());
        }
        match &mut self.body {
            Ospfv3Body::LinkStateAck(ack) => ack,
            // Unreachable: the body was just normalized above.
            _ => unreachable!("link state ack body installed above"),
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

    /// The decode-time IPv6 upper-layer checksum status (RFC 5340 §2.7).
    ///
    /// Builder-constructed packets report [`OspfChecksumStatus::NotChecked`]. On
    /// decode this is set to [`OspfChecksumStatus::Valid`] or
    /// [`OspfChecksumStatus::Invalid`] when checksum validation is enabled and the
    /// enclosing IPv6 pseudo-header is available, and stays
    /// [`OspfChecksumStatus::NotChecked`] when validation is disabled or no IPv6
    /// pseudo-header is in scope. This is decode metadata only and never affects
    /// the re-compiled bytes.
    pub fn checksum_status(&self) -> OspfChecksumStatus {
        self.checksum_status
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
        // Dispatch on the body variant so each typed body extends the header
        // one-liner with its own at-a-glance detail (mirroring the OSPFv2
        // summary). OSPFv3 reuses the OSPFv2 packet-type numbering (RFC 5340
        // §A.3), so `ospf_type_name` names the type. The header carries the
        // Instance ID (RFC 5340 §A.3.1) in place of the OSPFv2 authentication
        // fields.
        let type_name = ospf_type_name(self.packet_type_value());
        let rid = self.router_id_value();
        let area = self.area_id_value();
        let inst = self.instance_id_value();
        match &self.body {
            Ospfv3Body::Hello(hello) => format!(
                "Ospfv3(type={type_name}, rid={rid}, area={area}, inst={inst}, dr={}, bdr={}, neighbors={})",
                hello.designated_router_value(),
                hello.backup_designated_router_value(),
                hello.neighbors_value().len()
            ),
            Ospfv3Body::DatabaseDescription(dd) => format!(
                "Ospfv3(type={type_name}, rid={rid}, area={area}, inst={inst}, mtu={}, seq=0x{:08x}, flags=0x{:02x}, lsa_headers={})",
                dd.interface_mtu_value(),
                dd.dd_sequence_number_value(),
                dd.flags_value(),
                dd.lsa_headers_value().len()
            ),
            Ospfv3Body::LinkStateRequest(lsr) => format!(
                "Ospfv3(type={type_name}, rid={rid}, area={area}, inst={inst}, requests={})",
                lsr.entries_value().len()
            ),
            Ospfv3Body::LinkStateUpdate(lsu) => format!(
                "Ospfv3(type={type_name}, rid={rid}, area={area}, inst={inst}, num_lsas={}, lsas={})",
                lsu.num_lsas_value(),
                lsu.lsas_value().len()
            ),
            Ospfv3Body::LinkStateAck(ack) => format!(
                "Ospfv3(type={type_name}, rid={rid}, area={area}, inst={inst}, lsa_headers={})",
                ack.lsa_headers_value().len()
            ),
            Ospfv3Body::Unknown { .. } => format!(
                "Ospfv3(type={type_name}, rid={rid}, area={area}, inst={inst}, len={len})"
            ),
        }
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        // Stable field/value pairs for `show()`. Auto-filled Packet Length and
        // Checksum print as `auto` when the caller left them unset; the checksum
        // prints as hex. The common header carries the Instance ID and Reserved
        // octet (RFC 5340 §A.3.1) in place of the OSPFv2 authentication fields.
        // The `type` field renders the OSPFv2-shared type name (RFC 5340 §A.3).
        let mut fields = vec![
            ("version", self.version_value().to_string()),
            ("type", ospf_type_name(self.packet_type_value()).to_string()),
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
        ];

        // Each typed body contributes its own stable pairs after the common
        // header (mirroring the OSPFv2 inspection surface). OSPFv3 has no
        // Network Mask in the Hello (RFC 5340 §A.3.2) and carries a 24-bit
        // Options field rendered as raw hex; the rest of the at-a-glance fields
        // mirror their OSPFv2 names.
        match &self.body {
            Ospfv3Body::Hello(hello) => {
                fields.push(("interface_id", hello.interface_id_value().to_string()));
                fields.push(("hello_interval", hello.hello_interval_value().to_string()));
                fields.push((
                    "dead_interval",
                    hello.router_dead_interval_value().to_string(),
                ));
                fields.push(("options", format!("0x{:06x}", hello.options_value())));
                fields.push(("priority", hello.router_priority_value().to_string()));
                fields.push((
                    "designated_router",
                    hello.designated_router_value().to_string(),
                ));
                fields.push((
                    "backup_designated_router",
                    hello.backup_designated_router_value().to_string(),
                ));
                fields.push(("neighbor_count", hello.neighbors_value().len().to_string()));
                for neighbor in hello.neighbors_value() {
                    fields.push(("neighbor", neighbor.to_string()));
                }
            }
            Ospfv3Body::DatabaseDescription(dd) => {
                fields.push(("interface_mtu", dd.interface_mtu_value().to_string()));
                fields.push(("options", format!("0x{:06x}", dd.options_value())));
                fields.push(("dd_flags", format_v3_dd_flags(dd)));
                fields.push((
                    "dd_sequence_number",
                    format!("0x{:08x}", dd.dd_sequence_number_value()),
                ));
                fields.push(("lsa_header_count", dd.lsa_headers_value().len().to_string()));
                for header in dd.lsa_headers_value() {
                    fields.push(("lsa_header", header.summary()));
                }
            }
            Ospfv3Body::LinkStateRequest(lsr) => {
                fields.push(("request_count", lsr.entries_value().len().to_string()));
                for entry in lsr.entries_value() {
                    fields.push((
                        "request",
                        format!(
                            "ls_type=0x{:04x}, id={}, adv={}",
                            entry.ls_type_value(),
                            entry.link_state_id_value(),
                            entry.advertising_router_value()
                        ),
                    ));
                }
            }
            Ospfv3Body::LinkStateUpdate(lsu) => {
                fields.push(("num_lsas", lsu.num_lsas_value().to_string()));
                fields.push(("lsa_count", lsu.lsas_value().len().to_string()));
                for lsa in lsu.lsas_value() {
                    fields.push((
                        "lsa",
                        format!("{} body={}B", lsa.header.summary(), lsa.body.encoded_len()),
                    ));
                    // A typed Router-LSA body (RFC 5340 §A.4.3) adds a
                    // `router_lsa` pair (the flags octet and interface count)
                    // followed by one `router_interface` pair per interface
                    // description (the link type, ids, and metric). A typed
                    // Network-LSA body (RFC 5340 §A.4.4) adds a `network_lsa`
                    // pair (the attached-router count) followed by one
                    // `attached_router` pair per attached Router ID. Other LSA
                    // body variants contribute only the `lsa` header summary
                    // above.
                    match &lsa.body {
                        Ospfv3LsaBody::Router(router) => {
                            fields.push((
                                "router_lsa",
                                format!(
                                    "flags=0x{:02x} options=0x{:06x} interfaces={}",
                                    router.flags_value(),
                                    router.options_value(),
                                    router.interfaces_value().len()
                                ),
                            ));
                            for interface in router.interfaces_value() {
                                fields.push((
                                    "router_interface",
                                    format!(
                                        "type={} metric={} if_id={} nbr_if_id={} nbr_rid={}",
                                        interface.if_type_value(),
                                        interface.metric_value(),
                                        interface.interface_id_value(),
                                        interface.neighbor_interface_id_value(),
                                        interface.neighbor_router_id_value()
                                    ),
                                ));
                            }
                        }
                        Ospfv3LsaBody::Network(network) => {
                            fields.push((
                                "network_lsa",
                                format!(
                                    "options=0x{:06x} attached_routers={}",
                                    network.options_value(),
                                    network.attached_routers_value().len()
                                ),
                            ));
                            for router in network.attached_routers_value() {
                                fields.push(("attached_router", router.to_string()));
                            }
                        }
                        Ospfv3LsaBody::Raw(_) => {}
                    }
                }
            }
            Ospfv3Body::LinkStateAck(ack) => {
                fields.push(("lsa_header_count", ack.lsa_headers_value().len().to_string()));
                for header in ack.lsa_headers_value() {
                    fields.push(("lsa_header", header.summary()));
                }
            }
            Ospfv3Body::Unknown { .. } => {}
        }

        fields
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

/// Render an OSPFv3 Database Description flags octet (RFC 5340 §A.3.3) for
/// `inspection_fields()`: the raw hex value, with the decoded `I|M|MS` labels in
/// parentheses when any recognized bit is set (e.g. `0x07 (I|M|MS)`). A value
/// with no recognized bits (including `0x00`) renders as the bare hex value.
/// Mirrors the OSPFv2 `format_dd_flags` rendering.
fn format_v3_dd_flags(dd: &Ospfv3DatabaseDescription) -> String {
    let flags = dd.flags_value();
    let labels = dd.dd_flags_summary();
    if labels.is_empty() {
        format!("0x{flags:02x}")
    } else {
        format!("0x{flags:02x} ({labels})")
    }
}
