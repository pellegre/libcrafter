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

pub mod auth;

#[allow(unused_imports)]
pub mod constants;

pub(crate) mod decode;

pub mod lsa;

pub mod packet;

#[allow(unused_imports)]
pub use auth::{OspfCryptoAuth, OSPF_MD5_DIGEST_LEN};
#[allow(unused_imports)]
pub use constants::*;
pub use packet::{
    OspfDatabaseDescription, OspfHello, OspfLinkStateAck, OspfLinkStateRequest,
    OspfLinkStateRequestEntry, OspfLinkStateUpdate,
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

/// Decode-time validation status for the OSPF common-header checksum.
///
/// Set during decode and gated by
/// [`ProtocolRegistry::validates_checksums`](crate::ProtocolRegistry); mirrors
/// [`Ipv4ChecksumStatus`](crate::Ipv4ChecksumStatus) and
/// [`UdpChecksumStatus`](crate::UdpChecksumStatus). The OSPF checksum is the
/// standard Internet checksum over the whole OSPF packet excluding the 8-octet
/// authentication field, and is zero for cryptographic authentication
/// (AuType 2, [`OSPF_AUTYPE_CRYPTOGRAPHIC`]); cryptographic-auth packets are
/// therefore reported as [`OspfChecksumStatus::NotChecked`] rather than checked.
///
/// This is decode metadata only: it never affects compiled bytes,
/// `clone_layer`, or round-trip equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OspfChecksumStatus {
    /// The decoded OSPF checksum validates.
    Valid,
    /// The decoded OSPF checksum failed validation.
    Invalid,
    /// Checksum validation was not attempted (validation disabled or the packet
    /// uses cryptographic authentication, where the checksum field is zero).
    NotChecked,
}

/// The body of an OSPFv2 packet (RFC 2328 §A.3), following the shared 24-octet
/// common header.
///
/// This block models the typed [`OspfBody::Hello`] body (RFC 2328 §A.3.2), the
/// [`OspfBody::DatabaseDescription`] body (RFC 2328 §A.3.3), the
/// [`OspfBody::LinkStateRequest`] body (RFC 2328 §A.3.4), the
/// [`OspfBody::LinkStateUpdate`] body (RFC 2328 §A.3.5), the
/// [`OspfBody::LinkStateAck`] body (RFC 2328 §A.3.6), and the
/// [`OspfBody::Unknown`] variant, which preserves the raw body bytes of a
/// packet type the builder/decoder does not (yet) model so the bytes round-trip
/// verbatim.
#[derive(Debug, Clone)]
pub enum OspfBody {
    /// The OSPFv2 Hello packet body (RFC 2328 §A.3.2).
    Hello(OspfHello),
    /// The OSPFv2 Database Description packet body (RFC 2328 §A.3.3).
    DatabaseDescription(OspfDatabaseDescription),
    /// The OSPFv2 Link State Request packet body (RFC 2328 §A.3.4).
    LinkStateRequest(OspfLinkStateRequest),
    /// The OSPFv2 Link State Update packet body (RFC 2328 §A.3.5).
    LinkStateUpdate(OspfLinkStateUpdate),
    /// The OSPFv2 Link State Acknowledgment packet body (RFC 2328 §A.3.6).
    LinkStateAck(OspfLinkStateAck),
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
            OspfBody::Hello(hello) => hello.encoded_len(),
            OspfBody::DatabaseDescription(dd) => dd.encoded_len(),
            OspfBody::LinkStateRequest(lsr) => lsr.encoded_len(),
            OspfBody::LinkStateUpdate(lsu) => lsu.encoded_len(),
            OspfBody::LinkStateAck(ack) => ack.encoded_len(),
            OspfBody::Unknown { body, .. } => body.len(),
        }
    }

    /// Append this body's bytes to `out`.
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            OspfBody::Hello(hello) => hello.encode(out),
            OspfBody::DatabaseDescription(dd) => dd.encode(out),
            OspfBody::LinkStateRequest(lsr) => lsr.encode(out),
            OspfBody::LinkStateUpdate(lsu) => lsu.encode(out),
            OspfBody::LinkStateAck(ack) => ack.encode(out),
            OspfBody::Unknown { body, .. } => out.extend_from_slice(body),
        }
    }

    /// The OSPF packet Type code this body carries.
    fn type_code(&self) -> u8 {
        match self {
            OspfBody::Hello(_) => OSPF_TYPE_HELLO,
            OspfBody::DatabaseDescription(_) => OSPF_TYPE_DATABASE_DESCRIPTION,
            OspfBody::LinkStateRequest(_) => OSPF_TYPE_LINK_STATE_REQUEST,
            OspfBody::LinkStateUpdate(_) => OSPF_TYPE_LINK_STATE_UPDATE,
            OspfBody::LinkStateAck(_) => OSPF_TYPE_LINK_STATE_ACK,
            OspfBody::Unknown { type_code, .. } => *type_code,
        }
    }

    /// Track the OSPF packet Type code on the body so the header and body agree
    /// by default.
    ///
    /// The typed bodies own their packet type (Hello, Database Description, Link
    /// State Request, Link State Acknowledgment) and so ignore type-code changes;
    /// only the opaque [`OspfBody::Unknown`] body tracks the header's type.
    fn set_type_code(&mut self, type_code: u8) {
        match self {
            OspfBody::Hello(_) => {}
            OspfBody::DatabaseDescription(_) => {}
            OspfBody::LinkStateRequest(_) => {}
            OspfBody::LinkStateUpdate(_) => {}
            OspfBody::LinkStateAck(_) => {}
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
    /// Decode-time checksum validation status. This is metadata only: it is not
    /// serialized, does not affect compiled bytes, and defaults to
    /// [`OspfChecksumStatus::NotChecked`] on builder-constructed packets.
    checksum_status: OspfChecksumStatus,
    /// Cryptographic-authentication parameters (AuType 2, keyed-MD5, RFC 2328
    /// §D.3) installed by [`Ospfv2::crypto_md5_auth`]. This is `compile()`
    /// metadata: when present (and the AuType is cryptographic) it drives the
    /// appended message-digest trailer; the secret key it holds never appears on
    /// the wire. `None` for null and simple-password authentication.
    crypto_auth: Option<OspfCryptoAuth>,
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
            checksum_status: OspfChecksumStatus::NotChecked,
            crypto_auth: None,
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

    /// Configure null authentication (AuType 0, RFC 2328 §D.1).
    ///
    /// Sets the AuType field to [`OSPF_AUTYPE_NULL`] and the 8-octet
    /// authentication field to all zeros. The standard Internet checksum (which
    /// excludes the authentication field) still protects the packet. This is an
    /// ergonomic shorthand over [`Ospfv2::autype`] / [`Ospfv2::authentication`].
    pub fn null_auth(mut self) -> Self {
        self.autype.set_user(OSPF_AUTYPE_NULL);
        self.authentication.set_user([0; OSPF_AUTH_LEN]);
        self
    }

    /// Configure simple-password authentication (AuType 1, RFC 2328 §D.2).
    ///
    /// Sets the AuType field to [`OSPF_AUTYPE_SIMPLE`] and copies up to 8 octets
    /// of the cleartext `password` into the 8-octet authentication field,
    /// right-padded with zeros. A password longer than 8 octets is truncated to
    /// its first 8 octets — the only 8 the field can carry. The checksum
    /// auto-fill excludes the authentication field, so setting a password never
    /// changes the computed checksum. Use [`Ospfv2::authentication`] directly to
    /// pin a deliberately malformed 8-octet authentication value.
    pub fn simple_password(mut self, password: &[u8]) -> Self {
        self.autype.set_user(OSPF_AUTYPE_SIMPLE);
        self.authentication
            .set_user(auth::simple_password_field(password));
        self
    }

    /// Configure cryptographic (keyed-MD5) authentication (AuType 2, RFC 2328
    /// §D.3).
    ///
    /// Sets the AuType field to [`OSPF_AUTYPE_CRYPTOGRAPHIC`], encodes the
    /// structured 8-octet authentication field — Reserved (2 octets, zero),
    /// Key ID, Authentication Data Length (16, the MD5 digest length), and the
    /// Cryptographic sequence number — and records the secret `key` so
    /// `compile()` can append the keyed-MD5 message-digest trailer. The trailer
    /// is `MD5(ospf_packet_with_structured_auth || key_padded_to_16)` (RFC 1321).
    ///
    /// For cryptographic authentication `compile()` writes the header Checksum as
    /// zero (RFC 2328 §D.3), the OSPF Packet Length covers only the header and
    /// body (the digest trailer is excluded but is still part of the IP payload),
    /// and the 16-octet digest is appended after the packet bytes. The secret key
    /// never appears on the wire — only the digest derived from it does.
    ///
    /// Caller overrides are honored: pin the [`authentication`](Ospfv2::authentication)
    /// field to install a deliberately malformed structured auth field, or pin the
    /// [`checksum`](Ospfv2::checksum) to override the zero checksum; the recorded
    /// key still drives the appended trailer.
    pub fn crypto_md5_auth(
        mut self,
        key_id: u8,
        sequence_number: u32,
        key: impl Into<Vec<u8>>,
    ) -> Self {
        let crypto = OspfCryptoAuth::new(key_id, sequence_number, key);
        self.autype.set_user(OSPF_AUTYPE_CRYPTOGRAPHIC);
        self.authentication.set_user(crypto.structured_auth_field());
        self.crypto_auth = Some(crypto);
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

    /// Build an OSPFv2 Hello packet (RFC 2328 §A.3.2).
    ///
    /// Sets the packet Type to [`OSPF_TYPE_HELLO`] and installs a default
    /// [`OspfHello`] body. Set the Hello fields fluently with
    /// [`Ospfv2::with_hello`] or replace the whole body with
    /// [`Ospfv2::hello_body`].
    pub fn hello() -> Self {
        Self::new()
            .packet_type(OSPF_TYPE_HELLO)
            .hello_body(OspfHello::new())
    }

    /// Replace the packet body with the given [`OspfHello`] body and set the
    /// packet Type to [`OSPF_TYPE_HELLO`].
    pub fn hello_body(mut self, hello: OspfHello) -> Self {
        self.packet_type.set_user(OSPF_TYPE_HELLO);
        self.body = OspfBody::Hello(hello);
        self
    }

    /// Mutate the Hello body in place through a closure, returning `self` for
    /// fluent chaining (e.g. `Ospfv2::hello().with_hello(|h| ...)`).
    ///
    /// If the current body is not a Hello it is replaced with a default one
    /// (and the packet Type set to [`OSPF_TYPE_HELLO`]) before the closure runs,
    /// so the accessor always yields a Hello body to configure.
    pub fn with_hello(mut self, configure: impl FnOnce(&mut OspfHello)) -> Self {
        configure(self.hello_mut());
        self
    }

    /// Borrow the Hello body mutably, installing a default Hello body (and
    /// setting the packet Type to [`OSPF_TYPE_HELLO`]) when the current body is
    /// not already a Hello.
    pub fn hello_mut(&mut self) -> &mut OspfHello {
        if !matches!(self.body, OspfBody::Hello(_)) {
            self.packet_type.set_user(OSPF_TYPE_HELLO);
            self.body = OspfBody::Hello(OspfHello::new());
        }
        match &mut self.body {
            OspfBody::Hello(hello) => hello,
            // Unreachable: the body was just normalized to a Hello above.
            _ => unreachable!("hello body installed above"),
        }
    }

    /// Build an OSPFv2 Database Description packet (RFC 2328 §A.3.3).
    ///
    /// Sets the packet Type to [`OSPF_TYPE_DATABASE_DESCRIPTION`] and installs a
    /// default [`OspfDatabaseDescription`] body. Set the DD fields fluently with
    /// [`Ospfv2::with_database_description`] or replace the whole body with
    /// [`Ospfv2::database_description_body`].
    pub fn database_description() -> Self {
        Self::new()
            .packet_type(OSPF_TYPE_DATABASE_DESCRIPTION)
            .database_description_body(OspfDatabaseDescription::new())
    }

    /// Replace the packet body with the given [`OspfDatabaseDescription`] body
    /// and set the packet Type to [`OSPF_TYPE_DATABASE_DESCRIPTION`].
    pub fn database_description_body(mut self, dd: OspfDatabaseDescription) -> Self {
        self.packet_type.set_user(OSPF_TYPE_DATABASE_DESCRIPTION);
        self.body = OspfBody::DatabaseDescription(dd);
        self
    }

    /// Mutate the Database Description body in place through a closure, returning
    /// `self` for fluent chaining (e.g.
    /// `Ospfv2::database_description().with_database_description(|d| ...)`).
    ///
    /// If the current body is not a Database Description it is replaced with a
    /// default one (and the packet Type set to
    /// [`OSPF_TYPE_DATABASE_DESCRIPTION`]) before the closure runs, so the
    /// accessor always yields a Database Description body to configure.
    pub fn with_database_description(
        mut self,
        configure: impl FnOnce(&mut OspfDatabaseDescription),
    ) -> Self {
        configure(self.database_description_mut());
        self
    }

    /// Borrow the Database Description body mutably, installing a default
    /// Database Description body (and setting the packet Type to
    /// [`OSPF_TYPE_DATABASE_DESCRIPTION`]) when the current body is not already
    /// a Database Description.
    pub fn database_description_mut(&mut self) -> &mut OspfDatabaseDescription {
        if !matches!(self.body, OspfBody::DatabaseDescription(_)) {
            self.packet_type.set_user(OSPF_TYPE_DATABASE_DESCRIPTION);
            self.body = OspfBody::DatabaseDescription(OspfDatabaseDescription::new());
        }
        match &mut self.body {
            OspfBody::DatabaseDescription(dd) => dd,
            // Unreachable: the body was just normalized to a DD above.
            _ => unreachable!("database description body installed above"),
        }
    }

    /// Build an OSPFv2 Link State Request packet (RFC 2328 §A.3.4).
    ///
    /// Sets the packet Type to [`OSPF_TYPE_LINK_STATE_REQUEST`] and installs a
    /// default (empty) [`OspfLinkStateRequest`] body. Add request entries
    /// fluently with [`Ospfv2::with_link_state_request`] or replace the whole
    /// body with [`Ospfv2::link_state_request_body`].
    pub fn link_state_request() -> Self {
        Self::new()
            .packet_type(OSPF_TYPE_LINK_STATE_REQUEST)
            .link_state_request_body(OspfLinkStateRequest::new())
    }

    /// Replace the packet body with the given [`OspfLinkStateRequest`] body and
    /// set the packet Type to [`OSPF_TYPE_LINK_STATE_REQUEST`].
    pub fn link_state_request_body(mut self, lsr: OspfLinkStateRequest) -> Self {
        self.packet_type.set_user(OSPF_TYPE_LINK_STATE_REQUEST);
        self.body = OspfBody::LinkStateRequest(lsr);
        self
    }

    /// Mutate the Link State Request body in place through a closure, returning
    /// `self` for fluent chaining (e.g.
    /// `Ospfv2::link_state_request().with_link_state_request(|r| ...)`).
    ///
    /// If the current body is not a Link State Request it is replaced with a
    /// default one (and the packet Type set to
    /// [`OSPF_TYPE_LINK_STATE_REQUEST`]) before the closure runs, so the
    /// accessor always yields a Link State Request body to configure.
    pub fn with_link_state_request(
        mut self,
        configure: impl FnOnce(&mut OspfLinkStateRequest),
    ) -> Self {
        configure(self.link_state_request_mut());
        self
    }

    /// Borrow the Link State Request body mutably, installing a default Link
    /// State Request body (and setting the packet Type to
    /// [`OSPF_TYPE_LINK_STATE_REQUEST`]) when the current body is not already a
    /// Link State Request.
    pub fn link_state_request_mut(&mut self) -> &mut OspfLinkStateRequest {
        if !matches!(self.body, OspfBody::LinkStateRequest(_)) {
            self.packet_type.set_user(OSPF_TYPE_LINK_STATE_REQUEST);
            self.body = OspfBody::LinkStateRequest(OspfLinkStateRequest::new());
        }
        match &mut self.body {
            OspfBody::LinkStateRequest(lsr) => lsr,
            // Unreachable: the body was just normalized to an LSR above.
            _ => unreachable!("link state request body installed above"),
        }
    }

    /// Build an OSPFv2 Link State Update packet (RFC 2328 §A.3.5).
    ///
    /// Sets the packet Type to [`OSPF_TYPE_LINK_STATE_UPDATE`] and installs a
    /// default (empty) [`OspfLinkStateUpdate`] body. Add LSAs fluently with
    /// [`Ospfv2::with_link_state_update`] or replace the whole body with
    /// [`Ospfv2::link_state_update_body`].
    pub fn link_state_update() -> Self {
        Self::new()
            .packet_type(OSPF_TYPE_LINK_STATE_UPDATE)
            .link_state_update_body(OspfLinkStateUpdate::new())
    }

    /// Replace the packet body with the given [`OspfLinkStateUpdate`] body and
    /// set the packet Type to [`OSPF_TYPE_LINK_STATE_UPDATE`].
    pub fn link_state_update_body(mut self, lsu: OspfLinkStateUpdate) -> Self {
        self.packet_type.set_user(OSPF_TYPE_LINK_STATE_UPDATE);
        self.body = OspfBody::LinkStateUpdate(lsu);
        self
    }

    /// Mutate the Link State Update body in place through a closure, returning
    /// `self` for fluent chaining (e.g.
    /// `Ospfv2::link_state_update().with_link_state_update(|u| ...)`).
    ///
    /// If the current body is not a Link State Update it is replaced with a
    /// default one (and the packet Type set to [`OSPF_TYPE_LINK_STATE_UPDATE`])
    /// before the closure runs, so the accessor always yields a Link State Update
    /// body to configure.
    pub fn with_link_state_update(
        mut self,
        configure: impl FnOnce(&mut OspfLinkStateUpdate),
    ) -> Self {
        configure(self.link_state_update_mut());
        self
    }

    /// Borrow the Link State Update body mutably, installing a default Link State
    /// Update body (and setting the packet Type to
    /// [`OSPF_TYPE_LINK_STATE_UPDATE`]) when the current body is not already a
    /// Link State Update.
    pub fn link_state_update_mut(&mut self) -> &mut OspfLinkStateUpdate {
        if !matches!(self.body, OspfBody::LinkStateUpdate(_)) {
            self.packet_type.set_user(OSPF_TYPE_LINK_STATE_UPDATE);
            self.body = OspfBody::LinkStateUpdate(OspfLinkStateUpdate::new());
        }
        match &mut self.body {
            OspfBody::LinkStateUpdate(lsu) => lsu,
            // Unreachable: the body was just normalized to an LSU above.
            _ => unreachable!("link state update body installed above"),
        }
    }

    /// Build an OSPFv2 Link State Acknowledgment packet (RFC 2328 §A.3.6).
    ///
    /// Sets the packet Type to [`OSPF_TYPE_LINK_STATE_ACK`] and installs a
    /// default (empty) [`OspfLinkStateAck`] body. Add LSA headers fluently with
    /// [`Ospfv2::with_link_state_ack`] or replace the whole body with
    /// [`Ospfv2::link_state_ack_body`].
    pub fn link_state_ack() -> Self {
        Self::new()
            .packet_type(OSPF_TYPE_LINK_STATE_ACK)
            .link_state_ack_body(OspfLinkStateAck::new())
    }

    /// Replace the packet body with the given [`OspfLinkStateAck`] body and set
    /// the packet Type to [`OSPF_TYPE_LINK_STATE_ACK`].
    pub fn link_state_ack_body(mut self, ack: OspfLinkStateAck) -> Self {
        self.packet_type.set_user(OSPF_TYPE_LINK_STATE_ACK);
        self.body = OspfBody::LinkStateAck(ack);
        self
    }

    /// Mutate the Link State Acknowledgment body in place through a closure,
    /// returning `self` for fluent chaining (e.g.
    /// `Ospfv2::link_state_ack().with_link_state_ack(|a| ...)`).
    ///
    /// If the current body is not a Link State Acknowledgment it is replaced with
    /// a default one (and the packet Type set to [`OSPF_TYPE_LINK_STATE_ACK`])
    /// before the closure runs, so the accessor always yields a Link State
    /// Acknowledgment body to configure.
    pub fn with_link_state_ack(
        mut self,
        configure: impl FnOnce(&mut OspfLinkStateAck),
    ) -> Self {
        configure(self.link_state_ack_mut());
        self
    }

    /// Borrow the Link State Acknowledgment body mutably, installing a default
    /// Link State Acknowledgment body (and setting the packet Type to
    /// [`OSPF_TYPE_LINK_STATE_ACK`]) when the current body is not already a Link
    /// State Acknowledgment.
    pub fn link_state_ack_mut(&mut self) -> &mut OspfLinkStateAck {
        if !matches!(self.body, OspfBody::LinkStateAck(_)) {
            self.packet_type.set_user(OSPF_TYPE_LINK_STATE_ACK);
            self.body = OspfBody::LinkStateAck(OspfLinkStateAck::new());
        }
        match &mut self.body {
            OspfBody::LinkStateAck(ack) => ack,
            // Unreachable: the body was just normalized to an LSAck above.
            _ => unreachable!("link state ack body installed above"),
        }
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

    /// Decode-time checksum validation status (RFC 2328 §A.3.1).
    ///
    /// Builder-constructed packets report [`OspfChecksumStatus::NotChecked`].
    /// On decode this is set to [`OspfChecksumStatus::Valid`] or
    /// [`OspfChecksumStatus::Invalid`] when checksum validation is enabled and
    /// the packet does not use cryptographic authentication; it stays
    /// [`OspfChecksumStatus::NotChecked`] when validation is disabled or the
    /// AuType is [`OSPF_AUTYPE_CRYPTOGRAPHIC`] (whose checksum field is zero).
    /// This is decode metadata only and does not affect compiled bytes.
    pub fn checksum_status(&self) -> OspfChecksumStatus {
        self.checksum_status
    }

    /// The cryptographic-authentication parameters (AuType 2, keyed-MD5) recorded
    /// by [`Ospfv2::crypto_md5_auth`], if any.
    ///
    /// Present only when cryptographic authentication was configured through the
    /// builder; `None` for null, simple-password, and decoded packets. When
    /// present, `compile()` appends a keyed-MD5 message-digest trailer after the
    /// OSPF packet (RFC 2328 §D.3). The secret key it holds never appears on the
    /// wire.
    pub fn crypto_auth(&self) -> Option<&OspfCryptoAuth> {
        self.crypto_auth.as_ref()
    }

    /// The recorded cryptographic-authentication parameters that `compile()`
    /// should use to append a keyed-MD5 trailer, if any.
    ///
    /// A trailer is appended only when both the recorded parameters are present
    /// (set via [`Ospfv2::crypto_md5_auth`]) and the effective AuType is
    /// [`OSPF_AUTYPE_CRYPTOGRAPHIC`]. Overriding the AuType away from
    /// cryptographic after configuring crypto auth therefore suppresses the
    /// trailer, keeping the AuType field authoritative.
    fn crypto_auth_for_trailer(&self) -> Option<&OspfCryptoAuth> {
        match &self.crypto_auth {
            Some(crypto) if self.autype_value() == OSPF_AUTYPE_CRYPTOGRAPHIC => Some(crypto),
            _ => None,
        }
    }

    /// Whether `compile()` appends a keyed-MD5 message-digest trailer for this
    /// packet (RFC 2328 §D.3), so length accounting can include it.
    fn appends_crypto_trailer(&self) -> bool {
        self.crypto_auth_for_trailer().is_some()
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

    fn summary(&self) -> String {
        // The effective Packet Length is the caller value, else the total OSPF
        // byte count (24-octet header + body) that `compile()` would emit.
        let len = self
            .packet_length_value()
            .map(usize::from)
            .unwrap_or(OSPF_HEADER_LEN + self.body.encoded_len());
        // Dispatch on the body variant so each typed body extends the header
        // one-liner with its own at-a-glance detail (mirroring BGP). The Hello
        // body reports the network mask, DR/BDR, and neighbor count; other
        // bodies fall back to the common-header summary with the Packet Length.
        match &self.body {
            OspfBody::Hello(hello) => format!(
                "Ospf(type={}, rid={}, area={}, mask={}, dr={}, bdr={}, neighbors={})",
                ospf_type_name(self.packet_type_value()),
                self.router_id_value(),
                self.area_id_value(),
                hello.network_mask_value(),
                hello.designated_router_value(),
                hello.backup_designated_router_value(),
                hello.neighbors_value().len()
            ),
            OspfBody::DatabaseDescription(dd) => format!(
                "Ospf(type={}, rid={}, area={}, mtu={}, seq=0x{:08x}, flags=0x{:02x}, lsa_headers={})",
                ospf_type_name(self.packet_type_value()),
                self.router_id_value(),
                self.area_id_value(),
                dd.interface_mtu_value(),
                dd.dd_sequence_number_value(),
                dd.flags_value(),
                dd.lsa_headers_value().len()
            ),
            OspfBody::LinkStateRequest(lsr) => format!(
                "Ospf(type={}, rid={}, area={}, requests={})",
                ospf_type_name(self.packet_type_value()),
                self.router_id_value(),
                self.area_id_value(),
                lsr.entries_value().len()
            ),
            OspfBody::LinkStateUpdate(lsu) => format!(
                "Ospf(type={}, rid={}, area={}, num_lsas={}, lsas={})",
                ospf_type_name(self.packet_type_value()),
                self.router_id_value(),
                self.area_id_value(),
                lsu.num_lsas_value(),
                lsu.lsas_value().len()
            ),
            OspfBody::LinkStateAck(ack) => format!(
                "Ospf(type={}, rid={}, area={}, lsa_headers={})",
                ospf_type_name(self.packet_type_value()),
                self.router_id_value(),
                self.area_id_value(),
                ack.lsa_headers_value().len()
            ),
            OspfBody::Unknown { .. } => format!(
                "Ospf(type={}, rid={}, area={}, len={})",
                ospf_type_name(self.packet_type_value()),
                self.router_id_value(),
                self.area_id_value(),
                len
            ),
        }
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        // Stable field/value pairs for `show()`. Auto-filled Packet Length and
        // Checksum print as `auto` when the caller left them unset; the checksum
        // and authentication fields print as hex.
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
            (
                "autype",
                format!(
                    "{} ({})",
                    self.autype_value(),
                    ospf_autype_name(self.autype_value())
                ),
            ),
            (
                "authentication",
                format!("0x{}", hex_bytes(&self.authentication_value())),
            ),
        ];

        // Each typed body contributes its own stable pairs after the common
        // header (mirroring BGP). The Hello body adds its intervals, options,
        // priority, mask, DR/BDR, neighbor count, and one `neighbor` per
        // neighbor Router ID.
        if let OspfBody::Hello(hello) = &self.body {
            fields.push(("hello_interval", hello.hello_interval_value().to_string()));
            fields.push((
                "dead_interval",
                hello.router_dead_interval_value().to_string(),
            ));
            fields.push((
                "options",
                format!("0x{:02x}", hello.options_value()),
            ));
            fields.push(("priority", hello.router_priority_value().to_string()));
            fields.push(("network_mask", hello.network_mask_value().to_string()));
            fields.push((
                "designated_router",
                hello.designated_router_value().to_string(),
            ));
            fields.push((
                "backup_designated_router",
                hello.backup_designated_router_value().to_string(),
            ));
            fields.push((
                "neighbor_count",
                hello.neighbors_value().len().to_string(),
            ));
            for neighbor in hello.neighbors_value() {
                fields.push(("neighbor", neighbor.to_string()));
            }
        }

        // The Database Description body adds its MTU, options, flags, DD
        // sequence number, and one `lsa_header` summary per carried LSA header.
        if let OspfBody::DatabaseDescription(dd) = &self.body {
            fields.push(("interface_mtu", dd.interface_mtu_value().to_string()));
            fields.push(("options", format!("0x{:02x}", dd.options_value())));
            fields.push(("dd_flags", format!("0x{:02x}", dd.flags_value())));
            fields.push((
                "dd_sequence_number",
                format!("0x{:08x}", dd.dd_sequence_number_value()),
            ));
            fields.push(("lsa_header_count", dd.lsa_headers_value().len().to_string()));
            for header in dd.lsa_headers_value() {
                fields.push(("lsa_header", header.summary()));
            }
        }

        // The Link State Request body adds its request count and one `request`
        // line per entry (LS type, Link State ID, Advertising Router).
        if let OspfBody::LinkStateRequest(lsr) = &self.body {
            fields.push(("request_count", lsr.entries_value().len().to_string()));
            for entry in lsr.entries_value() {
                fields.push((
                    "request",
                    format!(
                        "ls_type=0x{:08x}, id={}, adv={}",
                        entry.ls_type_value(),
                        entry.link_state_id_value(),
                        entry.advertising_router_value()
                    ),
                ));
            }
        }

        // The Link State Update body adds its `# LSAs` count, its carried-LSA
        // count, and one `lsa` line per carried LSA: the LSA header summary plus
        // the body byte length (e.g. `LSA(...) body=12B`). The body is still
        // `Raw` here, so its length is the byte count after the 20-octet header;
        // typed bodies (added in later steps) keep the same `body=NB` suffix.
        if let OspfBody::LinkStateUpdate(lsu) = &self.body {
            fields.push(("num_lsas", lsu.num_lsas_value().to_string()));
            fields.push(("lsa_count", lsu.lsas_value().len().to_string()));
            for lsa in lsu.lsas_value() {
                fields.push((
                    "lsa",
                    format!("{} body={}B", lsa.header.summary(), lsa.body.encoded_len()),
                ));
                // A typed Router-LSA body (RFC 2328 §A.4.2) adds a `router_lsa`
                // pair (the V/E/B flags and link count) followed by one
                // `router_link` pair per link (type name, Link ID, Link Data,
                // metric). Other LSA body variants contribute only the `lsa`
                // header summary above.
                if let crate::protocols::ospf::lsa::OspfLsaBody::Router(router) = &lsa.body {
                    fields.push(("router_lsa", router.summary()));
                    for link in router.links_value() {
                        fields.push(("router_link", link.summary()));
                    }
                }
                // A typed Network-LSA body (RFC 2328 §A.4.3) adds a `network_lsa`
                // pair (the network mask and attached-router count) followed by
                // one `attached_router` pair per attached Router ID. Other LSA
                // body variants contribute only the `lsa` header summary above.
                if let crate::protocols::ospf::lsa::OspfLsaBody::Network(network) = &lsa.body {
                    fields.push(("network_lsa", network.summary()));
                    for router in network.attached_routers_value() {
                        fields.push(("attached_router", router.to_string()));
                    }
                }
                // A typed Summary-LSA body (RFC 2328 §A.4.4, LS type 3 and 4)
                // adds a `summary_lsa` pair (the network mask and TOS/metric-entry
                // count) followed by one `summary_tos` pair per TOS/metric entry
                // (the TOS code and its 24-bit metric). Other LSA body variants
                // contribute only the `lsa` header summary above.
                if let crate::protocols::ospf::lsa::OspfLsaBody::Summary(summary) = &lsa.body {
                    fields.push(("summary_lsa", summary.summary()));
                    for entry in summary.entries_value() {
                        fields.push((
                            "summary_tos",
                            format!(
                                "tos={} metric={}",
                                entry.tos_value(),
                                entry.metric_value()
                            ),
                        ));
                    }
                }
                // A typed AS-External-LSA body (RFC 2328 §A.4.5, LS type 5) adds
                // an `as_external_lsa` pair (the network mask and a summary of the
                // mandatory TOS 0 entry) followed by one `as_external_tos` pair per
                // external metric entry (the E bit / external metric type, 24-bit
                // metric, forwarding address, and external route tag). Other LSA
                // body variants contribute only the `lsa` header summary above.
                if let crate::protocols::ospf::lsa::OspfLsaBody::AsExternal(external) = &lsa.body {
                    fields.push(("as_external_lsa", external.summary()));
                    for entry in external.entries_value() {
                        fields.push((
                            "as_external_tos",
                            format!(
                                "type={} metric={} fwd={} tag=0x{:08x}",
                                if entry.e_bit_value() { "E2" } else { "E1" },
                                entry.metric_value(),
                                entry.forwarding_address_value(),
                                entry.external_route_tag_value()
                            ),
                        ));
                    }
                }
            }
        }

        // The Link State Acknowledgment body adds its acknowledged-header count
        // and one `lsa_header` summary per carried LSA header.
        if let OspfBody::LinkStateAck(ack) = &self.body {
            fields.push((
                "lsa_header_count",
                ack.lsa_headers_value().len().to_string(),
            ));
            for header in ack.lsa_headers_value() {
                fields.push(("lsa_header", header.summary()));
            }
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        // The OSPF packet is the 24-octet common header plus the body. When
        // cryptographic authentication is active, `compile()` also appends a
        // keyed-MD5 message-digest trailer after the packet (RFC 2328 §D.3): the
        // trailer is excluded from the OSPF Packet Length field but is part of the
        // emitted bytes, so the enclosing IP payload length must count it.
        let mut len = OSPF_HEADER_LEN + self.body.encoded_len();
        if self.appends_crypto_trailer() {
            len += OSPF_MD5_DIGEST_LEN as usize;
        }
        len
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        // The OSPF Packet Length field covers the common header plus the body. The
        // cryptographic message-digest trailer (if any) is appended after the
        // packet and is deliberately NOT counted here (RFC 2328 §D.3).
        let total_len = OSPF_HEADER_LEN + self.body.encoded_len();

        // Cryptographic authentication (AuType 2, RFC 2328 §D.3) zeroes the header
        // Checksum and appends a keyed-MD5 trailer; null/simple authentication use
        // the standard Internet checksum.
        let crypto = self.crypto_auth_for_trailer();

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
        // For cryptographic authentication the checksum field is left zero and is
        // never auto-filled (RFC 2328 §D.3).
        let pinned_checksum = self.checksum.value().copied();
        out.extend_from_slice(&pinned_checksum.unwrap_or(0).to_be_bytes());

        out.extend_from_slice(&self.autype_value().to_be_bytes());
        out.extend_from_slice(&self.authentication_value());

        // Body bytes follow the 24-octet common header.
        self.body.encode(out);

        if let Some(crypto) = crypto {
            // Cryptographic authentication: the header Checksum stays zero unless
            // the caller pinned a (deliberately malformed) value, and a 16-octet
            // keyed-MD5 digest over the packet-so-far concatenated with the secret
            // key padded to 16 octets is appended after the OSPF packet (RFC 2328
            // §D.3). The digest is excluded from the Packet Length but is part of
            // the emitted bytes, so the enclosing IP payload counts it.
            let digest = crypto.md5_digest(&out[start..]);
            out.extend_from_slice(&digest);
        } else if pinned_checksum.is_none() {
            // Null/simple authentication: auto-fill the standard Internet checksum
            // over the whole packet EXCLUDING the 8-octet authentication field
            // (octets 16..24), computed with the checksum field itself zeroed
            // (RFC 2328 §A.3.1). The placeholder above already wrote zero.
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

/// Render bytes as a continuous lowercase hex string (no separators), used for
/// the authentication field in `inspection_fields()`.
fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

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

    /// `summary()` reads the header at a glance and `inspection_fields()`
    /// exposes a stable `type` entry equal to the type name, so the OSPF common
    /// header is inspectable through `Packet::summary()` and `Packet::show()`.
    #[test]
    fn ospf_summary_and_inspection_expose_the_common_header() {
        let ospf = Ospfv2::new()
            .packet_type(OSPF_TYPE_HELLO)
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0]);

        // The one-line summary carries the type name and router id.
        let summary = ospf.summary();
        assert!(summary.contains("Hello"), "summary missing type name: {summary}");
        assert!(
            summary.contains("192.0.2.1"),
            "summary missing router id: {summary}"
        );

        // `inspection_fields` carries a `type` entry equal to the expected name.
        let fields = ospf.inspection_fields();
        let type_field = fields
            .iter()
            .find(|(name, _)| *name == "type")
            .map(|(_, value)| value.as_str());
        assert_eq!(type_field, Some(ospf_type_name(OSPF_TYPE_HELLO)));
        assert_eq!(type_field, Some("Hello"));

        // Unset length/checksum print as `auto`.
        let length = fields.iter().find(|(name, _)| *name == "length");
        assert_eq!(length.map(|(_, v)| v.as_str()), Some("auto"));
        let checksum = fields.iter().find(|(name, _)| *name == "checksum");
        assert_eq!(checksum.map(|(_, v)| v.as_str()), Some("auto"));
    }

    /// A Hello packet's `summary()` extends the common-header one-liner with the
    /// network mask, DR/BDR, and `neighbors=` count, and `inspection_fields()`
    /// contributes one stable `neighbor` pair per neighbor Router ID, so the
    /// Hello body is inspectable through `Packet::summary()` / `Packet::show()`.
    #[test]
    fn ospf_hello_summary_and_inspection_describe_the_body() {
        let ospf = Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_hello(|h| {
                *h = OspfHello::new()
                    .network_mask(Ipv4Addr::new(255, 255, 255, 0))
                    .designated_router(Ipv4Addr::new(192, 0, 2, 1))
                    .backup_designated_router(Ipv4Addr::new(192, 0, 2, 2))
                    .neighbor(Ipv4Addr::new(192, 0, 2, 3))
                    .neighbor(Ipv4Addr::new(192, 0, 2, 4))
                    .neighbor(Ipv4Addr::new(192, 0, 2, 5));
            });

        // The one-line summary carries the Hello detail: type, mask, DR/BDR, and
        // the neighbor count.
        let summary = ospf.summary();
        assert!(summary.contains("type=Hello"), "summary missing type: {summary}");
        assert!(
            summary.contains("mask=255.255.255.0"),
            "summary missing network mask: {summary}"
        );
        assert!(summary.contains("dr=192.0.2.1"), "summary missing DR: {summary}");
        assert!(
            summary.contains("bdr=192.0.2.2"),
            "summary missing BDR: {summary}"
        );
        assert!(
            summary.contains("neighbors=3"),
            "summary missing neighbor count: {summary}"
        );

        // `inspection_fields` carries the stable Hello pairs, including the
        // neighbor count and one `neighbor` entry per neighbor Router ID.
        let fields = ospf.inspection_fields();
        let value_of = |name: &str| {
            fields
                .iter()
                .find(|(field, _)| *field == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value_of("network_mask"), Some("255.255.255.0"));
        assert_eq!(value_of("designated_router"), Some("192.0.2.1"));
        assert_eq!(value_of("backup_designated_router"), Some("192.0.2.2"));
        assert_eq!(value_of("hello_interval"), Some("10"));
        assert_eq!(value_of("dead_interval"), Some("40"));
        assert_eq!(value_of("priority"), Some("0"));
        assert_eq!(value_of("options"), Some("0x00"));
        assert_eq!(value_of("neighbor_count"), Some("3"));

        // Every neighbor Router ID appears as its own `neighbor` pair.
        let neighbors: Vec<&str> = fields
            .iter()
            .filter(|(field, _)| *field == "neighbor")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(neighbors, vec!["192.0.2.3", "192.0.2.4", "192.0.2.5"]);
    }

    /// A Link State Update packet's `summary()` reports the carried-LSA count
    /// (`lsas=`), and `inspection_fields()` contributes a `lsa_count` pair plus
    /// one `lsa` entry per carried LSA, each combining the LSA header summary with
    /// the body byte length (`body=NB`), so the LSU and its LSAs are inspectable
    /// through `Packet::summary()` / `Packet::show()`.
    #[test]
    fn ospf_link_state_update_summary_and_inspection_describe_each_lsa() {
        use crate::protocols::ospf::lsa::{
            OspfLsa, OspfLsaBody, OspfLsaHeader, OSPF_LSA_NETWORK, OSPF_LSA_ROUTER,
        };

        let router_lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_ROUTER)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 1))
                .advertising_router(Ipv4Addr::new(192, 0, 2, 1)),
            // Six body octets after the 20-octet header.
            OspfLsaBody::Raw(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
        );
        let network_lsa = OspfLsa::new(
            OspfLsaHeader::new()
                .ls_type(OSPF_LSA_NETWORK)
                .link_state_id(Ipv4Addr::new(192, 0, 2, 2))
                .advertising_router(Ipv4Addr::new(198, 51, 100, 7)),
            // Four body octets after the 20-octet header.
            OspfLsaBody::Raw(vec![0xaa, 0xbb, 0xcc, 0xdd]),
        );

        let ospf = Ospfv2::link_state_update()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .with_link_state_update(|u| {
                *u = OspfLinkStateUpdate::new().lsa(router_lsa).lsa(network_lsa);
            });

        // The one-line summary reports the carried-LSA count via `lsas=`.
        let summary = ospf.summary();
        assert!(
            summary.contains("type=LSUpdate"),
            "summary missing type: {summary}"
        );
        assert!(
            summary.contains("lsas=2"),
            "summary missing carried-LSA count: {summary}"
        );

        // `inspection_fields` carries the `lsa_count` pair and one `lsa` entry per
        // carried LSA.
        let fields = ospf.inspection_fields();
        let lsa_count = fields
            .iter()
            .find(|(field, _)| *field == "lsa_count")
            .map(|(_, value)| value.as_str());
        assert_eq!(lsa_count, Some("2"));

        let lsa_entries: Vec<&str> = fields
            .iter()
            .filter(|(field, _)| *field == "lsa")
            .map(|(_, value)| value.as_str())
            .collect();
        // One `lsa` entry per carried LSA.
        assert_eq!(lsa_entries.len(), 2);

        // Each entry combines the LSA header summary with the body byte length.
        assert!(
            lsa_entries[0].contains("type=Router"),
            "first lsa entry missing header summary: {}",
            lsa_entries[0]
        );
        assert!(
            lsa_entries[0].contains("body=6B"),
            "first lsa entry missing body byte length: {}",
            lsa_entries[0]
        );
        assert!(
            lsa_entries[1].contains("type=Network"),
            "second lsa entry missing header summary: {}",
            lsa_entries[1]
        );
        assert!(
            lsa_entries[1].contains("body=4B"),
            "second lsa entry missing body byte length: {}",
            lsa_entries[1]
        );
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

    /// A well-formed OSPF Hello wrapped in IPv4 (protocol 89), decoded through
    /// the default registry (checksum validation on), records
    /// [`OspfChecksumStatus::Valid`] and re-compiles byte-for-byte.
    #[test]
    fn ospf_decode_records_valid_checksum_status() {
        use crate::packet::NetworkLayer;
        use crate::protocols::ip::v4::Ipv4;

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(192, 0, 2, 2))
            / Ospfv2::hello()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0]))
        .compile()
        .expect("Ipv4 / Ospfv2 Hello compiles");

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect("the default registry decodes OSPF over IPv4");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.checksum_status(), OspfChecksumStatus::Valid);

        // The decode-time status is metadata only; the packet still round-trips.
        let recompiled = decoded.compile().expect("decoded OSPF re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// An OSPF packet whose checksum octet is corrupted decodes with
    /// [`OspfChecksumStatus::Invalid`] yet still re-compiles byte-for-byte
    /// (the corrupted checksum is preserved as a user-set field).
    #[test]
    fn ospf_decode_records_invalid_checksum_status() {
        use crate::packet::NetworkLayer;
        use crate::protocols::ip::v4::Ipv4;

        // Build a valid Ipv4 / Ospfv2 Hello, then corrupt one OSPF checksum
        // octet in the assembled bytes. The IPv4 header is 20 octets (no
        // options), so the OSPF checksum field sits at offsets 20+12..20+14.
        let mut raw = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(192, 0, 2, 2))
            / Ospfv2::hello().router_id([192, 0, 2, 1]))
        .compile()
        .expect("Ipv4 / Ospfv2 Hello compiles")
        .as_bytes()
        .to_vec();

        let ipv4_header_len = (raw[0] & 0x0f) as usize * 4;
        let ospf_checksum_octet = ipv4_header_len + 12;
        raw[ospf_checksum_octet] ^= 0xff;
        // Recompute the IPv4 header checksum so only the OSPF checksum is wrong:
        // re-decode then re-compile would refill it, so instead decode the
        // (IP-corrupt-tolerant) buffer directly and assert on the OSPF status.
        // The IPv4 layer reports its own checksum status independently; here we
        // only care that the OSPF layer flags the corrupted OSPF checksum.

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &raw)
            .expect("a corrupted-OSPF-checksum buffer still decodes structurally");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.checksum_status(), OspfChecksumStatus::Invalid);

        // The corrupted checksum is a user-set field, so re-compiling the OSPF
        // layer reproduces the corrupted bytes verbatim.
        let mut ospf_only = Vec::new();
        let recompiled_ospf = Packet::from_layer(ospf.clone())
            .compile()
            .expect("the decoded OSPF layer re-compiles");
        ospf_only.extend_from_slice(recompiled_ospf.as_bytes());
        assert_eq!(&raw[ipv4_header_len..], ospf_only.as_slice());
    }

    /// Decoding through a registry with checksum validation disabled leaves the
    /// OSPF checksum status as [`OspfChecksumStatus::NotChecked`], and the
    /// packet still round-trips byte-for-byte.
    #[test]
    fn ospf_decode_skips_checksum_validation_when_disabled() {
        use crate::packet::NetworkLayer;
        use crate::protocols::ip::v4::Ipv4;
        use crate::registry::ProtocolRegistry;

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(192, 0, 2, 2))
            / Ospfv2::hello().router_id([192, 0, 2, 1]))
        .compile()
        .expect("Ipv4 / Ospfv2 Hello compiles");

        let registry = ProtocolRegistry::new().checksum_validation(false);
        let decoded = registry
            .decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())
            .expect("the registry decodes OSPF over IPv4");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(ospf.checksum_status(), OspfChecksumStatus::NotChecked);

        let recompiled = decoded.compile().expect("decoded OSPF re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }

    /// A Hello built with `simple_password(b"secret")` carries AuType 1 and the
    /// cleartext password right-padded into the 8-octet authentication field
    /// (RFC 2328 §D.2), round-trips byte-for-byte through IPv4 decode, and still
    /// reports a valid checksum (the auth field is excluded from the checksum).
    #[test]
    fn ospf_simple_password_encodes_into_the_auth_field_and_round_trips() {
        use crate::packet::NetworkLayer;
        use crate::protocols::ip::v4::Ipv4;

        let ospf = Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .simple_password(b"secret");

        // AuType is simple password and the 8-octet field is the password
        // right-padded with zeros.
        assert_eq!(ospf.autype_value(), OSPF_AUTYPE_SIMPLE);
        assert_eq!(
            ospf.authentication_value(),
            [b's', b'e', b'c', b'r', b'e', b't', 0, 0]
        );

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(192, 0, 2, 2))
            / ospf)
            .compile()
            .expect("Ipv4 / simple-password Hello compiles");

        // The AuType (octets 14..16 of the OSPF header) and the authentication
        // field (octets 16..24) appear on the wire. The IPv4 header is 20 octets
        // (no options), so the OSPF header starts at offset 20.
        let raw = bytes.as_bytes();
        let ipv4_header_len = (raw[0] & 0x0f) as usize * 4;
        let ospf = ipv4_header_len;
        assert_eq!(&raw[ospf + 14..ospf + 16], &OSPF_AUTYPE_SIMPLE.to_be_bytes());
        assert_eq!(
            &raw[ospf + 16..ospf + 24],
            &[b's', b'e', b'c', b'r', b'e', b't', 0, 0]
        );

        // Decoding through the default registry (checksum validation on) recovers
        // the AuType and authentication field, reports a valid checksum (the auth
        // field is excluded from the OSPF checksum), and re-compiles byte-for-byte.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, raw)
            .expect("the default registry decodes the simple-password Hello");
        let layer = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        assert_eq!(layer.autype_value(), OSPF_AUTYPE_SIMPLE);
        assert_eq!(
            layer.authentication_value(),
            [b's', b'e', b'c', b'r', b'e', b't', 0, 0]
        );
        assert_eq!(layer.checksum_status(), OspfChecksumStatus::Valid);

        let recompiled = decoded.compile().expect("decoded OSPF re-compiles");
        assert_eq!(recompiled.as_bytes(), raw);
    }

    /// A Hello built with `null_auth()` carries AuType 0 and a zero 8-octet
    /// authentication field (RFC 2328 §D.1).
    #[test]
    fn ospf_null_auth_zeroes_the_auth_field() {
        let ospf = Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .null_auth();

        assert_eq!(ospf.autype_value(), OSPF_AUTYPE_NULL);
        assert_eq!(ospf.authentication_value(), [0; OSPF_AUTH_LEN]);

        let bytes = Packet::from_layer(ospf).compile().unwrap();
        // AuType (octets 14..16) and authentication field (octets 16..24) are zero.
        assert_eq!(&bytes[14..16], &OSPF_AUTYPE_NULL.to_be_bytes());
        assert_eq!(&bytes[16..24], &[0u8; OSPF_AUTH_LEN]);
    }

    /// The `autype` inspection field surfaces the AuType name (RFC 2328 §D)
    /// alongside its numeric value, so the authentication type is inspectable
    /// through `Packet::show()`.
    #[test]
    fn ospf_inspection_surfaces_the_autype_name() {
        let ospf = Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .simple_password(b"secret");
        let fields = ospf.inspection_fields();
        let autype = fields
            .iter()
            .find(|(name, _)| *name == "autype")
            .map(|(_, value)| value.as_str());
        assert_eq!(autype, Some("1 (Simple)"));

        let null = Ospfv2::hello().router_id([192, 0, 2, 1]).null_auth();
        let null_autype = null
            .inspection_fields()
            .into_iter()
            .find(|(name, _)| *name == "autype")
            .map(|(_, value)| value);
        assert_eq!(null_autype.as_deref(), Some("0 (Null)"));
    }

    /// A Hello built with `crypto_md5_auth(...)` (AuType 2, RFC 2328 §D.3)
    /// compiles with a zero header Checksum, an OSPF Packet Length equal to the
    /// header+body (excluding the appended digest), the structured 8-octet
    /// authentication field, and a 16-octet keyed-MD5 digest trailer that
    /// recomputing with the same key reproduces.
    #[test]
    fn ospf_crypto_md5_auth_zeroes_checksum_and_appends_digest_trailer() {
        let key = b"ospf-secret-key".to_vec();
        let ospf = Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .crypto_md5_auth(7, 0x0000_002a, key.clone());

        // The AuType is cryptographic and the structured auth field carries the
        // Reserved/Key ID/Auth Data Length/Crypto-sequence layout.
        assert_eq!(ospf.autype_value(), OSPF_AUTYPE_CRYPTOGRAPHIC);
        assert_eq!(
            ospf.authentication_value(),
            [0x00, 0x00, 0x07, OSPF_MD5_DIGEST_LEN, 0x00, 0x00, 0x00, 0x2a]
        );

        // The body-only OSPF packet length (header + Hello body) excludes the
        // 16-octet digest trailer.
        let packet_len = OSPF_HEADER_LEN + ospf.body.encoded_len();

        let bytes = Packet::from_layer(ospf).compile().unwrap();

        // The emitted bytes are the packet plus the 16-octet digest trailer.
        assert_eq!(bytes.len(), packet_len + OSPF_MD5_DIGEST_LEN as usize);

        // The OSPF Packet Length field (octets 2..4) covers only the header+body.
        assert_eq!(&bytes[2..4], &(packet_len as u16).to_be_bytes());

        // The header Checksum field (octets 12..14) is zero for cryptographic
        // authentication (it is not the Internet checksum).
        assert_eq!(&bytes[12..14], &[0u8, 0u8]);

        // The 8-octet authentication field (octets 16..24) is the structured form.
        assert_eq!(
            &bytes[16..24],
            &[0x00, 0x00, 0x07, OSPF_MD5_DIGEST_LEN, 0x00, 0x00, 0x00, 0x2a]
        );

        // The trailing 16 octets are the keyed-MD5 digest. Recomputing the digest
        // over the packet bytes (everything before the trailer) with the same key
        // reproduces the trailer exactly.
        let trailer = &bytes.as_bytes()[packet_len..];
        assert_eq!(trailer.len(), OSPF_MD5_DIGEST_LEN as usize);
        let recomputed =
            OspfCryptoAuth::new(7, 0x0000_002a, key).md5_digest(&bytes.as_bytes()[..packet_len]);
        assert_eq!(trailer, recomputed);
    }

    /// A crypto-authed Hello honors caller overrides: a pinned (deliberately
    /// malformed) Checksum survives instead of being zeroed, and a pinned
    /// authentication field replaces the structured form, while the recorded key
    /// still drives the appended digest trailer.
    #[test]
    fn ospf_crypto_md5_auth_honors_pinned_checksum_and_authentication() {
        let ospf = Ospfv2::hello()
            .router_id([192, 0, 2, 1])
            .area_id([0, 0, 0, 0])
            .crypto_md5_auth(3, 1, b"k".to_vec())
            .checksum(0xbeef)
            .authentication([0xaa; OSPF_AUTH_LEN]);

        let packet_len = OSPF_HEADER_LEN + ospf.body.encoded_len();
        let bytes = Packet::from_layer(ospf).compile().unwrap();

        // The pinned checksum is written verbatim (not zeroed by crypto auth).
        assert_eq!(&bytes[12..14], &0xbeefu16.to_be_bytes());
        // The pinned authentication field is written verbatim.
        assert_eq!(&bytes[16..24], &[0xaau8; OSPF_AUTH_LEN]);
        // The digest trailer is still appended after the packet body.
        assert_eq!(bytes.len(), packet_len + OSPF_MD5_DIGEST_LEN as usize);
    }
}
