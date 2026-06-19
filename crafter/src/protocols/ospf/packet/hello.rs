//! OSPFv2 Hello packet body (RFC 2328 §A.3.2).
//!
//! The Hello body follows the 24-octet common header and carries the
//! parameters routers use to discover and maintain neighbor relationships:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Network Mask                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         HelloInterval         |    Options    |    Rtr Pri    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     RouterDeadInterval                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Designated Router                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Backup Designated Router                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Neighbor                            ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The fixed portion is 20 octets, followed by a list of 4-octet neighbor
//! Router IDs. Like the other bodies, [`OspfHello`] lives inside the
//! [`Ospfv2`](crate::protocols::ospf::Ospfv2) layer as an
//! [`OspfBody::Hello`](crate::protocols::ospf::OspfBody::Hello) variant; its
//! `Field<T>` members let `compile()` honor any value the caller pinned while
//! filling sensible RFC defaults for the rest.

use core::net::Ipv4Addr;

use crate::field::Field;
use crate::protocols::ospf::constants::{OSPF_OPTIONS_E, OSPF_OPTIONS_O};

/// The fixed (pre-neighbor-list) length of the Hello body, in octets:
/// Network Mask(4) + HelloInterval(2) + Options(1) + Rtr Pri(1) +
/// RouterDeadInterval(4) + Designated Router(4) + Backup Designated Router(4).
const OSPF_HELLO_FIXED_LEN: usize = 20;

/// Default HelloInterval, in seconds (RFC 2328 §C.3).
const OSPF_HELLO_DEFAULT_HELLO_INTERVAL: u16 = 10;

/// Default RouterDeadInterval, in seconds (RFC 2328 §C.3, four hello intervals).
const OSPF_HELLO_DEFAULT_DEAD_INTERVAL: u32 = 40;

/// OSPFv2 Hello packet body (RFC 2328 §A.3.2).
///
/// Carries the Network Mask, HelloInterval, Options, Router Priority,
/// RouterDeadInterval, Designated Router, Backup Designated Router, and the
/// list of neighbor Router IDs. Each scalar field is a [`Field`] so `compile()`
/// fills the ones the caller left unset (sensible RFC defaults) while
/// preserving anything set explicitly, including wrong-on-purpose values.
#[derive(Debug, Clone)]
pub struct OspfHello {
    /// Network Mask of the originating interface (RFC 2328 §A.3.2).
    network_mask: Field<Ipv4Addr>,
    /// HelloInterval, in seconds; defaults to 10 (RFC 2328 §A.3.2).
    hello_interval: Field<u16>,
    /// Optional capabilities (RFC 2328 §A.2); defaults to 0.
    options: Field<u8>,
    /// Router Priority used in DR election; defaults to 0 (RFC 2328 §A.3.2).
    router_priority: Field<u8>,
    /// RouterDeadInterval, in seconds; defaults to 40 (RFC 2328 §A.3.2).
    router_dead_interval: Field<u32>,
    /// Designated Router for the network; defaults to the unspecified address.
    designated_router: Field<Ipv4Addr>,
    /// Backup Designated Router; defaults to the unspecified address.
    backup_designated_router: Field<Ipv4Addr>,
    /// Neighbor Router IDs heard from on this interface (RFC 2328 §A.3.2).
    neighbors: Vec<Ipv4Addr>,
}

impl OspfHello {
    /// Build a Hello body with RFC defaults: HelloInterval 10,
    /// RouterDeadInterval 40, Options and Router Priority 0, the Network Mask
    /// and DR/BDR left unset (emitted as the unspecified address), and an empty
    /// neighbor list.
    pub fn new() -> Self {
        Self {
            network_mask: Field::unset(),
            hello_interval: Field::defaulted(OSPF_HELLO_DEFAULT_HELLO_INTERVAL),
            options: Field::defaulted(0),
            router_priority: Field::defaulted(0),
            router_dead_interval: Field::defaulted(OSPF_HELLO_DEFAULT_DEAD_INTERVAL),
            designated_router: Field::unset(),
            backup_designated_router: Field::unset(),
            neighbors: Vec::new(),
        }
    }

    /// Construct a Hello body from decoded wire fields, marking every scalar
    /// field as caller-supplied so re-compilation preserves the decoded values
    /// byte-for-byte.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_decoded_parts(
        network_mask: Ipv4Addr,
        hello_interval: u16,
        options: u8,
        router_priority: u8,
        router_dead_interval: u32,
        designated_router: Ipv4Addr,
        backup_designated_router: Ipv4Addr,
        neighbors: Vec<Ipv4Addr>,
    ) -> Self {
        Self {
            network_mask: Field::user(network_mask),
            hello_interval: Field::user(hello_interval),
            options: Field::user(options),
            router_priority: Field::user(router_priority),
            router_dead_interval: Field::user(router_dead_interval),
            designated_router: Field::user(designated_router),
            backup_designated_router: Field::user(backup_designated_router),
            neighbors,
        }
    }

    /// Set the Network Mask field.
    pub fn network_mask(mut self, network_mask: impl Into<Ipv4Addr>) -> Self {
        self.network_mask.set_user(network_mask.into());
        self
    }

    /// Set the HelloInterval field, in seconds.
    pub fn hello_interval(mut self, hello_interval: u16) -> Self {
        self.hello_interval.set_user(hello_interval);
        self
    }

    /// Set the Options field (RFC 2328 §A.2 capability bits).
    pub fn options(mut self, options: u8) -> Self {
        self.options.set_user(options);
        self
    }

    /// Toggle the E-bit ([`OSPF_OPTIONS_E`],
    /// 0x02) in the Options field (RFC 2328 §A.2): when set the router accepts
    /// and forwards AS-External-LSAs. Leaves the other Options bits untouched.
    pub fn external_capable(mut self, external_capable: bool) -> Self {
        self.set_options_bit(OSPF_OPTIONS_E, external_capable);
        self
    }

    /// Toggle the O-bit ([`OSPF_OPTIONS_O`],
    /// 0x40) in the Options field (RFC 5250 §2.1): when set the router is
    /// opaque-LSA capable. Leaves the other Options bits untouched.
    pub fn opaque_capable(mut self, opaque_capable: bool) -> Self {
        self.set_options_bit(OSPF_OPTIONS_O, opaque_capable);
        self
    }

    /// Set or clear a single Options bit, marking the Options field as
    /// caller-supplied while preserving the other bits.
    fn set_options_bit(&mut self, bit: u8, set: bool) {
        let mut options = self.options_value();
        if set {
            options |= bit;
        } else {
            options &= !bit;
        }
        self.options.set_user(options);
    }

    /// Set the Router Priority field used in DR election.
    pub fn router_priority(mut self, router_priority: u8) -> Self {
        self.router_priority.set_user(router_priority);
        self
    }

    /// Set the RouterDeadInterval field, in seconds.
    pub fn router_dead_interval(mut self, router_dead_interval: u32) -> Self {
        self.router_dead_interval.set_user(router_dead_interval);
        self
    }

    /// Set the Designated Router field.
    pub fn designated_router(mut self, designated_router: impl Into<Ipv4Addr>) -> Self {
        self.designated_router.set_user(designated_router.into());
        self
    }

    /// Set the Backup Designated Router field.
    pub fn backup_designated_router(
        mut self,
        backup_designated_router: impl Into<Ipv4Addr>,
    ) -> Self {
        self.backup_designated_router
            .set_user(backup_designated_router.into());
        self
    }

    /// Append a single neighbor Router ID to the Hello's neighbor list.
    pub fn neighbor(mut self, neighbor: impl Into<Ipv4Addr>) -> Self {
        self.neighbors.push(neighbor.into());
        self
    }

    /// Append several neighbor Router IDs to the Hello's neighbor list.
    pub fn neighbors<I, A>(mut self, neighbors: I) -> Self
    where
        I: IntoIterator<Item = A>,
        A: Into<Ipv4Addr>,
    {
        self.neighbors.extend(neighbors.into_iter().map(Into::into));
        self
    }

    /// The effective Network Mask (the caller value, else the unspecified
    /// address).
    pub fn network_mask_value(&self) -> Ipv4Addr {
        self.network_mask
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The effective HelloInterval (the caller value, else the default 10).
    pub fn hello_interval_value(&self) -> u16 {
        self.hello_interval
            .value()
            .copied()
            .unwrap_or(OSPF_HELLO_DEFAULT_HELLO_INTERVAL)
    }

    /// The effective Options field (the caller value, else 0).
    pub fn options_value(&self) -> u8 {
        self.options.value().copied().unwrap_or(0)
    }

    /// The effective Router Priority (the caller value, else 0).
    pub fn router_priority_value(&self) -> u8 {
        self.router_priority.value().copied().unwrap_or(0)
    }

    /// The effective RouterDeadInterval (the caller value, else the default 40).
    pub fn router_dead_interval_value(&self) -> u32 {
        self.router_dead_interval
            .value()
            .copied()
            .unwrap_or(OSPF_HELLO_DEFAULT_DEAD_INTERVAL)
    }

    /// The effective Designated Router (the caller value, else the unspecified
    /// address).
    pub fn designated_router_value(&self) -> Ipv4Addr {
        self.designated_router
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The effective Backup Designated Router (the caller value, else the
    /// unspecified address).
    pub fn backup_designated_router_value(&self) -> Ipv4Addr {
        self.backup_designated_router
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The neighbor Router IDs heard from on this interface.
    pub fn neighbors_value(&self) -> &[Ipv4Addr] {
        &self.neighbors
    }

    /// The on-wire length of this Hello body, in octets: the fixed 20 octets
    /// plus 4 octets per neighbor Router ID.
    pub(crate) fn encoded_len(&self) -> usize {
        OSPF_HELLO_FIXED_LEN + self.neighbors.len() * 4
    }

    /// Append the RFC 2328 §A.3.2 Hello body to `out`: the fixed 20 octets in
    /// big-endian, then each neighbor Router ID (4 octets each).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.network_mask_value().octets());
        out.extend_from_slice(&self.hello_interval_value().to_be_bytes());
        out.push(self.options_value());
        out.push(self.router_priority_value());
        out.extend_from_slice(&self.router_dead_interval_value().to_be_bytes());
        out.extend_from_slice(&self.designated_router_value().octets());
        out.extend_from_slice(&self.backup_designated_router_value().octets());
        for neighbor in &self.neighbors {
            out.extend_from_slice(&neighbor.octets());
        }
    }
}

impl Default for OspfHello {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Hello body built with two neighbors compiles to the exact RFC 2328
    /// §A.3.2 layout, and the enclosing OSPF packet length covers the 24-octet
    /// common header plus the Hello body.
    #[test]
    fn ospf_hello_body_compiles_with_two_neighbors() {
        use crate::packet::{Layer, Packet};
        use crate::protocols::ospf::{Ospfv2, OSPF_HEADER_LEN};

        let hello = OspfHello::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .hello_interval(10)
            .options(0x02)
            .router_priority(1)
            .router_dead_interval(40)
            .designated_router(Ipv4Addr::new(192, 0, 2, 1))
            .backup_designated_router(Ipv4Addr::new(192, 0, 2, 2))
            .neighbor(Ipv4Addr::new(192, 0, 2, 3))
            .neighbor(Ipv4Addr::new(192, 0, 2, 4));

        // The body encodes to the fixed 20 octets plus two 4-octet neighbors.
        let mut body = Vec::new();
        hello.encode(&mut body);
        assert_eq!(hello.encoded_len(), OSPF_HELLO_FIXED_LEN + 2 * 4);
        assert_eq!(body.len(), hello.encoded_len());

        // Hand-computed RFC 2328 §A.3.2 layout.
        let expected: Vec<u8> = vec![
            // Network Mask 255.255.255.0
            0xff, 0xff, 0xff, 0x00, // HelloInterval 10
            0x00, 0x0a, // Options 0x02
            0x02, // Rtr Pri 1
            0x01, // RouterDeadInterval 40
            0x00, 0x00, 0x00, 0x28, // Designated Router 192.0.2.1
            192, 0, 2, 1, // Backup Designated Router 192.0.2.2
            192, 0, 2, 2, // Neighbor 192.0.2.3
            192, 0, 2, 3, // Neighbor 192.0.2.4
            192, 0, 2, 4,
        ];
        assert_eq!(body, expected);

        // The Hello rides inside an Ospfv2 layer; the compiled packet's Packet
        // Length field (octets 2..4) covers the common header plus the body.
        let ospf = Ospfv2::hello().with_hello(|h| {
            *h = hello.clone();
        });
        let bytes = Packet::from_layer(ospf).compile().expect("Hello compiles");

        let total = OSPF_HEADER_LEN + body.len();
        assert_eq!(bytes.len(), total);
        assert_eq!(&bytes[2..4], &(total as u16).to_be_bytes());
        // The header Type octet carries the Hello type code.
        assert_eq!(bytes[1], crate::protocols::ospf::OSPF_TYPE_HELLO);
        // The body bytes follow the 24-octet header verbatim.
        assert_eq!(&bytes[OSPF_HEADER_LEN..], expected.as_slice());

        // `Layer::encoded_len` agrees with the emitted length.
        let layer = Ospfv2::hello().with_hello(|h| *h = hello);
        assert_eq!(layer.encoded_len(), total);
    }

    /// The `external_capable` / `opaque_capable` convenience setters toggle the
    /// individual Options bits (RFC 2328 §A.2 E-bit 0x02, RFC 5250 O-bit 0x40)
    /// without disturbing the others, and a Hello built with
    /// `external_capable(true)` sets bit 0x02 on the wire and round-trips
    /// byte-for-byte through a compile/decode cycle.
    #[test]
    fn ospf_hello_external_capable_sets_options_bit_and_round_trips() {
        use crate::packet::Packet;
        use crate::protocols::ospf::constants::{OSPF_OPTIONS_E, OSPF_OPTIONS_O};
        use crate::protocols::ospf::decode::append_ospf_packet;
        use crate::protocols::ospf::{OspfBody, Ospfv2, OSPF_HEADER_LEN};

        // The convenience setters toggle just their own bit, preserving the rest.
        let hello = OspfHello::new().external_capable(true).opaque_capable(true);
        assert_eq!(
            hello.options_value(),
            OSPF_OPTIONS_E | OSPF_OPTIONS_O,
            "both convenience setters compose without clobbering each other"
        );
        // Clearing one bit leaves the other untouched.
        let cleared = hello.clone().external_capable(false);
        assert_eq!(cleared.options_value(), OSPF_OPTIONS_O);

        // A Hello with just external_capable(true) sets the E-bit (0x02).
        let hello = OspfHello::new()
            .network_mask(Ipv4Addr::new(255, 255, 255, 0))
            .external_capable(true)
            .neighbor(Ipv4Addr::new(192, 0, 2, 3));
        assert_eq!(hello.options_value() & OSPF_OPTIONS_E, OSPF_OPTIONS_E);

        let bytes = Packet::from_layer(
            Ospfv2::hello()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_hello(|h| *h = hello.clone()),
        )
        .compile()
        .expect("a Hello with external_capable compiles");

        // The Options octet (the 3rd octet of the 20-octet Hello fixed portion,
        // after Network Mask(4) + HelloInterval(2)) carries the E-bit on the
        // wire.
        let options_octet = bytes.as_bytes()[OSPF_HEADER_LEN + 6];
        assert_eq!(options_octet & OSPF_OPTIONS_E, OSPF_OPTIONS_E);

        // The packet decodes to a typed Hello whose Options expose the E-bit.
        let decoded =
            append_ospf_packet(Packet::new(), bytes.as_bytes()).expect("the Hello decodes");
        let ospf = decoded
            .layer::<Ospfv2>()
            .expect("the decoded packet exposes a typed Ospfv2 layer");
        let decoded_hello = match &ospf.body {
            OspfBody::Hello(hello) => hello,
            other => panic!("expected a typed Hello body, got {other:?}"),
        };
        assert_eq!(
            decoded_hello.options_value() & OSPF_OPTIONS_E,
            OSPF_OPTIONS_E
        );

        // The decoded Hello re-compiles byte-for-byte.
        let recompiled = decoded.compile().expect("the decoded Hello re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }
}
