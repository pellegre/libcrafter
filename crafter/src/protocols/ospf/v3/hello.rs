//! OSPFv3 Hello packet body (RFC 5340 §A.3.2).
//!
//! The OSPFv3 Hello body follows the 16-octet OSPFv3 common header and carries
//! the parameters routers use to discover and maintain neighbor relationships
//! over IPv6. Unlike the OSPFv2 Hello (RFC 2328 §A.3.2) it carries no Network
//! Mask, the Options field is 24 bits wide, and the HelloInterval and
//! RouterDeadInterval are 16 bits each:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Interface ID                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | Rtr Priority  |                  Options                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        HelloInterval          |       RouterDeadInterval      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   Designated Router ID                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Backup Designated Router ID                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        Neighbor ID                           ...
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The fixed portion is 20 octets, followed by a list of 4-octet neighbor
//! Router IDs. Like the OSPFv2 bodies, [`Ospfv3Hello`] lives inside the
//! [`Ospfv3`](crate::protocols::ospf::Ospfv3) layer as an
//! [`Ospfv3Body::Hello`](crate::protocols::ospf::Ospfv3Body::Hello) variant; its
//! `Field<T>` members let `compile()` honor any value the caller pinned while
//! filling sensible RFC defaults for the rest.

use core::net::Ipv4Addr;

use crate::field::Field;

/// The fixed (pre-neighbor-list) length of the OSPFv3 Hello body, in octets:
/// Interface ID(4) + Rtr Priority(1) + Options(3) + HelloInterval(2) +
/// RouterDeadInterval(2) + Designated Router ID(4) + Backup Designated Router
/// ID(4). RFC 5340 §A.3.2.
const OSPFV3_HELLO_FIXED_LEN: usize = 20;

/// Mask selecting the low 24 bits of the OSPFv3 Options field (RFC 5340 §A.2):
/// the field is encoded as three octets on the wire.
const OSPFV3_OPTIONS_MASK: u32 = 0x00ff_ffff;

/// Default HelloInterval, in seconds (RFC 5340 §A.3.2, mirroring RFC 2328 §C.3).
const OSPFV3_HELLO_DEFAULT_HELLO_INTERVAL: u16 = 10;

/// Default RouterDeadInterval, in seconds (four hello intervals; RFC 2328 §C.3).
const OSPFV3_HELLO_DEFAULT_DEAD_INTERVAL: u16 = 40;

/// OSPFv3 Hello packet body (RFC 5340 §A.3.2).
///
/// Carries the Interface ID, Router Priority, 24-bit Options, HelloInterval,
/// RouterDeadInterval, Designated Router ID, Backup Designated Router ID, and
/// the list of neighbor Router IDs. Each scalar field is a [`Field`] so
/// `compile()` fills the ones the caller left unset (sensible RFC defaults)
/// while preserving anything set explicitly, including wrong-on-purpose values.
#[derive(Debug, Clone)]
pub struct Ospfv3Hello {
    /// Interface ID of the originating interface (RFC 5340 §A.3.2); defaults to 0.
    interface_id: Field<u32>,
    /// Router Priority used in DR election; defaults to 0 (RFC 5340 §A.3.2).
    router_priority: Field<u8>,
    /// Optional capabilities (RFC 5340 §A.2), 24-bit; defaults to 0. Only the
    /// low 24 bits are emitted on the wire.
    options: Field<u32>,
    /// HelloInterval, in seconds; defaults to 10 (RFC 5340 §A.3.2).
    hello_interval: Field<u16>,
    /// RouterDeadInterval, in seconds; defaults to 40 (RFC 5340 §A.3.2).
    router_dead_interval: Field<u16>,
    /// Designated Router ID for the link; defaults to the unspecified address.
    designated_router: Field<Ipv4Addr>,
    /// Backup Designated Router ID; defaults to the unspecified address.
    backup_designated_router: Field<Ipv4Addr>,
    /// Neighbor Router IDs heard from on this interface (RFC 5340 §A.3.2).
    neighbors: Vec<Ipv4Addr>,
}

impl Ospfv3Hello {
    /// Build an OSPFv3 Hello body with RFC defaults: Interface ID 0, Router
    /// Priority 0, Options 0, HelloInterval 10, RouterDeadInterval 40, the
    /// DR/BDR left unset (emitted as the unspecified address), and an empty
    /// neighbor list.
    pub fn new() -> Self {
        Self {
            interface_id: Field::defaulted(0),
            router_priority: Field::defaulted(0),
            options: Field::defaulted(0),
            hello_interval: Field::defaulted(OSPFV3_HELLO_DEFAULT_HELLO_INTERVAL),
            router_dead_interval: Field::defaulted(OSPFV3_HELLO_DEFAULT_DEAD_INTERVAL),
            designated_router: Field::unset(),
            backup_designated_router: Field::unset(),
            neighbors: Vec::new(),
        }
    }

    /// Set the Interface ID field (RFC 5340 §A.3.2).
    pub fn interface_id(mut self, interface_id: u32) -> Self {
        self.interface_id.set_user(interface_id);
        self
    }

    /// Set the Router Priority field used in DR election.
    pub fn router_priority(mut self, router_priority: u8) -> Self {
        self.router_priority.set_user(router_priority);
        self
    }

    /// Set the Options field (RFC 5340 §A.2 capability bits, 24-bit). Only the
    /// low 24 bits are emitted on the wire.
    pub fn options(mut self, options: u32) -> Self {
        self.options.set_user(options);
        self
    }

    /// Set the HelloInterval field, in seconds.
    pub fn hello_interval(mut self, hello_interval: u16) -> Self {
        self.hello_interval.set_user(hello_interval);
        self
    }

    /// Set the RouterDeadInterval field, in seconds.
    pub fn router_dead_interval(mut self, router_dead_interval: u16) -> Self {
        self.router_dead_interval.set_user(router_dead_interval);
        self
    }

    /// Set the Designated Router ID field.
    pub fn designated_router(mut self, designated_router: impl Into<Ipv4Addr>) -> Self {
        self.designated_router.set_user(designated_router.into());
        self
    }

    /// Set the Backup Designated Router ID field.
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

    /// The effective Interface ID (the caller value, else 0).
    pub fn interface_id_value(&self) -> u32 {
        self.interface_id.value().copied().unwrap_or(0)
    }

    /// The effective Router Priority (the caller value, else 0).
    pub fn router_priority_value(&self) -> u8 {
        self.router_priority.value().copied().unwrap_or(0)
    }

    /// The effective Options field, masked to the low 24 bits emitted on the
    /// wire (the caller value, else 0).
    pub fn options_value(&self) -> u32 {
        self.options.value().copied().unwrap_or(0) & OSPFV3_OPTIONS_MASK
    }

    /// The effective HelloInterval (the caller value, else the default 10).
    pub fn hello_interval_value(&self) -> u16 {
        self.hello_interval
            .value()
            .copied()
            .unwrap_or(OSPFV3_HELLO_DEFAULT_HELLO_INTERVAL)
    }

    /// The effective RouterDeadInterval (the caller value, else the default 40).
    pub fn router_dead_interval_value(&self) -> u16 {
        self.router_dead_interval
            .value()
            .copied()
            .unwrap_or(OSPFV3_HELLO_DEFAULT_DEAD_INTERVAL)
    }

    /// The effective Designated Router ID (the caller value, else the
    /// unspecified address).
    pub fn designated_router_value(&self) -> Ipv4Addr {
        self.designated_router
            .value()
            .copied()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
    }

    /// The effective Backup Designated Router ID (the caller value, else the
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
        OSPFV3_HELLO_FIXED_LEN + self.neighbors.len() * 4
    }

    /// Append the RFC 5340 §A.3.2 Hello body to `out`: the fixed 20 octets in
    /// big-endian (with the Options field packed into 3 octets after the
    /// 1-octet Router Priority), then each neighbor Router ID (4 octets each).
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.interface_id_value().to_be_bytes());
        out.push(self.router_priority_value());
        // Options is a 24-bit field: emit the low 24 bits as three big-endian
        // octets, after the 1-octet Router Priority.
        let options = self.options_value();
        out.push(((options >> 16) & 0xff) as u8);
        out.push(((options >> 8) & 0xff) as u8);
        out.push((options & 0xff) as u8);
        out.extend_from_slice(&self.hello_interval_value().to_be_bytes());
        out.extend_from_slice(&self.router_dead_interval_value().to_be_bytes());
        out.extend_from_slice(&self.designated_router_value().octets());
        out.extend_from_slice(&self.backup_designated_router_value().octets());
        for neighbor in &self.neighbors {
            out.extend_from_slice(&neighbor.octets());
        }
    }
}

impl Default for Ospfv3Hello {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NetworkLayer, Packet};
    use crate::protocols::ip::v6::Ipv6;
    use crate::protocols::ospf::{Ospfv3, OSPFV3_HEADER_LEN, OSPFV3_TYPE_HELLO};
    use core::net::Ipv6Addr;

    /// An OSPFv3 Hello built with two neighbors over IPv6 encodes to the exact
    /// RFC 5340 §A.3.2 layout — including the 24-bit Options packed into three
    /// octets after the 1-octet Router Priority — and round-trips byte-for-byte
    /// through a compile/decode cycle. Uses `2001:db8::/32` documentation
    /// addresses and OSPF documentation router IDs.
    #[test]
    fn ospfv3_hello_body_compiles_and_round_trips_with_two_neighbors() {
        // The fixed 20 octets plus two 4-octet neighbors encode to the
        // hand-computed RFC 5340 §A.3.2 layout. Options 0x000013 exercises the
        // 24-bit packing (only the low three octets are emitted).
        let hello = Ospfv3Hello::new()
            .interface_id(0x0000_0005)
            .router_priority(1)
            .options(0x00ff_0013)
            .hello_interval(10)
            .router_dead_interval(40)
            .designated_router(Ipv4Addr::new(192, 0, 2, 1))
            .backup_designated_router(Ipv4Addr::new(192, 0, 2, 2))
            .neighbor(Ipv4Addr::new(192, 0, 2, 3))
            .neighbor(Ipv4Addr::new(192, 0, 2, 4));

        // The Options accessor masks to the low 24 bits emitted on the wire.
        assert_eq!(hello.options_value(), 0x00ff_0013);

        let mut body = Vec::new();
        hello.encode(&mut body);
        assert_eq!(hello.encoded_len(), OSPFV3_HELLO_FIXED_LEN + 2 * 4);
        assert_eq!(body.len(), hello.encoded_len());

        // Hand-computed RFC 5340 §A.3.2 layout: no Network Mask, 24-bit Options,
        // 16-bit intervals.
        let expected: Vec<u8> = vec![
            // Interface ID 0x00000005
            0x00, 0x00, 0x00, 0x05, // Rtr Priority 1
            0x01, // Options (24-bit) 0xff0013 -> 0xff, 0x00, 0x13
            0xff, 0x00, 0x13, // HelloInterval 10
            0x00, 0x0a, // RouterDeadInterval 40
            0x00, 0x28, // Designated Router 192.0.2.1
            192, 0, 2, 1, // Backup Designated Router 192.0.2.2
            192, 0, 2, 2, // Neighbor 192.0.2.3
            192, 0, 2, 3, // Neighbor 192.0.2.4
            192, 0, 2, 4,
        ];
        assert_eq!(body, expected);

        // The Hello rides inside an Ospfv3 layer over IPv6; the compiled packet
        // exposes the Hello body bytes after the 16-octet common header.
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();

        let bytes = (Ipv6::new().src(src).dst(dst)
            / Ospfv3::hello()
                .router_id([192, 0, 2, 1])
                .area_id([0, 0, 0, 0])
                .with_hello(|h| *h = hello.clone()))
        .compile()
        .expect("Ipv6 / Ospfv3 Hello compiles");

        // The compiled packet decodes through the default registry and
        // re-compiles byte-for-byte. The OSPFv3 layer carries the Hello type
        // code; the Hello body bytes follow the 16-octet common header verbatim.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes())
            .expect("the default registry decodes the OSPFv3 Hello over IPv6");
        let ospfv3 = decoded
            .layer::<Ospfv3>()
            .expect("the decoded packet exposes a typed Ospfv3 layer");
        assert_eq!(ospfv3.packet_type_value(), OSPFV3_TYPE_HELLO);

        // The 24-octet IPv6 header precedes the OSPFv3 packet; the OSPFv3 body
        // (after its 16-octet common header) equals the hand-computed Hello.
        let ospfv3_start = bytes.as_bytes().len() - (OSPFV3_HEADER_LEN + expected.len());
        let body_start = ospfv3_start + OSPFV3_HEADER_LEN;
        assert_eq!(&bytes.as_bytes()[body_start..], expected.as_slice());

        let recompiled = decoded.compile().expect("the decoded OSPFv3 Hello re-compiles");
        assert_eq!(recompiled.as_bytes(), bytes.as_bytes());
    }
}
