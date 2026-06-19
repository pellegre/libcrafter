//! Build, inspect, and decode OSPFv2 packets entirely offline.
//!
//! This example constructs three OSPFv2 messages over IPv4 using documentation
//! address space (`192.0.2.0/24`, `198.51.100.0/24`) and the `AllSPFRouters`
//! multicast destination `224.0.0.5`:
//!
//! 1. a Hello packet (Type 1),
//! 2. a Database Description packet (Type 2), and
//! 3. a Link State Update (Type 4) carrying a Router-LSA.
//!
//! For each packet it prints `summary()`, `show()`, and `hexdump()`, decodes the
//! compiled bytes back through `Packet::decode_from_l3`, and asserts a
//! byte-for-byte round-trip (the re-decoded packet recompiles to the same bytes).
//!
//! It never opens a socket or sends live traffic: it only builds, compiles,
//! decodes, and inspects bytes in memory.
//!
//! The OSPF message layers (`Ospfv2`) and inspection constants come from
//! `crafter::prelude::*`; the OSPF body and LSA construction types live under
//! `crafter::protocols::ospf` and are imported by their module path, mirroring
//! the OSPF guide (`docs/guide/ospf.md`).

mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;
use crafter::protocols::ospf::lsa::{
    OspfLsa, OspfLsaBody, OspfLsaHeader, OspfRouterLink, OspfRouterLsa, OSPF_LSA_ROUTER,
    OSPF_ROUTER_LINK_POINT_TO_POINT, OSPF_ROUTER_LINK_STUB,
};
use crafter::protocols::ospf::packet::{OspfDatabaseDescription, OspfHello, OspfLinkStateUpdate};
use std::net::Ipv4Addr;

/// Documentation-safe OSPF router ID / source address.
const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// Backbone area `0.0.0.0`.
const AREA_ID: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
/// `AllSPFRouters` multicast destination.
const ALL_SPF_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 5);

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ospf_packets\n\nBuild an OSPFv2 Hello, a Database Description, and a Link State Update with a\nRouter-LSA over IPv4 using documentation addresses, print summary/show/hexdump,\ndecode each back, and assert a byte-for-byte round-trip. Offline only.",
    ) {
        return Ok(());
    }

    println!("example: ospf_packets (offline only, documentation address space)");

    inspect_and_round_trip("Hello", hello())?;
    inspect_and_round_trip("Database Description", database_description())?;
    inspect_and_round_trip("Link State Update (Router-LSA)", link_state_update())?;

    println!("\nall OSPF packets round-tripped byte-for-byte");
    Ok(())
}

/// Build an OSPFv2 Hello (Type 1) over IPv4.
fn hello() -> Packet {
    Ipv4::new().src(ROUTER_ID).dst(ALL_SPF_ROUTERS)
        / Ospfv2::hello()
            .router_id(ROUTER_ID)
            .area_id(AREA_ID)
            .hello_body(
                OspfHello::new()
                    .network_mask(Ipv4Addr::new(255, 255, 255, 0))
                    .hello_interval(10)
                    .router_dead_interval(40)
                    .router_priority(1)
                    .designated_router(ROUTER_ID)
                    .neighbors([Ipv4Addr::new(192, 0, 2, 2)]),
            )
}

/// Build an OSPFv2 Database Description (Type 2) over IPv4.
fn database_description() -> Packet {
    Ipv4::new().src(ROUTER_ID).dst(ALL_SPF_ROUTERS)
        / Ospfv2::database_description()
            .router_id(ROUTER_ID)
            .area_id(AREA_ID)
            .database_description_body(
                OspfDatabaseDescription::new()
                    .interface_mtu(1500)
                    .dd_sequence_number(0x0000_4242)
                    .init(true)
                    .more(true)
                    .master(true),
            )
}

/// Build an OSPFv2 Link State Update (Type 4) carrying a Router-LSA over IPv4.
fn link_state_update() -> Packet {
    let router = OspfRouterLsa::new()
        .border()
        .link(OspfRouterLink::new(
            Ipv4Addr::new(192, 0, 2, 2),
            Ipv4Addr::new(198, 51, 100, 1),
            OSPF_ROUTER_LINK_POINT_TO_POINT,
            10,
        ))
        .link(OspfRouterLink::new(
            Ipv4Addr::new(198, 51, 100, 0),
            Ipv4Addr::new(255, 255, 255, 0),
            OSPF_ROUTER_LINK_STUB,
            20,
        ));

    let lsa = OspfLsa::new(
        OspfLsaHeader::new()
            .ls_type(OSPF_LSA_ROUTER)
            .link_state_id(ROUTER_ID)
            .advertising_router(ROUTER_ID),
        OspfLsaBody::Router(router),
    );

    Ipv4::new().src(ROUTER_ID).dst(ALL_SPF_ROUTERS)
        / Ospfv2::link_state_update()
            .router_id(ROUTER_ID)
            .area_id(AREA_ID)
            .link_state_update_body(OspfLinkStateUpdate::new().lsa(lsa))
}

/// Compile `packet`, print its inspection output, decode it back from IPv4, and
/// assert the re-decoded packet recompiles to the same bytes.
fn inspect_and_round_trip(label: &str, packet: Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;

    println!("\n=== {label} ===");
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());
    println!("hexdump:\n{}", compiled.hexdump());

    // Decode the compiled bytes back through the default registry (IPv4
    // protocol 89 decodes as OSPFv2), then recompile and compare byte-for-byte.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let recompiled = decoded.compile()?;

    if recompiled.as_bytes() != compiled.as_bytes() {
        return Err(format!(
            "{label}: round-trip mismatch ({} built bytes vs {} re-decoded bytes)",
            compiled.as_bytes().len(),
            recompiled.as_bytes().len(),
        )
        .into());
    }

    let ospf = decoded
        .layer::<Ospfv2>()
        .expect("decoded OSPF packet should contain an Ospfv2 layer");
    println!(
        "round-trip: ok ({} bytes); decoded type {} ({})",
        compiled.as_bytes().len(),
        ospf.packet_type_value(),
        ospf_type_name(ospf.packet_type_value()),
    );

    Ok(())
}
