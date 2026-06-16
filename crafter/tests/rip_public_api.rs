//! Public-surface baseline test for the RIP layer.
//!
//! Pins that the RIP types added in steps 03-17 are reachable through
//! `crafter::prelude::*` and slot into the standard packet abstraction: build
//! with the public builders, compose under UDP/IPv4 with `/`, and `compile()`
//! to wire bytes. Stays fully offline and uses documentation address space.

use std::net::Ipv4Addr;

use crafter::prelude::*;

const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

#[test]
fn rip_public_api_builds_via_prelude() -> crafter::Result<()> {
    // Build a RIP version 2 whole-table request through the prelude surface:
    // `Rip`, `RipEntry`, and `RipCommand` are all re-exported by the prelude.
    let rip = Rip::request().entry(RipEntry::whole_table_request());

    assert_eq!(rip.command(), RipCommand::Request);
    assert_eq!(rip.version_value(), RIP_VERSION_2);
    assert_eq!(rip.entries().len(), 1);

    // Compose under UDP/IPv4 using `/` and compile to wire bytes.
    let packet = Ipv4::new().src(DOC_SRC).dst(DOC_DST)
        / Udp::new().sport(RIP_UDP_PORT).dport(RIP_UDP_PORT)
        / rip;

    let compiled = packet.compile()?;
    assert!(
        !compiled.as_bytes().is_empty(),
        "compiled RIP packet must have a non-empty byte buffer"
    );

    Ok(())
}
