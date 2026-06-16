//! Public-surface baseline test for the RIPng layer.
//!
//! Pins that the RIPng types added in steps 31-41 are reachable through
//! `crafter::prelude::*` and slot into the standard packet abstraction: build
//! with the public builders, compose under UDP/IPv6 with `/`, `compile()` to
//! wire bytes, and round-trip decode back to a `Ripng` layer. Stays fully
//! offline and uses documentation address space (`2001:db8::/32`).

use std::net::Ipv6Addr;

use crafter::prelude::*;

#[test]
fn ripng_public_api_builds_via_prelude() -> crafter::Result<()> {
    // Build a RIPng Response through the prelude surface: `Ripng` and
    // `RipngRte` are both re-exported by the prelude.
    let ripng = Ripng::response().rte(RipngRte::route(
        "2001:db8::".parse::<Ipv6Addr>().expect("valid prefix"),
        32,
        1,
    ));

    assert_eq!(ripng.command(), RipCommand::Response);
    assert_eq!(ripng.version_value(), RIPNG_VERSION_1);
    assert_eq!(ripng.rtes().len(), 1);

    // Compose under UDP/IPv6 using `/` and compile to wire bytes.
    let packet = Ipv6::new()
        .src("2001:db8::1".parse::<Ipv6Addr>().expect("valid source"))
        .dst(RIPNG_MULTICAST)
        / Udp::new().sport(RIPNG_UDP_PORT).dport(RIPNG_UDP_PORT)
        / ripng;

    let compiled = packet.compile()?;
    assert!(
        !compiled.as_bytes().is_empty(),
        "compiled RIPng packet must have a non-empty byte buffer"
    );

    // The conservative UDP/521 binding round-trips the payload back to a
    // `Ripng` layer reachable through the prelude.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;
    let decoded_ripng = decoded
        .layer::<Ripng>()
        .expect("decoded packet includes a Ripng layer");
    assert_eq!(decoded_ripng.command(), RipCommand::Response);
    assert_eq!(decoded_ripng.rtes().len(), 1);

    Ok(())
}
