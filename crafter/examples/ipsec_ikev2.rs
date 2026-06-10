//! Build, inspect, and decode an IKE_SA_INIT message entirely offline.
//!
//! This example crafts the minimal first message of the IKEv2 exchange
//! (RFC 7296 §1.2) — `IkeHeader / SA / KE / Ni` — carried over UDP/500, compiles
//! it to wire bytes, prints the layer tree through `summary()` / `show()` /
//! `hexdump()`, then decodes it from L3. UDP/500 routes to IKEv2, the Next
//! Payload chain produces one typed layer per payload, and the auto-filled IKE
//! message length and Next Payload codepoints round-trip byte-for-byte.
//!
//! Everything is offline: no interface is opened and no packet is transmitted.
//! All addresses are documentation address space (RFC 5737) and the nonce / key
//! exchange bytes are fixed placeholders — never real cryptographic material.
//!
//! Run it with:
//!
//! ```text
//! cargo run --example ipsec_ikev2
//! ```

use std::net::Ipv4Addr;

use crafter::prelude::*;

/// Documentation-safe source / destination pair (RFC 5737).
const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

/// UDP port 500, the IKEv2 well-known port (RFC 7296 §2).
const IKE_UDP_PORT: u16 = 500;

/// Build an `IKE_SA_INIT` initiator message: `IkeHeader / SA / KE / Ni`.
fn ike_sa_init_packet() -> Packet {
    // One IKE proposal carrying a single ENCR transform (AES-128) plus a D-H
    // group transform; codepoints are illustrative for the wire round-trip.
    let proposal = Proposal::new(1, PROTOCOL_ID_IKE)
        .with_transform(
            Transform::new(TRANSFORM_TYPE_ENCR, 20)
                .with_attribute(TransformAttribute::key_length(128)),
        )
        .with_transform(Transform::new(TRANSFORM_TYPE_DH, DH_GROUP_MODP_2048));
    let sa = IkeSaPayload::new().with_proposal(proposal);
    let ke = IkeKePayload::new(DH_GROUP_MODP_2048, vec![0xAB; 32]);
    let ni = IkeNoncePayload::new(vec![0x5A; 16]);

    let header = IkeHeader::new()
        .initiator_spi(0x0102_0304_0506_0708)
        .exchange(IKE_SA_INIT)
        .initiator();

    Ipv4::new().src(DOC_SRC).dst(DOC_DST).protocol(IPPROTO_UDP)
        / Udp::new().sport(IKE_UDP_PORT).dport(IKE_UDP_PORT)
        / header
        / sa
        / ke
        / ni
}

fn main() -> Result<()> {
    let packet = ike_sa_init_packet();
    let compiled = packet.compile()?;

    println!("example: ipsec_ikev2");
    println!("mode: offline");
    println!("documentation address pair: {DOC_SRC} -> {DOC_DST}");
    println!("exchange: IKE_SA_INIT over UDP/{IKE_UDP_PORT}");
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());
    println!("compiled bytes: {}", compiled.len());
    println!("hexdump:\n{}", compiled.hexdump());

    let wire = compiled.as_bytes().to_vec();
    // The enclosing IPv4 advertises UDP (17); both UDP ports are 500.
    assert_eq!(wire[9], IPPROTO_UDP, "outer IPv4 advertises UDP");
    assert_eq!(&wire[20..22], &IKE_UDP_PORT.to_be_bytes());
    assert_eq!(&wire[22..24], &IKE_UDP_PORT.to_be_bytes());

    // Decode from L3. UDP/500 routes to IKEv2 and the Next Payload chain decodes
    // into one typed layer per payload, all reachable via `crafter::prelude::*`.
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    println!();
    println!("decode: {}", decoded.summary());

    let header = decoded
        .layer::<IkeHeader>()
        .expect("decoded IKE header present");
    println!(
        "  initiator spi: {:#018x}",
        header.initiator_spi_value().expect("initiator SPI exposed")
    );
    println!(
        "  exchange type: {} (IKE_SA_INIT)",
        header.exchange_type_value().expect("exchange type exposed")
    );
    println!(
        "  first payload: {} (SA)",
        header.next_payload_value().expect("next payload exposed")
    );

    assert!(
        decoded.layer::<IkeSaPayload>().is_some(),
        "SA payload decodes"
    );
    let ke = decoded.layer::<IkeKePayload>().expect("KE payload decodes");
    println!("  ke dh group: {}", ke.dh_group_num());
    assert!(
        decoded.layer::<IkeNoncePayload>().is_some(),
        "Nonce payload decodes"
    );

    // Re-compiling the decoded message reproduces the wire bytes exactly,
    // including the auto-filled IKE message length and Next Payload chain.
    let recompiled = decoded.compile()?;
    assert_eq!(
        recompiled.as_bytes(),
        wire.as_slice(),
        "the decoded IKE_SA_INIT message re-compiles byte-for-byte"
    );
    println!(
        "  re-compile: byte-for-byte identical ({} bytes)",
        wire.len()
    );

    Ok(())
}
