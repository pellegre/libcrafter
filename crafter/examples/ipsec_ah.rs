//! Build and verify an AH-protected transport datagram entirely offline.
//!
//! This example crafts `Ipv4 / Ah::secured(sa) / Tcp / Raw` in transport mode
//! with an integrity-only (HMAC-SHA-256-128) security association. AH never
//! encrypts: it authenticates the canonicalized immutable IP fields, the AH
//! header with its ICV field zeroed, and the cleartext upper-layer data
//! (RFC 4302). The example compiles the datagram, inspects it through
//! `summary()` / `show()` / `hexdump()`, then decodes it twice: once with the
//! default SA-less registry (the AH header is typed but unverified) and once
//! with a registry carrying the matching SA (the ICV is re-verified and a
//! verified status is recorded).
//!
//! Everything is offline: no interface is opened and no packet is transmitted.
//! All addresses are documentation address space (RFC 5737) and the key is a
//! fixed repeated byte — never real key material.
//!
//! Run it with:
//!
//! ```text
//! cargo run --example ipsec_ah
//! ```

use std::net::Ipv4Addr;

use crafter::prelude::*;

/// Documentation-safe source / destination pair (RFC 5737).
const DOC_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DOC_DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);

/// The documentation SPI carried by both the SA and the AH header.
const AH_SPI: u32 = 0x0000_3100;

/// A fixed 32-octet HMAC-SHA-256 integrity key (documentation-only).
fn hmac_key() -> Vec<u8> {
    vec![0x33u8; 32]
}

/// Build the fixed integrity-only HMAC-SHA-256-128 transport-mode SA.
fn ah_security_association() -> SecurityAssociation {
    SecurityAssociation::new(AH_SPI)
        .integrity(IntegrityAlgorithm::HmacSha2_256_128, hmac_key())
        .transport()
        .extended_sequence(false)
}

fn main() -> Result<()> {
    let sa = ah_security_association();
    assert!(sa.validate().is_ok(), "documentation AH SA validates");
    assert_eq!(sa.mode, IpsecMode::Transport);

    // Build a transport-mode AH datagram. AH only authenticates, so the TCP / Raw
    // upper layers travel in the clear; the enclosing IPv4 advertises AH (51).
    let packet: Packet = Ipv4::new()
        .src(DOC_SRC)
        .dst(DOC_DST)
        .protocol(IPPROTO_AH)
        .ttl(64)
        / Ah::secured(sa.clone()).spi(AH_SPI).sequence(1)
        / Tcp::new().sport(43000).dport(443)
        / Raw::from("ah-example");

    let compiled = packet.compile()?;

    println!("example: ipsec_ah");
    println!("mode: offline");
    println!("documentation address pair: {DOC_SRC} -> {DOC_DST}");
    println!("suite: HMAC-SHA-256-128 (integrity-only), transport mode");
    println!("summary: {}", packet.summary());
    println!("show:\n{}", packet.show());
    println!("compiled bytes: {}", compiled.len());
    println!("hexdump:\n{}", compiled.hexdump());

    let wire = compiled.as_bytes().to_vec();
    // The IPv4 protocol field (offset 9) advertises AH; the AH Next Header
    // (offset 20) names the protected upper layer (TCP, 6) in transport mode.
    assert_eq!(wire[9], IPPROTO_AH, "outer IPv4 advertises AH");
    assert_eq!(wire[20], IPPROTO_TCP, "AH Next Header is TCP in transport");

    // Decode with the default registry: AH is typed but unverified (no SA).
    let opaque = Packet::decode_from_l3(NetworkLayer::Ipv4, &wire)?;
    let opaque_ah = opaque.layer::<Ah>().expect("typed AH header recovered");
    println!();
    println!("decode (no SA): {}", opaque.summary());
    println!(
        "  spi: {:#010x}",
        opaque_ah.spi_value().expect("SPI is exposed")
    );
    println!(
        "  icv bytes: {}",
        opaque_ah
            .icv_value()
            .map(<[u8]>::len)
            .expect("ICV is captured")
    );
    println!(
        "  verification status: {:?} (no SA in the registry)",
        opaque_ah.verification_status()
    );

    // Decode with a registry carrying the SA: the ICV is re-verified over the
    // canonicalized IP header, the zeroed AH header, and the cleartext payload.
    let registry = ProtocolRegistry::new().with_security_association(sa);
    let decoded = Packet::decode_from_l3_with_registry(&registry, NetworkLayer::Ipv4, &wire)?;
    let ah = decoded.layer::<Ah>().expect("typed AH recovered with SA");
    println!();
    println!("decode (with SA): {}", decoded.summary());
    println!("  spi: {:#010x}", ah.spi_value().expect("SPI is exposed"));
    println!(
        "  next header: {}",
        ah.next_header_value().expect("Next Header is exposed")
    );
    let verified = ah.verification_status();
    println!("  verification status: {verified:?}");
    assert_eq!(verified, Some(true), "matching SA verifies the AH ICV");

    let tcp = decoded.layer::<Tcp>().expect("protected TCP in the clear");
    println!(
        "  inner tcp: {} -> {}",
        tcp.source_port_value(),
        tcp.destination_port_value()
    );

    Ok(())
}
