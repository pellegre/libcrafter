mod common;

use common::{flag_present, print_help_if_requested, ExampleResult, EXAMPLE_IFACE};
use crafter::prelude::*;
use crafter::protocols::rip::{
    rip_v2_multicast_response, verify, RipAuth, RipAuthVerification, RipDigestAlgorithm,
};
use std::net::Ipv4Addr;

/// Documentation-range source address for the RIP speaker (192.0.2.0/24).
const RIP_SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
/// First advertised route prefix (198.51.100.0/24).
const ROUTE_ONE_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 0);
/// Second advertised route prefix (198.51.100.128/25).
const ROUTE_TWO_NETWORK: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 128);
/// /24 subnet mask for the first advertised route.
const MASK_24: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
/// /25 subnet mask for the second advertised route.
const MASK_25: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 128);

/// Clearly test-only simple-password key (RFC 2453 §4.1). Documentation/example
/// secret only — never a real credential.
const SIMPLE_PASSWORD: &[u8] = b"rip-doc-pass";
/// Clearly test-only keyed-message-digest key (RFC 2082 / RFC 4822 §3).
/// Documentation/example secret only — never a real credential.
const DIGEST_KEY: &[u8] = b"rip-doc-md5-key";
/// Key Identifier carried in the keyed-digest authentication entry.
const DIGEST_KEY_ID: u8 = 1;
/// A different, wrong key used to demonstrate that verification rejects it.
const WRONG_KEY: &[u8] = b"rip-wrong-key";

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example rip_auth -- [--send]\n\nBuild a RIPv2 response authenticated with a simple password and a second response authenticated with a keyed message digest (the digest is auto-computed on compile()), inspect their dry-run send plans, and verify each against the correct key (OK) and a wrong key (mismatch). All addresses are documentation space and all keys are clearly test-only. Offline by default; --send is reserved for an explicit, gated live path and is not enabled in this example.",
    ) {
        return Ok(());
    }

    // The live path is opt-in only. Even when requested we refuse to place real
    // RIP traffic on the wire from this example: real sends must originate from a
    // provider-backed endpoint or lab session, not the developer machine.
    if flag_present("--send") {
        eprintln!(
            "refusing live send: rip_auth is an offline example; \
             run RIP against a provider-backed routing daemon via the probe/lab runners instead"
        );
        return Err("live RIP send is not enabled in this example".into());
    }

    println!("example: rip_auth");
    println!("mode: dry-run");
    println!("source: {RIP_SOURCE}");

    // Two advertised documentation-range routes reused by both authenticated
    // responses (RFC 2453 per-entry route tag, subnet mask, metric).
    let route_entries = || {
        vec![
            RipEntry::ipv2_route(ROUTE_ONE_NETWORK, MASK_24, 1).with_route_tag(64512),
            RipEntry::ipv2_route(ROUTE_TWO_NETWORK, MASK_25, 2).with_route_tag(64513),
        ]
    };

    // 1. Simple-password authentication (RFC 2453 §4.1): the leading AFI-0xFFFF
    //    entry carries the 16-octet plaintext password. Attach it to a RIPv2
    //    multicast response and compile.
    let simple = rip_v2_multicast_response(RIP_SOURCE, route_entries())
        .replace_rip_auth(RipAuth::simple_password(SIMPLE_PASSWORD), SIMPLE_PASSWORD);
    print_plan(
        "simple-password",
        "RIPv2 response with simple-password authentication",
        &simple,
    )?;
    report_verification(
        "simple-password",
        &simple,
        SIMPLE_PASSWORD,
        WRONG_KEY,
        RipAuthVerification::SimplePasswordOk,
        RipAuthVerification::SimplePasswordMismatch,
    )?;

    // 2. Keyed message-digest authentication (RFC 2082 Keyed-MD5): the leading
    //    AFI-0xFFFF entry carries the digest header and a trailing block carries
    //    the digest. The digest is left unset so compile() auto-computes it from
    //    DIGEST_KEY, demonstrating "fill what the caller did not set".
    let keyed = rip_v2_multicast_response(RIP_SOURCE, route_entries()).replace_rip_auth(
        RipAuth::keyed_digest_with(RipDigestAlgorithm::KeyedMd5, DIGEST_KEY_ID),
        DIGEST_KEY,
    );
    print_plan(
        "keyed-digest",
        "RIPv2 response with keyed message-digest authentication (digest auto-computed)",
        &keyed,
    )?;
    report_verification(
        "keyed-digest",
        &keyed,
        DIGEST_KEY,
        WRONG_KEY,
        RipAuthVerification::DigestOk,
        RipAuthVerification::DigestMismatch,
    )?;

    Ok(())
}

/// Helper trait providing a small adapter to attach RIPv2 authentication to a
/// pre-built `Ipv4 / Udp / Rip` packet returned by the multicast convenience.
trait RipAuthPacketExt {
    /// Replace the packet's `Rip` layer with an authenticated copy carrying
    /// `auth` (compiled with `key`).
    fn replace_rip_auth(self, auth: RipAuth, key: &[u8]) -> Packet;
}

impl RipAuthPacketExt for Packet {
    fn replace_rip_auth(mut self, auth: RipAuth, key: &[u8]) -> Packet {
        let authenticated = self
            .layer::<Rip>()
            .cloned()
            .expect("multicast response carries a Rip layer")
            .auth(auth, key.to_vec());
        if let Some(rip) = self.layer_mut::<Rip>() {
            *rip = authenticated;
        }
        self
    }
}

fn print_plan(label: &str, description: &str, packet: &Packet) -> ExampleResult<()> {
    let plan = packet.send_dry_run(SendOptions::new().iface(EXAMPLE_IFACE).network_layer())?;

    println!();
    println!("{label}: {description}");
    println!("summary: {}", packet.summary());
    println!("interface: {}", plan.interface());
    println!("target: {:?}", plan.target());
    println!("compiled bytes: {}", plan.len());
    println!("show:\n{}", packet.show());
    println!("hexdump:\n{}", plan.compiled_packet().hexdump());
    Ok(())
}

fn report_verification(
    label: &str,
    packet: &Packet,
    correct_key: &[u8],
    wrong_key: &[u8],
    expected_ok: RipAuthVerification,
    expected_mismatch: RipAuthVerification,
) -> ExampleResult<()> {
    // The verification helper operates on the RIP message bytes (the UDP
    // payload), not the IP/UDP framing. Compile just the Rip layer to obtain the
    // exact on-wire RIP message — including the auto-computed digest — that a
    // receiver would feed to verify().
    let rip = packet
        .layer::<Rip>()
        .cloned()
        .ok_or("packet is missing its Rip layer")?;
    let compiled = Packet::from_layer(rip).compile()?;
    let message = compiled.as_bytes();

    let with_correct = verify(message, correct_key);
    let with_wrong = verify(message, wrong_key);

    println!();
    println!("{label}: verification");
    println!("correct key -> {with_correct:?}");
    println!("wrong key   -> {with_wrong:?}");

    // The example must run to completion offline; assert the documented outcomes
    // so a regression in the auth path fails the example rather than passing
    // silently.
    if with_correct != expected_ok {
        return Err(format!(
            "{label}: expected {expected_ok:?} for the correct key, got {with_correct:?}"
        )
        .into());
    }
    if with_wrong != expected_mismatch {
        return Err(format!(
            "{label}: expected {expected_mismatch:?} for the wrong key, got {with_wrong:?}"
        )
        .into());
    }

    Ok(())
}
