mod common;

use common::{local_ipv4, parse_ipv4_arg, print_help_if_requested, remote_ipv4, ExampleResult};
use crafter::prelude::*;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example icmpv4_error -- [--src IPv4] [--dst IPv4]\n\nBuild a documentation-safe ICMPv4 time-exceeded error that quotes the\noffending datagram and carries an RFC 4884 / RFC 4950 MPLS extension object,\nthen compile and decode it offline.",
    ) {
        return Ok(());
    }

    let src = parse_ipv4_arg("--src", local_ipv4())?;
    let dst = parse_ipv4_arg("--dst", remote_ipv4())?;

    // The original datagram that exceeded its TTL, quoted back to its sender.
    let offending = Ipv4::new().src(dst).dst(src).ttl(1)
        / Udp::new().sport(33434).dport(33435)
        / Raw::from("traceroute-probe");

    // Time-exceeded (type 11, code 0) error carrying the quoted datagram and a
    // single-label MPLS extension object (RFC 4884 framing, RFC 4950 object).
    let packet = Ipv4::new().src(src).dst(dst)
        / Icmpv4::time_exceeded().code(ICMP_CODE_TIME_EXCEEDED_TTL)
        / Icmpv4QuotedIp::new(offending)
        / IcmpExtension::new()
        / IcmpExtensionObject::new()
        / IcmpExtensionMpls::new().label(16000).exp(0).ttl(64);

    // compile() auto-fills the ICMP checksum, the RFC 4884 length and zero
    // padding, the extension checksum, the MPLS bottom-of-stack bit, and the
    // IPv4 length/protocol fields. Nothing set above is overwritten.
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    let icmp = decoded
        .layer::<Icmpv4>()
        .expect("decoded ICMPv4 error should contain Icmpv4");
    let mpls = decoded
        .layer::<IcmpExtensionMpls>()
        .expect("decoded packet should contain the MPLS extension object");

    println!("example: icmpv4_error");
    println!("source: {src}");
    println!("destination: {dst}");
    println!("decoded summary: {}", decoded.summary());
    println!(
        "icmp checksum: {}",
        icmp.checksum_value()
            .map(|checksum| format!("0x{checksum:04x}"))
            .unwrap_or_else(|| "not decoded".to_string())
    );
    println!(
        "quoted datagram present: {}",
        decoded.layer::<Icmpv4QuotedIp>().is_some()
    );
    println!(
        "mpls label/ttl/bottom: {} / {} / {}",
        mpls.label_value(),
        mpls.ttl_value(),
        mpls.bottom_of_stack_value()
            .map(|set| set.to_string())
            .unwrap_or_else(|| "auto".to_string())
    );
    println!("show:\n{}", decoded.show());
    println!("hexdump:\n{}", compiled.hexdump());

    Ok(())
}
