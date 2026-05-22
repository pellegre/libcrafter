mod common;

use common::{
    arg_or, flag_present, print_help_if_requested, print_send_report, send_options, ExampleResult,
};
use crafter::prelude::*;
use std::net::Ipv6Addr;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ipv6_routing_header -- [--dry-run] [--live] [--iface IFACE]\n\nBuild an IPv6 segment routing header packet. The default is dry-run.",
    ) {
        return Ok(());
    }

    let live = flag_present("--live");
    let iface = arg_or("--iface", "dry-run0");
    let mut hmac = [0u8; 32];
    hmac[15] = 0xff;
    let routing = Ipv6SegmentRoutingHeader::new()
        .push_ipv6_segment("2001:db8:1234::2")?
        .push_ipv6_segment("2001:db8:1234::3")?
        .push_ipv6_segment("2001:db8:1234::4")?
        .policy_flag1(IPV6_SEGMENT_POLICY_SOURCE_ADDRESS)
        .policy_str(3, "dead:beef::", IPV6_SEGMENT_POLICY_EGRESS)?
        .pflag(true)
        .hmac_key_id(5)
        .hmac(hmac);
    let packet = Ipv6::new()
        .src("2001:db8:dead:beef:cafe::".parse::<Ipv6Addr>()?)
        .dst("2001:db8:1234::1".parse::<Ipv6Addr>()?)
        / routing
        / Tcp::new().sport(1234).dport(80).flags(TCP_FLAG_SYN)
        / Raw::from("segment-route");
    let report = packet.send(send_options(&iface, live, false))?;

    print_send_report("ipv6_routing_header", &packet, &report);

    Ok(())
}
