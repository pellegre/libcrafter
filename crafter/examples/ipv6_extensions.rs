mod common;

use common::{local_ipv6, print_help_if_requested, remote_ipv6, ExampleResult};
use crafter::prelude::*;

const UNKNOWN_NEXT_HEADER: u8 = 143;

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example ipv6_extensions --\n\nBuild and decode IPv6 traffic class, flow-label, options, routing, segment-routing, fragment, and raw-fallback packets offline.",
    ) {
        return Ok(());
    }

    println!("example: ipv6_extensions");
    println!("mode: offline");

    inspect_ipv6_packet("traffic class, flow label, and options", &options_packet()?)?;
    inspect_ipv6_packet("generic routing header", &generic_routing_packet())?;
    inspect_ipv6_packet("segment routing header", &segment_routing_packet()?)?;
    inspect_ipv6_packet("non-initial fragment header", &fragment_header_packet())?;
    inspect_ipv6_packet("no-next-header raw fallback", &no_next_header_packet())?;
    inspect_ipv6_packet("unknown-next-header raw fallback", &unknown_next_packet())?;

    Ok(())
}

fn options_packet() -> ExampleResult<Packet> {
    let destination_options = Ipv6DestinationOptionsHeader::new()
        .option(Ipv6Option::home_address_str("2001:db8::99")?)
        .option(Ipv6Option::generic(0x22, [0xab, 0xcd])?);

    Ok(Ipv6::new()
        .src(local_ipv6())
        .dst(remote_ipv6())
        .dscp(Dscp::ef())
        .ecn(Ecn::ce())
        .try_flow_label(0x12345)?
        .hop_limit(32)
        / Ipv6HopByHopOptionsHeader::new()
            .option(Ipv6Option::router_alert(IPV6_ROUTER_ALERT_MLD))
            .option(Ipv6Option::padn(2)?)
        / destination_options
        / Udp::new().sport(5353).dport(5353)
        / Raw::from("options"))
}

fn generic_routing_packet() -> Packet {
    Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / Ipv6RoutingHeader::new()
            .routing_type(IPV6_ROUTING_TYPE_RPL)
            .segments_left(1)
            .type_data([0xde, 0xad, 0xbe, 0xef])
        / Udp::new().sport(40000).dport(40001)
        / Raw::from("routing")
}

fn segment_routing_packet() -> ExampleResult<Packet> {
    let routing = Ipv6SegmentRoutingHeader::new()
        .push_ipv6_segment("2001:db8::30")?
        .push_ipv6_segment("2001:db8::40")?
        .segleft(1)
        .first_segment(1)
        .pflag(true)
        .tag(0x1001)
        .raw_trailing_data([0x00]);

    Ok(Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / routing
        / Tcp::new()
            .sport(41000)
            .dport(443)
            .seq(1)
            .flags(TCP_FLAG_SYN)
        / Raw::from("segment-route"))
}

fn fragment_header_packet() -> Packet {
    Ipv6::new().src(local_ipv6()).dst(remote_ipv6())
        / Ipv6FragmentHeader::new()
            .next_header(IPPROTO_UDP)
            .fragment_offset(2)
            .identification(0x0102_0304)
        / Raw::from("later-fragment")
}

fn no_next_header_packet() -> Packet {
    Ipv6::new()
        .src(local_ipv6())
        .dst(remote_ipv6())
        .next_header(IPPROTO_IPV6_NO_NEXT)
        / Raw::from_bytes([0x6e, 0x6f, 0x2d, 0x6e, 0x65, 0x78, 0x74])
}

fn unknown_next_packet() -> Packet {
    Ipv6::new()
        .src(local_ipv6())
        .dst(remote_ipv6())
        .next_header(UNKNOWN_NEXT_HEADER)
        / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef])
}

fn inspect_ipv6_packet(label: &str, packet: &Packet) -> ExampleResult<()> {
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, compiled.as_bytes())?;

    println!();
    println!("packet: {label}");
    println!("decoded summary: {}", decoded.summary());
    print_ipv6_fields(&decoded);
    print_options_headers(&decoded);
    print_routing_headers(&decoded);
    print_fragment_header(&decoded);
    print_raw_fallback(&decoded);
    println!("compiled len: {}", compiled.len());

    Ok(())
}

fn print_ipv6_fields(packet: &Packet) {
    if let Some(ipv6) = packet.layer::<Ipv6>() {
        println!(
            "ipv6: traffic_class=0x{:02x} dscp={} ecn={} flow_label=0x{:05x} hop_limit={} next_header={}",
            ipv6.traffic_class_value(),
            ipv6.dscp_value().value(),
            ipv6.ecn_value().value(),
            ipv6.flow_label_value(),
            ipv6.hop_limit_value(),
            ipv6.next_header_value()
        );
    }
}

fn print_options_headers(packet: &Packet) {
    if let Some(hop_by_hop) = packet.layer::<Ipv6HopByHopOptionsHeader>() {
        println!(
            "hop-by-hop: next_header={} options=[{}]",
            hop_by_hop.next_header_value(),
            option_summaries(hop_by_hop.options_value())
        );
    }
    if let Some(destination) = packet.layer::<Ipv6DestinationOptionsHeader>() {
        println!(
            "destination-options: next_header={} options=[{}]",
            destination.next_header_value(),
            option_summaries(destination.options_value())
        );
    }
}

fn print_routing_headers(packet: &Packet) {
    if let Some(routing) = packet.layer::<Ipv6RoutingHeader>() {
        println!(
            "routing: type={} label={} status={:?} segments_left={} data={}",
            routing.routing_type_value(),
            routing.routing_type_label(),
            routing.routing_type_status(),
            routing.segments_left_value(),
            hex_bytes(routing.type_data_bytes())
        );
    }
    if let Some(routing) = packet.layer::<Ipv6SegmentRoutingHeader>() {
        println!(
            "srh: segments_left={} last_entry={} p_flag={} flags=0x{:02x} tag=0x{:04x}",
            routing.segments_left_value(),
            routing.last_entry_value(),
            routing.p_flag_value(),
            routing.flags_value(),
            routing.tag_value()
        );
        println!("srh segments: {:?}", routing.segments());
        println!(
            "srh trailing data: {}",
            hex_bytes(routing.raw_trailing_data_bytes())
        );
    }
}

fn print_fragment_header(packet: &Packet) {
    if let Some(fragment) = packet.layer::<Ipv6FragmentHeader>() {
        println!(
            "fragment: status={} offset_units={} offset_bytes={} more={} id=0x{:08x} reserved_zero={}",
            fragment.fragment_status_label(),
            fragment.fragment_offset_value(),
            fragment.fragment_offset_bytes(),
            fragment.has_more_fragments(),
            fragment.identification_value(),
            fragment.reserved_fields_are_zero()
        );
    }
}

fn print_raw_fallback(packet: &Packet) {
    if packet.layer::<Tcp>().is_some()
        || packet.layer::<Udp>().is_some()
        || packet.layer::<Icmpv6>().is_some()
    {
        return;
    }

    if let Some(raw) = packet.layer::<Raw>() {
        println!(
            "raw fallback: len={} bytes={}",
            raw.len(),
            hex_bytes(raw.as_bytes())
        );
    }
}

fn option_summaries(options: &[Ipv6Option]) -> String {
    options
        .iter()
        .map(option_summary)
        .collect::<Vec<_>>()
        .join("; ")
}

fn option_summary(option: &Ipv6Option) -> String {
    let mut details = format!(
        "type=0x{:02x} action={:?} change={} data={}",
        option.option_type(),
        option.action(),
        option.change_en_route(),
        hex_bytes(option.data())
    );
    if let Some(value) = option.router_alert_value() {
        details.push_str(&format!(
            " router_alert={}({})",
            value,
            option.router_alert_value_label().unwrap_or("unknown")
        ));
    }
    if let Some(length) = option.jumbo_payload_length() {
        details.push_str(&format!(" jumbo_payload_len={length}"));
    }
    if let Some(address) = option.home_address_value() {
        details.push_str(&format!(" home_address={address}"));
    }
    details
}

fn hex_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "empty".to_string();
    }

    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
