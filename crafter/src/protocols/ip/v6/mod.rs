//! IPv6 base header and IPv6 extension header implementations.

mod constants;
mod display;
mod extension;
mod header;
mod options;

use core::net::Ipv6Addr;
use core::str::FromStr;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext, Packet, Raw};
use crate::protocols::icmp::Icmpv6;
use crate::protocols::ip::shared::{IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
use crate::protocols::transport::{Tcp, Udp};
use crate::registry::ProtocolRegistry;

pub use constants::{
    IPPROTO_IPV6_AH, IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_ESP, IPPROTO_IPV6_EXPERIMENTAL_1,
    IPPROTO_IPV6_EXPERIMENTAL_2, IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HIP, IPPROTO_IPV6_HOPOPTS,
    IPPROTO_IPV6_MOBILITY, IPPROTO_IPV6_NO_NEXT, IPPROTO_IPV6_ROUTE, IPPROTO_IPV6_SHIM6,
    IPV6_MOBILE_ROUTING_HEADER_EXT_LEN, IPV6_MOBILE_ROUTING_RESERVED,
    IPV6_MOBILE_ROUTING_SEGMENTS_LEFT, IPV6_OPTION_HOME_ADDRESS, IPV6_OPTION_JUMBO_PAYLOAD,
    IPV6_OPTION_PAD1, IPV6_OPTION_PADN, IPV6_OPTION_ROUTER_ALERT,
    IPV6_ROUTER_ALERT_ACTIVE_NETWORKS, IPV6_ROUTER_ALERT_MLD, IPV6_ROUTER_ALERT_MPLS_OAM,
    IPV6_ROUTER_ALERT_RESERVED, IPV6_ROUTER_ALERT_RSVP, IPV6_ROUTING_TYPE_CRH16,
    IPV6_ROUTING_TYPE_CRH32, IPV6_ROUTING_TYPE_EXPERIMENTAL_1, IPV6_ROUTING_TYPE_EXPERIMENTAL_2,
    IPV6_ROUTING_TYPE_MOBILE, IPV6_ROUTING_TYPE_NIMROD, IPV6_ROUTING_TYPE_RESERVED,
    IPV6_ROUTING_TYPE_RH0, IPV6_ROUTING_TYPE_RPL, IPV6_ROUTING_TYPE_SEGMENT,
    IPV6_ROUTING_TYPE_SOURCE_ROUTE, IPV6_SEGMENT_POLICY_EGRESS, IPV6_SEGMENT_POLICY_INGRESS,
    IPV6_SEGMENT_POLICY_SOURCE_ADDRESS, IPV6_SEGMENT_POLICY_UNSET,
};
use constants::{IPV6_HEADER_LEN, IPV6_MAX_FLOW_LABEL};
pub use display::{
    ipv6_fragment_header_status_label, ipv6_routing_type_label, ipv6_routing_type_status,
};
use extension::{
    decode_destination_options_header, decode_fragment_header, decode_hop_by_hop_header,
    decode_routing_header, DecodedRoutingHeader,
};
pub use extension::{
    Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6FragmentHeaderStatus,
    Ipv6HopByHopOptionsHeader, Ipv6MobileRoutingHeader, Ipv6MobileRoutingHeaderStatus,
    Ipv6RoutingHeader, Ipv6RoutingTypeStatus, Ipv6SegmentRoutingHeader,
};
pub use header::Ipv6;
pub use options::{ipv6_router_alert_value_label, Ipv6Option, Ipv6OptionAction, Ipv6OptionIter};

/// Append a decoded IPv6 packet using an explicit registry.
pub(crate) fn append_ipv6_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let (ipv6, payload, rest) = decode_ipv6_parts(bytes)?;
    append_ipv6_payload_with_registry(registry, packet.push(ipv6), payload, rest)
}

fn decode_ipv6_parts(bytes: &[u8]) -> Result<(Ipv6, &[u8], &[u8])> {
    if bytes.len() < IPV6_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv6 header",
            IPV6_HEADER_LEN,
            bytes.len(),
        ));
    }

    let version_class_flow = read_u32_be(&bytes[0..4])?;
    let version = (version_class_flow >> 28) as u8;
    if version != 6 {
        return Err(CrafterError::invalid_field_value(
            "ipv6.version",
            "IPv6 packets must have version 6",
        ));
    }

    let payload_length = read_u16_be(&bytes[4..6])? as usize;
    let total_length = IPV6_HEADER_LEN + payload_length;
    if bytes.len() < total_length {
        return Err(CrafterError::buffer_too_short(
            "ipv6 packet",
            total_length,
            bytes.len(),
        ));
    }

    let ipv6 = Ipv6 {
        version: Field::user(version),
        traffic_class: Field::user(((version_class_flow >> 20) & 0xff) as u8),
        flow_label: Field::user(version_class_flow & IPV6_MAX_FLOW_LABEL),
        payload_length: Field::user(payload_length as u16),
        next_header: Field::user(bytes[6]),
        hop_limit: Field::user(bytes[7]),
        source: Field::user(Ipv6Addr::from(copy_array_16(&bytes[8..24]))),
        destination: Field::user(Ipv6Addr::from(copy_array_16(&bytes[24..40]))),
    };

    Ok((
        ipv6,
        &bytes[IPV6_HEADER_LEN..total_length],
        &bytes[total_length..],
    ))
}

fn append_ipv6_payload_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    payload: &[u8],
    rest: &[u8],
) -> Result<Packet> {
    let next_header = packet
        .layer::<Ipv6>()
        .map(Ipv6::next_header_value)
        .unwrap_or_default();

    packet = append_ipv6_next_with_registry(registry, packet, next_header, payload)?;

    if !rest.is_empty() {
        packet = packet.push(Raw::from_bytes(rest));
    }

    Ok(packet)
}

fn append_ipv6_next_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    mut next_header: u8,
    mut payload: &[u8],
) -> Result<Packet> {
    loop {
        match next_header {
            IPPROTO_IPV6_HOPOPTS => {
                let (hop_by_hop, inner_next_header, remaining) = decode_hop_by_hop_header(payload)?;
                packet = packet.push(hop_by_hop);
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_DSTOPTS => {
                let (destination_options, inner_next_header, remaining) =
                    decode_destination_options_header(payload)?;
                packet = packet.push(destination_options);
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_ROUTE => {
                let (routing, inner_next_header, remaining) = decode_routing_header(payload)?;
                packet = match routing {
                    DecodedRoutingHeader::Generic(layer) => packet.push(layer),
                    DecodedRoutingHeader::Mobile(layer) => packet.push(layer),
                    DecodedRoutingHeader::Segment(layer) => packet.push(layer),
                };
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_FRAGMENT => {
                let (fragment, inner_next_header, remaining) = decode_fragment_header(payload)?;
                let is_non_initial_fragment = fragment.fragment_offset_value() > 0;
                packet = packet.push(fragment);
                if is_non_initial_fragment {
                    if !remaining.is_empty() {
                        packet = packet.push(Raw::from_bytes(remaining));
                    }
                    return Ok(packet);
                }
                next_header = inner_next_header;
                payload = remaining;
            }
            _ => return registry.decode_ipv6_next_header(packet, next_header, payload),
        }
    }
}

fn payload_len_after(ctx: LayerContext<'_>) -> usize {
    ctx.packet()
        .iter()
        .enumerate()
        .skip(ctx.index() + 1)
        .map(|(index, layer)| {
            let layer_ctx = LayerContext::new(ctx.packet(), index);
            layer.encoded_len_with_context(&layer_ctx)
        })
        .sum()
}

fn layer_ipv6_next_header(layer: &dyn Layer) -> Option<u8> {
    if layer.as_any().is::<Ipv6HopByHopOptionsHeader>() {
        Some(IPPROTO_IPV6_HOPOPTS)
    } else if layer.as_any().is::<Ipv6DestinationOptionsHeader>() {
        Some(IPPROTO_IPV6_DSTOPTS)
    } else if layer.as_any().is::<Ipv6RoutingHeader>()
        || layer.as_any().is::<Ipv6MobileRoutingHeader>()
        || layer.as_any().is::<Ipv6SegmentRoutingHeader>()
    {
        Some(IPPROTO_IPV6_ROUTE)
    } else if layer.as_any().is::<Ipv6FragmentHeader>() {
        Some(IPPROTO_IPV6_FRAGMENT)
    } else if layer.as_any().is::<Tcp>() {
        Some(IPPROTO_TCP)
    } else if layer.as_any().is::<Udp>() {
        Some(IPPROTO_UDP)
    } else if layer.as_any().is::<Icmpv6>() {
        Some(IPPROTO_ICMPV6)
    } else {
        None
    }
}

fn parse_ipv6(input: &str) -> Result<Ipv6Addr> {
    Ipv6Addr::from_str(input).map_err(|_| {
        CrafterError::invalid_field_value("ipv6_address", "expected textual IPv6 address")
    })
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn copy_array_16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}

#[cfg(test)]
mod ipv6_tests {
    use super::{Ipv6, IPPROTO_IPV6_ROUTE};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{NetworkLayer, Packet, Raw, Tcp, TCP_FLAG_SYN};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 2)
    }

    #[test]
    fn ipv6_tcp_header_autofills_length_next_header_and_checksum() {
        let packet = Ipv6::new()
            .src(src())
            .dst(dst())
            .tc(0xab)
            .fl(0x12345)
            .hlim(32)
            / Tcp::new().sport(1234).dport(80).seq(7).flags(TCP_FLAG_SYN)
            / Raw::from("abc");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[0], 0x6a);
        assert_eq!(&bytes.as_bytes()[4..6], &(23u16).to_be_bytes());
        assert_eq!(bytes.as_bytes()[6], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[7], 32);

        let mut tcp = bytes.as_bytes()[40..].to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[56], bytes.as_bytes()[57]]),
            ipv6_pseudo_header_checksum(src(), dst(), crate::IPPROTO_TCP, &tcp)
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let ipv6 = decoded.layer::<Ipv6>().unwrap();
        assert_eq!(ipv6.source(), src());
        assert_eq!(ipv6.destination(), dst());
        assert_eq!(ipv6.traffic_class_value(), 0xab);
        assert_eq!(ipv6.flow_label_value(), 0x12345);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_explicit_base_next_header_is_preserved() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(IPPROTO_IPV6_ROUTE) / Raw::from("abc"))
            .compile()
            .unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
    }

    #[test]
    fn ipv6_decode_rejects_short_and_malformed_headers() {
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, [0u8; 39]).is_err());

        let mut bad_version = (Ipv6::new() / Raw::from("abc"))
            .compile()
            .unwrap()
            .into_bytes();
        bad_version[0] = 0x40;
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bad_version).is_err());

        let mut bad_length = (Ipv6::new() / Raw::from("abc"))
            .compile()
            .unwrap()
            .into_bytes();
        bad_length[4..6].copy_from_slice(&(10u16).to_be_bytes());
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bad_length).is_err());
    }
}

#[cfg(test)]
mod ipv6_extensions {
    use super::{Ipv6FragmentHeader, IPPROTO_IPV6_FRAGMENT};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{Ipv6, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 10, 0, 0, 0, 0, 1)
    }

    fn dst() -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 20, 0, 0, 0, 0, 2)
    }

    #[test]
    fn ipv6_fragment_header_chains_to_udp_and_preserves_checksum_context() {
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6FragmentHeader::new()
                .identification(0x0102_0304)
                .more_fragments(true)
            / Udp::new().sport(1234).dport(5678)
            / Raw::from("payload");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_FRAGMENT);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_UDP);
        assert_eq!(&bytes.as_bytes()[42..44], &1u16.to_be_bytes());
        assert_eq!(&bytes.as_bytes()[44..48], &0x0102_0304u32.to_be_bytes());

        let mut udp = bytes.as_bytes()[48..].to_vec();
        udp[6] = 0;
        udp[7] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[54], bytes.as_bytes()[55]]),
            ipv6_pseudo_header_checksum(src(), dst(), crate::IPPROTO_UDP, &udp)
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let fragment = decoded.layer::<Ipv6FragmentHeader>().unwrap();
        let udp = decoded.layer::<Udp>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(fragment.identification_value(), 0x0102_0304);
        assert!(fragment.has_more_fragments());
        assert_eq!(udp.source_port_value(), 1234);
        assert_eq!(raw.as_bytes(), b"payload");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_non_initial_fragments_preserve_remaining_bytes_as_raw() {
        let bytes = (Ipv6::new().src(src()).dst(dst())
            / Ipv6FragmentHeader::new()
                .nh(crate::IPPROTO_UDP)
                .fragment_offset(2)
                .identification(9)
            / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<Udp>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[1, 2, 3, 4]);
    }

    #[test]
    fn ipv6_unknown_next_header_preserves_payload_as_raw() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(253) / Raw::from_bytes([9, 8, 7]))
            .compile()
            .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();

        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[9, 8, 7]);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_extension_decode_rejects_short_fragment_headers() {
        let bytes = (Ipv6::new().src(src()).dst(dst()).nh(IPPROTO_IPV6_FRAGMENT)
            / Raw::from_bytes([0u8; 7]))
        .compile()
        .unwrap();

        assert!(Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod ipv6_routing_header {
    use super::{
        Ipv6MobileRoutingHeader, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader, IPPROTO_IPV6_ROUTE,
        IPV6_ROUTING_TYPE_SEGMENT,
    };
    use crate::{Ipv6, NetworkLayer, Packet, Raw, Tcp};
    use core::net::Ipv6Addr;

    fn src() -> Ipv6Addr {
        "2001:db8:dead:beef:cafe::".parse().unwrap()
    }

    fn dst() -> Ipv6Addr {
        "2001:db8:1234::1".parse().unwrap()
    }

    #[test]
    fn ipv6_segment_routing_header_matches_rfc8754_shape() {
        let sr_header = Ipv6SegmentRoutingHeader::new()
            .push_ipv6_segment("2001:db8:1234::2")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::3")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::4")
            .unwrap()
            .push_ipv6_segment("2001:db8:1234::5")
            .unwrap()
            .last_entry(3)
            .flags(0x40)
            .tag(0x1234)
            .raw_trailing_data([0x05, 0x02, 0xaa, 0xbb]);
        let packet = Ipv6::new().src(src()).dst(dst())
            / sr_header
            / Tcp::new().sport(1234).dport(80)
            / Raw::from("Hello World!");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[41], 9);
        assert_eq!(bytes.as_bytes()[42], IPV6_ROUTING_TYPE_SEGMENT);
        assert_eq!(bytes.as_bytes()[43], 3);
        assert_eq!(bytes.as_bytes()[44], 3);
        assert_eq!(bytes.as_bytes()[45], 0x40);
        assert_eq!(&bytes.as_bytes()[46..48], &[0x12, 0x34]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let sr = decoded.layer::<Ipv6SegmentRoutingHeader>().unwrap();
        assert_eq!(sr.segments().len(), 4);
        assert_eq!(sr.segments_left_value(), 3);
        assert_eq!(sr.last_entry_value(), 3);
        assert_eq!(sr.first_segment_value(), 3);
        assert_eq!(sr.flags_value(), 0x40);
        assert!(sr.p_flag_value());
        assert_eq!(sr.tag_value(), 0x1234);
        assert_eq!(
            sr.raw_trailing_data_bytes(),
            &[0x05, 0x02, 0xaa, 0xbb, 0, 0, 0, 0]
        );
        assert_eq!(decoded.layer::<Tcp>().unwrap().destination_port_value(), 80);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"Hello World!");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_mobile_routing_header_encodes_home_address_and_decodes_tcp() {
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6MobileRoutingHeader::new()
                .home_address_str("2001:db8::1")
                .unwrap()
            / Tcp::new().sport(1111).dport(2222)
            / Raw::from("mobile");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[6], IPPROTO_IPV6_ROUTE);
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_TCP);
        assert_eq!(bytes.as_bytes()[41], 2);
        assert_eq!(bytes.as_bytes()[42], 2);
        assert_eq!(bytes.as_bytes()[43], 1);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let mobile = decoded.layer::<Ipv6MobileRoutingHeader>().unwrap();
        assert_eq!(
            mobile.home_address_value(),
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(decoded.layer::<Tcp>().unwrap().source_port_value(), 1111);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_generic_routing_header_preserves_unknown_type_data() {
        let data = [0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5];
        let packet = Ipv6::new().src(src()).dst(dst())
            / Ipv6RoutingHeader::new()
                .nh(crate::IPPROTO_IPV6_EXPERIMENTAL_1)
                .routing_type(253)
                .segments_left(0)
                .append_type_data(data)
            / Raw::from("tail");
        let bytes = packet.compile().unwrap();
        assert_eq!(bytes.as_bytes()[40], crate::IPPROTO_IPV6_EXPERIMENTAL_1);
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
        let routing = decoded.layer::<Ipv6RoutingHeader>().unwrap();

        assert_eq!(routing.routing_type_value(), 253);
        assert_eq!(&routing.type_data_bytes()[..data.len()], &data);
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), b"tail");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn ipv6_routing_header_builder_rejects_malformed_segment_fields() {
        let bad_empty_segment_header = Packet::new().push(Ipv6SegmentRoutingHeader::new());
        assert!(bad_empty_segment_header.compile().is_err());

        let bad_policy_flag = Ipv6SegmentRoutingHeader::new().policy_flag(4, 1);
        assert!(bad_policy_flag.is_err());
    }
}
