#[cfg(test)]
mod ip_ranges {
    use std::net::Ipv4Addr;

    use crate::net::{get_ip_strings, get_ips, parse_ip_range, parse_numbers, Ipv4Range};

    #[test]
    fn parses_libcrafter_wildcard_range() {
        let range = Ipv4Range::parse("192.168.0.*").unwrap();

        assert_eq!(range.len(), 256);
        assert_eq!(range.addresses()[0], Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(range.addresses()[255], Ipv4Addr::new(192, 168, 0, 255));
        assert!(range.contains(Ipv4Addr::new(192, 168, 0, 42)));
    }

    #[test]
    fn parses_per_octet_lists_and_ranges_in_order() {
        let ips = get_ips("10.0,2.1-2.7,9").unwrap();

        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(10, 0, 1, 7),
                Ipv4Addr::new(10, 0, 1, 9),
                Ipv4Addr::new(10, 0, 2, 7),
                Ipv4Addr::new(10, 0, 2, 9),
                Ipv4Addr::new(10, 2, 1, 7),
                Ipv4Addr::new(10, 2, 1, 9),
                Ipv4Addr::new(10, 2, 2, 7),
                Ipv4Addr::new(10, 2, 2, 9),
            ]
        );
    }

    #[test]
    fn parses_cidr_and_full_ip_bounds() {
        assert_eq!(
            get_ips("192.0.2.4/30").unwrap(),
            vec![
                Ipv4Addr::new(192, 0, 2, 4),
                Ipv4Addr::new(192, 0, 2, 5),
                Ipv4Addr::new(192, 0, 2, 6),
                Ipv4Addr::new(192, 0, 2, 7),
            ]
        );
        assert_eq!(
            get_ip_strings("192.0.2.9-192.0.2.11").unwrap(),
            vec!["192.0.2.9", "192.0.2.10", "192.0.2.11"]
        );
    }

    #[test]
    fn parses_number_ranges_compatibly() {
        assert_eq!(
            parse_numbers("80,443,1000-1002").unwrap(),
            vec![80, 443, 1000, 1001, 1002]
        );
    }

    #[test]
    fn rejects_malformed_ranges() {
        assert!(parse_ip_range("192.168.0").is_err());
        assert!(parse_ip_range("192.168.0.5-3").is_err());
        assert!(parse_ip_range("192.168.0.300").is_err());
        assert!(parse_ip_range("*.*.*.*").is_err());
    }
}

#[cfg(test)]
mod interface_helpers {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::MacAddr;

    use crate::net::{
        default_interface_in, find_interface_in, get_my_ip_in, get_my_ipv6_in, get_my_mac_in,
        interface_for_in, InterfaceAddress, InterfaceInfo,
    };

    fn table() -> Vec<InterfaceInfo> {
        vec![
            InterfaceInfo::new("lo")
                .up(true)
                .running(true)
                .loopback(true)
                .ipv4(Ipv4Addr::new(127, 0, 0, 1), 8),
            InterfaceInfo::new("eth0")
                .up(true)
                .running(true)
                .mac(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
                .ipv4(Ipv4Addr::new(192, 0, 2, 10), 24)
                .ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64)
                .ipv6(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10), 64),
            InterfaceInfo::new("down0")
                .mac(MacAddr::new([0x02, 0, 0, 0, 0, 2]))
                .ipv4(Ipv4Addr::new(198, 51, 100, 10), 24),
        ]
    }

    #[test]
    fn selects_default_non_loopback_interface() {
        let default = default_interface_in(&table()).unwrap();

        assert_eq!(default.name(), "eth0");
        assert_eq!(default.first_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    }

    #[test]
    fn finds_interface_and_addresses_from_mock_table() {
        let table = table();

        assert_eq!(find_interface_in("eth0", &table).unwrap().name(), "eth0");
        assert_eq!(
            get_my_mac_in("eth0", &table).unwrap(),
            MacAddr::new([0x02, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            get_my_ip_in("eth0", &table).unwrap(),
            Ipv4Addr::new(192, 0, 2, 10)
        );
    }

    #[test]
    fn ipv6_helper_can_skip_link_local_addresses() {
        let table = table();

        assert_eq!(
            get_my_ipv6_in("eth0", true, &table).unwrap(),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            get_my_ipv6_in("eth0", false, &table).unwrap(),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 10)
        );
    }

    #[test]
    fn route_hint_prefers_matching_prefix_before_default() {
        let table = vec![
            InterfaceInfo::new("eth0")
                .up(true)
                .running(true)
                .ipv4(Ipv4Addr::new(192, 0, 2, 10), 24),
            InterfaceInfo::new("eth1")
                .up(true)
                .running(true)
                .ipv4(Ipv4Addr::new(198, 51, 100, 10), 24),
        ];

        let selected =
            interface_for_in(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99)), &table).unwrap();
        assert_eq!(selected.name(), "eth1");
    }

    #[test]
    fn interface_address_contains_same_prefix() {
        let address = InterfaceAddress::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 25);

        assert!(address.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100))));
        assert!(!address.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))));
    }
}

#[cfg(test)]
mod send_plan {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::{Ethernet, Icmp, Ipv4, Ipv6, NetworkLayer, Packet, Raw, Tcp, Udp};

    use crate::net::{PacketSendExt, SendMode, SendOptions, SendTarget, SocketSender};

    fn ipv4_packet() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(1111).dport(2222)
            / Raw::from("hello")
    }

    #[test]
    fn send_plan_auto_detects_l3_ipv4_and_compiles() {
        let packet = ipv4_packet();
        let plan = packet
            .send_dry_run(SendOptions::new().iface("eth0"))
            .unwrap();

        assert_eq!(plan.interface(), "eth0");
        assert_eq!(plan.requested_mode(), SendMode::Auto);
        assert!(plan.target().is_network_layer());
        assert_eq!(plan.bytes()[0] >> 4, 4);
        assert_eq!(plan.len(), packet.compile().unwrap().len());

        match plan.target() {
            SendTarget::NetworkLayer {
                network_layer,
                destination,
                protocol,
            } => {
                assert_eq!(network_layer, NetworkLayer::Ipv4);
                assert_eq!(destination, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
                assert_eq!(protocol, crate::IPPROTO_UDP);
            }
            _ => panic!("expected network-layer send target"),
        }
    }

    #[test]
    fn send_plan_auto_detects_l2_ethernet() {
        let packet = Ethernet::new() / ipv4_packet();
        let plan = packet
            .send_dry_run(SendOptions::new().iface("veth0"))
            .unwrap();

        assert_eq!(plan.interface(), "veth0");
        assert!(plan.target().is_link_layer());
        assert_eq!(
            plan.target(),
            SendTarget::LinkLayer {
                link_type: crate::LinkType::Ethernet
            }
        );
        assert_eq!(plan.bytes()[12..14], crate::ETHERTYPE_IPV4.to_be_bytes());
    }

    #[test]
    fn send_plan_respects_explicit_network_intent() {
        let packet = ipv4_packet();
        let plan = packet
            .send_plan(SendOptions::new().iface("eth0").network_layer())
            .unwrap();

        assert_eq!(plan.requested_mode(), SendMode::NetworkLayer);
        assert!(plan.target().is_network_layer());
    }

    #[test]
    fn socket_sender_dry_run_returns_report_without_transmitting() {
        let packet =
            Ethernet::new() / Ipv4::new().dst(Ipv4Addr::new(203, 0, 113, 1)) / Icmp::echo_request();
        let report = SocketSender::dry_run("eth0").send(&packet).unwrap();

        assert!(report.is_dry_run());
        assert_eq!(report.bytes_sent(), report.plan().len());
        assert!(report.plan().target().is_link_layer());
    }

    #[test]
    fn send_plan_supports_ipv6_dry_run() {
        let packet = Ipv6::new()
            .src(Ipv6Addr::LOCALHOST)
            .dst(Ipv6Addr::LOCALHOST)
            / Tcp::new().sport(1234).dport(443);
        let plan = packet
            .send_dry_run(SendOptions::new().iface("lo").network_layer())
            .unwrap();

        match plan.target() {
            SendTarget::NetworkLayer {
                network_layer,
                destination,
                protocol,
            } => {
                assert_eq!(network_layer, NetworkLayer::Ipv6);
                assert_eq!(destination, IpAddr::V6(Ipv6Addr::LOCALHOST));
                assert_eq!(protocol, crate::IPPROTO_TCP);
            }
            _ => panic!("expected IPv6 network-layer send target"),
        }
    }
}

#[cfg(test)]
mod send_errors {
    use crate::{Ethernet, Ipv4, Packet, Raw};

    use crate::net::{NetError, PacketSendExt, SendOptions, SocketSender};

    #[test]
    fn send_plan_requires_interface() {
        let packet = Ipv4::new() / Raw::from("payload");
        let error = packet.send_plan(SendOptions::new().dry_run()).unwrap_err();

        assert!(matches!(error, NetError::InterfaceRequired));
    }

    #[test]
    fn send_plan_rejects_empty_interface() {
        let packet = Ipv4::new() / Raw::from("payload");
        let error = packet
            .send_plan(SendOptions::new().iface("  ").dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::InvalidInterfaceName { .. }));
    }

    #[test]
    fn send_plan_rejects_packet_shape_for_auto_mode() {
        let packet = Packet::new().push(Raw::from("payload"));
        let error = packet
            .send_plan(SendOptions::new().iface("eth0").dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::UnsupportedPacketShape { .. }));
    }

    #[test]
    fn link_layer_intent_rejects_network_packet() {
        let packet = Ipv4::new() / Raw::from("payload");
        let error = packet
            .send_plan(SendOptions::new().iface("eth0").link_layer().dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::UnsupportedPacketShape { .. }));
    }

    #[test]
    fn network_layer_intent_rejects_link_packet() {
        let packet = Ethernet::new() / Ipv4::new() / Raw::from("payload");
        let error = packet
            .send_plan(SendOptions::new().iface("eth0").network_layer().dry_run())
            .unwrap_err();

        assert!(matches!(error, NetError::UnsupportedPacketShape { .. }));
    }

    #[test]
    fn live_send_reports_missing_interface_before_opening_raw_socket() {
        let packet = Ethernet::new() / Ipv4::new() / Raw::from("payload");
        let error = SocketSender::new(SendOptions::new().iface("missing-crafter-iface"))
            .send(&packet)
            .unwrap_err();

        assert!(matches!(error, NetError::InterfaceNotFound { .. }));
    }
}

#[cfg(test)]
mod send_recv_filters {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use crate::{Arp, Dns, Icmp, Icmpv6, IntoPacket, Ipv4, Ipv6, MacAddr, Tcp, Udp};

    use crate::net::{PacketSendRecvExt, SendRecv};

    #[test]
    fn reply_filter_for_icmp_reverses_ipv4_hosts() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(7).seq(9);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "icmp and src host 198.51.100.20 and dst host 192.0.2.10"
        );
    }

    #[test]
    fn reply_filter_for_icmpv6_reverses_ipv6_hosts() {
        let packet = Ipv6::new()
            .src(Ipv6Addr::LOCALHOST)
            .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            / Icmpv6::echo_request().id(7).seq(9);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "icmp6 and src host 2001:db8::1 and dst host ::1"
        );
    }

    #[test]
    fn reply_filter_for_tcp_reverses_ports_and_combines_user_filter() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Tcp::new().sport(44444).dport(80);

        let options = SendRecv::new()
            .iface("eth0")
            .timeout(Duration::from_millis(100))
            .retry(2)
            .filter("tcp[tcpflags] & tcp-rst != 0");

        assert_eq!(
            options.effective_filter(&packet).unwrap(),
            "(tcp and src host 198.51.100.20 and dst host 192.0.2.10 and src port 80 and dst port 44444) and (tcp[tcpflags] & tcp-rst != 0)"
        );
    }

    #[test]
    fn reply_filter_for_dns_uses_server_port_and_transaction_hosts() {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            / Udp::new().sport(53000).dport(53)
            / Dns::a_query("example.com").id(0x1234);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "udp and src host 8.8.8.8 and dst host 192.0.2.10 and src port 53"
        );
    }

    #[test]
    fn reply_filter_for_dhcp_uses_server_to_client_ports() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let packet = Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_client()
            / crate::Dhcp::discover(mac).xid(0xfeed_beef);

        assert_eq!(
            packet.reply_filter().unwrap(),
            "udp and src port 67 and dst port 68"
        );
    }

    #[test]
    fn reply_filter_for_arp_uses_target_and_sender_hosts() {
        let packet = Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            MacAddr::new([0x02, 0, 0, 0, 0, 1]),
        )
        .into_packet();

        assert_eq!(
            packet.reply_filter().unwrap(),
            "arp and src host 192.0.2.1 and dst host 192.0.2.10"
        );
    }
}

#[cfg(test)]
mod reply_matching {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::{
        Arp, Dhcp, DhcpMessageType, Dns, DnsRecord, Icmp, Icmpv6, IntoPacket, Ipv4, Ipv6, MacAddr,
        Packet, Raw, Tcp, Udp, DNS_TYPE_A, TCP_FLAG_ACK, TCP_FLAG_RST, TCP_FLAG_SYN,
    };

    use crate::net::{reply_matches, ReplyMatcher};

    #[test]
    fn matches_arp_is_at_reply() {
        let requester = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let responder = MacAddr::new([0x02, 0, 0, 0, 0, 2]);
        let request = Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            requester,
        )
        .into_packet();
        let reply = Arp::is_at(
            Ipv4Addr::new(192, 0, 2, 1),
            responder,
            Ipv4Addr::new(192, 0, 2, 10),
            requester,
        )
        .into_packet();

        assert!(reply_matches(&request, &reply));
    }

    #[test]
    fn matches_icmp_echo_reply_after_decode_roundtrip() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(7).seq(9)
            / Raw::from("hello");
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Icmp::echo_reply().id(7).seq(9)
            / Raw::from("hello");
        let decoded_reply = Packet::decode_from_l3(
            crate::NetworkLayer::Ipv4,
            reply.compile().unwrap().as_bytes(),
        )
        .unwrap();

        assert!(ReplyMatcher::from_packet(&request).matches(&decoded_reply));
    }

    #[test]
    fn rejects_icmp_echo_reply_with_wrong_sequence() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(7).seq(9);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Icmp::echo_reply().id(7).seq(10);

        assert!(!reply_matches(&request, &reply));
    }

    #[test]
    fn matches_icmpv6_echo_reply() {
        let request = Ipv6::new()
            .src(Ipv6Addr::LOCALHOST)
            .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            / Icmpv6::echo_request().id(11).seq(12);
        let reply = Ipv6::new()
            .src(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
            .dst(Ipv6Addr::LOCALHOST)
            / Icmpv6::echo_reply().id(11).seq(12);

        assert!(reply_matches(&request, &reply));
    }

    #[test]
    fn matches_tcp_reply_by_reversed_flow() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Tcp::new()
                .sport(44444)
                .dport(80)
                .seq(100)
                .flags(TCP_FLAG_SYN);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Tcp::new()
                .sport(80)
                .dport(44444)
                .seq(900)
                .ack(101)
                .flags(TCP_FLAG_SYN | TCP_FLAG_ACK);
        let reset = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Tcp::new()
                .sport(80)
                .dport(44444)
                .ack(101)
                .flags(TCP_FLAG_RST | TCP_FLAG_ACK);

        assert!(reply_matches(&request, &reply));
        assert!(reply_matches(&request, &reset));
    }

    #[test]
    fn matches_udp_reply_by_reversed_flow() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Udp::new().sport(44444).dport(9999)
            / Raw::from("request");
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(9999).dport(44444)
            / Raw::from("reply");

        assert!(reply_matches(&request, &reply));
    }

    #[test]
    fn matches_dns_response_by_id_and_reversed_udp_flow() {
        let request = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(8, 8, 8, 8))
            / Udp::new().sport(53000).dport(53)
            / Dns::a_query("example.com").id(0x1234);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(8, 8, 8, 8))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53000)
            / Dns::a_query("example.com")
                .id(0x1234)
                .response(true)
                .answer(DnsRecord::a(
                    "example.com",
                    Ipv4Addr::new(93, 184, 216, 34),
                    60,
                ));
        let wrong_id = Ipv4::new()
            .src(Ipv4Addr::new(8, 8, 8, 8))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53000)
            / Dns::query("example.com", DNS_TYPE_A)
                .id(0x4321)
                .response(true);

        assert!(reply_matches(&request, &reply));
        assert!(!reply_matches(&request, &wrong_id));
    }

    #[test]
    fn matches_dhcp_offer_by_transaction_and_client_hardware_address() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 1]);
        let request = Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_client()
            / Dhcp::discover(mac).xid(0xfeed_beef);
        let reply = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_server()
            / Dhcp::offer(
                mac,
                Ipv4Addr::new(192, 0, 2, 100),
                Ipv4Addr::new(192, 0, 2, 1),
            )
            .xid(0xfeed_beef);
        let wrong_xid = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::BROADCAST)
            / Udp::dhcp_server()
            / Dhcp::new()
                .op(crate::BOOTP_REPLY)
                .client_mac(mac)
                .message_type(DhcpMessageType::Offer)
                .xid(0xfeed_beee);

        assert!(reply_matches(&request, &reply));
        assert!(!reply_matches(&request, &wrong_xid));
    }
}

#[cfg(test)]
mod batch_send {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::{Ipv4, Packet, Raw, Udp};

    use crate::net::{send_packets, BatchSend, PacketBatchSendExt, SendTarget};

    fn udp_request(index: u8) -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, index))
            / Udp::new().sport(40_000 + u16::from(index)).dport(3_344)
            / Raw::from_bytes([index, index + 1])
    }

    #[test]
    fn batch_send_dry_run_preserves_order_and_attempts() {
        let packets = vec![udp_request(1), udp_request(2), udp_request(3)];
        let report = packets
            .as_slice()
            .batch_send(
                BatchSend::new()
                    .iface("eth0")
                    .network_layer()
                    .dry_run()
                    .concurrency_limit(2)
                    .retry(2),
            )
            .unwrap();

        assert!(report.is_dry_run());
        assert_eq!(report.len(), 3);
        assert_eq!(report.concurrency_limit(), 2);
        assert_eq!(report.retries(), 2);

        for (index, entry) in report.entries().iter().enumerate() {
            assert_eq!(entry.request_index(), index);
            assert_eq!(entry.attempts(), 2);
            for send_report in entry.send_reports() {
                assert!(send_report.is_dry_run());
                assert_eq!(send_report.bytes_sent(), send_report.plan().len());
                assert!(matches!(
                    send_report.plan().target(),
                    SendTarget::NetworkLayer { .. }
                ));
            }
        }
    }

    #[test]
    fn batch_send_normalizes_zero_limits_and_exposes_timeout() {
        let packets = vec![udp_request(7)];
        let timeout = Duration::from_millis(25);
        let report = send_packets(
            &packets,
            BatchSend::new()
                .iface("eth0")
                .network_layer()
                .dry_run()
                .concurrency_limit(0)
                .retry(0)
                .timeout(timeout),
        )
        .unwrap();

        assert_eq!(report.concurrency_limit(), 1);
        assert_eq!(report.retries(), 1);
        assert_eq!(report.retry_timeout(), timeout);
        assert_eq!(report.entry(0).unwrap().attempts(), 1);
    }
}

#[cfg(test)]
mod batch_send_recv {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::{Icmp, Ipv4, NetworkLayer, Packet, Raw};

    use crate::net::{BatchSendRecv, PacketBatchSendRecvExt};

    fn echo_request(sequence: u16) -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Icmp::echo_request().id(0x4242).seq(sequence)
            / Raw::from_bytes(sequence.to_be_bytes())
    }

    fn echo_reply(sequence: u16) -> Packet {
        let packet = Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 20))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Icmp::echo_reply().id(0x4242).seq(sequence)
            / Raw::from_bytes(sequence.to_be_bytes());

        Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile().unwrap().as_bytes()).unwrap()
    }

    #[test]
    fn batch_send_recv_dry_run_preserves_order_and_attempts() {
        let requests = vec![echo_request(1), echo_request(2), echo_request(3)];
        let report = requests
            .as_slice()
            .batch_send_recv_dry_run(
                BatchSendRecv::new()
                    .iface("eth0")
                    .network_layer()
                    .concurrency_limit(2)
                    .retry(2)
                    .timeout(Duration::from_millis(50)),
            )
            .unwrap();

        assert_eq!(report.len(), 3);
        assert_eq!(report.concurrency_limit(), 2);
        assert_eq!(report.retries(), 2);
        assert_eq!(report.timeout(), Duration::from_millis(50));
        assert_eq!(report.reply_count(), 0);
        assert_eq!(report.timed_out_indices(), vec![0, 1, 2]);
        assert_eq!(
            report.effective_filter(),
            Some("icmp and src host 198.51.100.20 and dst host 192.0.2.10")
        );

        for (index, entry) in report.entries().iter().enumerate() {
            assert_eq!(entry.request_index(), index);
            assert_eq!(entry.attempts(), 2);
            assert!(entry.timed_out());
        }
    }

    #[test]
    fn batch_send_recv_collects_partial_replies_in_request_order() {
        let requests = vec![echo_request(1), echo_request(2), echo_request(3)];
        let report = BatchSendRecv::new()
            .iface("eth0")
            .network_layer()
            .concurrency_limit(2)
            .collect_replies_from_candidates(
                &requests,
                vec![echo_reply(3), echo_reply(99), echo_reply(1)],
            );

        assert_eq!(report.reply_count(), 2);
        assert_eq!(report.timed_out_count(), 1);
        assert_eq!(report.timed_out_indices(), vec![1]);

        assert_eq!(
            report
                .entry(0)
                .unwrap()
                .reply()
                .unwrap()
                .layer::<Icmp>()
                .unwrap()
                .sequence_number_value(),
            Some(1)
        );
        assert!(report.entry(1).unwrap().reply().is_none());
        assert_eq!(
            report
                .entry(2)
                .unwrap()
                .reply()
                .unwrap()
                .layer::<Icmp>()
                .unwrap()
                .sequence_number_value(),
            Some(3)
        );
    }
}

#[cfg(test)]
mod send_recv_wire_endpoint {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::{Icmp, Ipv4};

    use crate::net::{PacketSendRecvExt, SendRecv};

    #[test]
    #[ignore = "requires root and a disposable wire endpoint"]
    fn send_recv_icmp_loopback_smoke() {
        let request = Ipv4::new()
            .src(Ipv4Addr::LOCALHOST)
            .dst(Ipv4Addr::LOCALHOST)
            / Icmp::echo_request();

        let reply = request
            .send_recv(
                SendRecv::new()
                    .iface("lo")
                    .network_layer()
                    .timeout(Duration::from_secs(1))
                    .retry(1),
            )
            .unwrap();

        assert!(reply.is_some());
    }
}
