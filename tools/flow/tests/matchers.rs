use std::net::Ipv4Addr;

use crafter_flow::prelude::*;

const DHCP_XID: u32 = 0x4d43_0101;
const DNS_XID: u16 = 0x7253;
const DNS_NAME: &str = "service.example.";

fn dhcp_discover(transaction_id: u32) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(docaddr::CLIENT_MAC)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::discover(docaddr::CLIENT_MAC).xid(transaction_id)
}

fn dhcp_offer(transaction_id: u32) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(docaddr::LOCAL_MAC)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(docaddr::SERVER_IPV4)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_server()
        / crafter::Dhcpv4::offer(
            docaddr::CLIENT_MAC,
            docaddr::CLIENT_IPV4,
            docaddr::SERVER_IPV4,
        )
        .xid(transaction_id)
}

fn dhcp_request(transaction_id: u32) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(docaddr::CLIENT_MAC)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::request(
            docaddr::CLIENT_MAC,
            docaddr::CLIENT_IPV4,
            docaddr::SERVER_IPV4,
        )
        .xid(transaction_id)
}

fn icmp_echo_request(identifier: u16, sequence: u16) -> crafter::Packet {
    crafter::Ipv4::new()
        .src(docaddr::CLIENT_IPV4)
        .dst(docaddr::SERVER_IPV4)
        / crafter::Icmpv4::echo_request()
            .id(identifier)
            .seq(sequence)
        / crafter::Raw::from("flow matcher ping")
}

fn icmp_echo_reply(identifier: u16, sequence: u16) -> crafter::Packet {
    crafter::Ipv4::new()
        .src(docaddr::SERVER_IPV4)
        .dst(docaddr::CLIENT_IPV4)
        / crafter::Icmpv4::echo_reply()
            .id(identifier)
            .seq(sequence)
        / crafter::Raw::from("flow matcher ping")
}

fn arp_who_has(target_ip: Ipv4Addr) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(docaddr::CLIENT_MAC)
        .dst(crafter::MacAddr::BROADCAST)
        / crafter::Arp::who_has(docaddr::CLIENT_IPV4, target_ip, docaddr::CLIENT_MAC)
}

fn arp_is_at(sender_ip: Ipv4Addr) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(docaddr::LOCAL_MAC)
        .dst(docaddr::CLIENT_MAC)
        / crafter::Arp::is_at(
            sender_ip,
            docaddr::LOCAL_MAC,
            docaddr::CLIENT_IPV4,
            docaddr::CLIENT_MAC,
        )
}

fn dns_query(name: &str) -> crafter::Packet {
    crafter::Ipv4::new()
        .src(docaddr::CLIENT_IPV4)
        .dst(docaddr::DNS_IPV4)
        / crafter::Udp::new()
            .source_port(53000)
            .destination_port(crafter::DNS_PORT)
        / crafter::Dns::query(name, crafter::DNS_TYPE_A).id(DNS_XID)
}

fn dhcp_message_type_matcher(message_type: crafter::Dhcpv4MessageType) -> LayerMatcher {
    LayerMatcher::where_layer::<crafter::Dhcpv4>(
        format!("DHCPv4 message type {message_type:?}"),
        move |dhcp| dhcp.message_type_value() == Some(message_type),
    )
}

fn dhcp_transaction_id_matcher(transaction_id: u32) -> LayerMatcher {
    LayerMatcher::where_layer::<crafter::Dhcpv4>(
        format!("DHCPv4 xid 0x{transaction_id:08x}"),
        move |dhcp| dhcp.transaction_id_value() == transaction_id,
    )
}

fn arp_who_has_matcher(target_ip: Ipv4Addr) -> LayerMatcher {
    LayerMatcher::where_layer::<crafter::Arp>("ARP who-has target", move |arp| {
        arp.opcode_value() == u16::from(crafter::ArpOperation::Request)
            && arp.target_ipv4() == Some(target_ip)
    })
}

fn dns_query_name_matcher(name: &str) -> LayerMatcher {
    let name = name.to_string();

    LayerMatcher::where_layer::<crafter::Dns>(
        format!("DNS query for {name}"),
        move |dns| {
            !dns.is_response()
                && dns
                    .questions()
                    .first()
                    .is_some_and(|question| question.name().eq_ignore_ascii_case(&name))
        },
    )
}

#[test]
fn reply_matcher_matches_dhcp_offer_by_transaction_id() {
    let discover = dhcp_discover(DHCP_XID);
    let offer = dhcp_offer(DHCP_XID);
    let wrong_transaction_id = dhcp_offer(DHCP_XID + 1);
    let matcher = ReplyMatcher::to(discover);
    let context = PacketContext::new();

    assert!(matcher.matches(&offer, &context));
    assert!(!matcher.matches(&wrong_transaction_id, &context));
}

#[test]
fn reply_matcher_matches_icmp_echo_reply_by_echo_fields() {
    let request = icmp_echo_request(0x4242, 7);
    let reply = icmp_echo_reply(0x4242, 7);
    let wrong_sequence = icmp_echo_reply(0x4242, 8);
    let matcher = ReplyMatcher::to(request);
    let context = PacketContext::new();

    assert!(matcher.matches(&reply, &context));
    assert!(!matcher.matches(&wrong_sequence, &context));
}

#[test]
fn layer_matcher_matches_dhcp_message_type_only() {
    let matcher = dhcp_message_type_matcher(crafter::Dhcpv4MessageType::Discover);
    let discover = dhcp_discover(DHCP_XID);
    let wrong_message_type = dhcp_request(DHCP_XID);
    let context = PacketContext::new();

    assert!(matcher.matches(&discover, &context));
    assert!(!matcher.matches(&wrong_message_type, &context));
}

#[test]
fn layer_matcher_matches_arp_who_has_only() {
    let matcher = arp_who_has_matcher(docaddr::SERVER_IPV4);
    let who_has = arp_who_has(docaddr::SERVER_IPV4);
    let wrong_message_type = arp_is_at(docaddr::SERVER_IPV4);
    let context = PacketContext::new();

    assert!(matcher.matches(&who_has, &context));
    assert!(!matcher.matches(&wrong_message_type, &context));
}

#[test]
fn layer_matcher_matches_dns_query_name_only() {
    let matcher = dns_query_name_matcher(DNS_NAME);
    let query = dns_query(DNS_NAME);
    let wrong_name = dns_query("other.example.");
    let context = PacketContext::new();

    assert!(matcher.matches(&query, &context));
    assert!(!matcher.matches(&wrong_name, &context));
}

#[test]
fn and_combinator_requires_dhcp_type_and_transaction_id() {
    let matcher = And::new(vec![
        dhcp_message_type_matcher(crafter::Dhcpv4MessageType::Offer).boxed(),
        dhcp_transaction_id_matcher(DHCP_XID).boxed(),
    ]);
    let offer = dhcp_offer(DHCP_XID);
    let wrong_transaction_id = dhcp_offer(DHCP_XID + 1);
    let wrong_message_type = dhcp_discover(DHCP_XID);
    let context = PacketContext::new();

    assert!(matcher.matches(&offer, &context));
    assert!(!matcher.matches(&wrong_transaction_id, &context));
    assert!(!matcher.matches(&wrong_message_type, &context));
}

#[test]
fn or_combinator_matches_arp_who_has_or_dns_query() {
    let matcher = Or::new(vec![
        arp_who_has_matcher(docaddr::SERVER_IPV4).boxed(),
        dns_query_name_matcher(DNS_NAME).boxed(),
    ]);
    let who_has = arp_who_has(docaddr::SERVER_IPV4);
    let query = dns_query(DNS_NAME);
    let wrong_name = dns_query("other.example.");
    let wrong_message_type = arp_is_at(docaddr::SERVER_IPV4);
    let context = PacketContext::new();

    assert!(matcher.matches(&who_has, &context));
    assert!(matcher.matches(&query, &context));
    assert!(!matcher.matches(&wrong_name, &context));
    assert!(!matcher.matches(&wrong_message_type, &context));
}

#[test]
fn not_combinator_excludes_a_wrong_dns_name() {
    let matcher = Not::new(dns_query_name_matcher("other.example.").boxed());
    let intended_query = dns_query(DNS_NAME);
    let wrong_name = dns_query("other.example.");
    let context = PacketContext::new();

    assert!(matcher.matches(&intended_query, &context));
    assert!(!matcher.matches(&wrong_name, &context));
}
