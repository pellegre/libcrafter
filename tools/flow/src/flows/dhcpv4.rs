//! DHCPv4 flow templates.

use std::net::Ipv4Addr;

use crafter::MacAddr;

use crate::{
    Flow, FlowBuilderExt, FlowError, FlowState, PacketContext, PredicateMatcher, Role, Step,
    StepGotoExt, Transition,
};
use crate::matcher::LayerMatcher;

/// Initial client state: send DISCOVER and wait for OFFER.
pub const SELECTING: &str = "Selecting";
/// Client state after receiving an OFFER: send REQUEST and wait for ACK.
pub const REQUESTING: &str = "Requesting";
/// Terminal client state after ACK.
pub const BOUND: &str = "Bound";
/// Initial server state: wait for DISCOVER.
pub const WAIT_DISCOVER: &str = "WaitDiscover";
/// Server state after OFFER: wait for REQUEST.
pub const WAIT_REQUEST: &str = "WaitRequest";
/// Terminal server state after ACK.
pub const DONE: &str = "Done";

const INITIAL_TRANSACTION_ID: u32 = 0x3903_f326;

/// Build the DHCPv4 client flow scaffold.
pub fn client_flow(client_mac: MacAddr) -> Flow {
    let selecting = FlowState::new(SELECTING)
        .on_entry(move |ctx| {
            let transaction_id = INITIAL_TRANSACTION_ID;
            ctx.set_client_mac(client_mac);
            ctx.set_transaction_id(transaction_id);
            Ok(Step::send(discover_packet(client_mac, transaction_id)))
        })
        .entry_description("DHCPv4 DISCOVER")
        .on(offer_transition());
    let requesting = FlowState::new(REQUESTING)
        .on_entry(request_action)
        .entry_description("DHCPv4 REQUEST")
        .on(ack_transition());
    let bound = FlowState::new(BOUND)
        .on_entry(|_ctx| Ok(Step::done()))
        .entry_terminal();

    Flow::new("dhcpv4-client")
        .role(Role::Initiator)
        .state(selecting)
        .state(requesting)
        .state(bound)
        .initial(SELECTING)
}

/// Build the DHCPv4 responder flow scaffold.
///
/// This is the server-side shape of the same DISCOVER/OFFER/REQUEST/ACK
/// conversation modeled by [`client_flow`], with the role flipped to
/// [`Role::Responder`]. Packet actions are filled in by the subsequent server
/// flow steps.
pub fn server_flow(server_mac: MacAddr, server_ip: Ipv4Addr, pool_base: Ipv4Addr) -> Flow {
    let wait_discover = FlowState::new(WAIT_DISCOVER).on(discover_transition(
        server_mac, server_ip, pool_base,
    ));
    let wait_request = FlowState::new(WAIT_REQUEST).on(request_transition(server_mac));
    let done = FlowState::new(DONE)
        .on_entry(|_ctx| Ok(Step::done()))
        .entry_terminal();

    Flow::new("dhcpv4-server")
        .role(Role::Responder)
        .state(wait_discover)
        .state(wait_request)
        .state(done)
        .initial(WAIT_DISCOVER)
}

fn discover_packet(client_mac: MacAddr, transaction_id: u32) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(client_mac)
        .dst(MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::discover(client_mac).xid(transaction_id)
}

fn request_action(ctx: &mut PacketContext) -> crate::Result<Step> {
    let client_mac = ctx
        .get_client_mac()
        .ok_or_else(|| missing_request_context("client_mac"))?;
    let transaction_id = ctx
        .get_transaction_id()
        .ok_or_else(|| missing_request_context("transaction_id"))?;
    let offered_ip = ctx
        .get_offered_ipv4()
        .ok_or_else(|| missing_request_context("offered_ipv4"))?;
    let server_identifier = ctx
        .get_server_identifier()
        .ok_or_else(|| missing_request_context("server_identifier"))?;

    Ok(Step::send(request_packet(
        client_mac,
        transaction_id,
        offered_ip,
        server_identifier,
    )))
}

fn missing_request_context(key: &str) -> FlowError {
    FlowError::Build(format!(
        "DHCPv4 REQUEST requires {key} in PacketContext"
    ))
}

fn request_packet(
    client_mac: MacAddr,
    transaction_id: u32,
    offered_ip: Ipv4Addr,
    server_identifier: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(client_mac)
        .dst(MacAddr::BROADCAST)
        / crafter::Ipv4::new()
            .src(Ipv4Addr::UNSPECIFIED)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_client()
        / crafter::Dhcpv4::request(client_mac, offered_ip, server_identifier).xid(transaction_id)
}

fn discover_transition(server_mac: MacAddr, server_ip: Ipv4Addr, pool_base: Ipv4Addr) -> Transition {
    Transition::on(
        LayerMatcher::where_layer::<crafter::Dhcpv4>("message type DISCOVER", |dhcp| {
            dhcp.message_type_value() == Some(crafter::Dhcpv4MessageType::Discover)
        }),
        move |packet, ctx| {
            let dhcp = packet.layer::<crafter::Dhcpv4>().ok_or_else(|| {
                FlowError::Capture("matched DHCPv4 DISCOVER packet has no DHCPv4 layer".to_string())
            })?;
            let client_mac = dhcp.client_mac_value().ok_or_else(|| {
                FlowError::Capture("matched DHCPv4 DISCOVER has no client MAC".to_string())
            })?;
            let transaction_id = dhcp.transaction_id_value();
            let offered_ip = pool_base;

            ctx.set_client_mac(client_mac);
            ctx.set_transaction_id(transaction_id);
            ctx.set_offered_ipv4(offered_ip);
            ctx.set_server_identifier(server_ip);

            Ok(Step::send(server_offer_packet(
                server_mac,
                server_ip,
                client_mac,
                transaction_id,
                offered_ip,
            ))
            .goto(WAIT_REQUEST))
        },
    )
    .targets([WAIT_REQUEST])
}

fn server_offer_packet(
    server_mac: MacAddr,
    server_ip: Ipv4Addr,
    client_mac: MacAddr,
    transaction_id: u32,
    offered_ip: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ethernet::new().src(server_mac).dst(client_mac)
        / crafter::Ipv4::new().src(server_ip).dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_server()
        / crafter::Dhcpv4::offer(client_mac, offered_ip, server_ip)
            .xid(transaction_id)
            .siaddr(server_ip)
            .router([server_ip])
            .domain_name_server([server_ip])
}

fn request_transition(server_mac: MacAddr) -> Transition {
    Transition::on(
        PredicateMatcher::new("DHCPv4 REQUEST for stored xid and offer", request_matches_context),
        move |_packet, ctx| {
            let client_mac = ctx
                .get_client_mac()
                .ok_or_else(|| missing_ack_context("client_mac"))?;
            let transaction_id = ctx
                .get_transaction_id()
                .ok_or_else(|| missing_ack_context("transaction_id"))?;
            let assigned_ip = ctx
                .get_offered_ipv4()
                .ok_or_else(|| missing_ack_context("offered_ipv4"))?;
            let server_identifier = ctx
                .get_server_identifier()
                .ok_or_else(|| missing_ack_context("server_identifier"))?;

            ctx.set_assigned_ipv4(assigned_ip);
            Ok(Step::send(server_ack_packet(
                server_mac,
                server_identifier,
                client_mac,
                transaction_id,
                assigned_ip,
            ))
            .goto(DONE))
        },
    )
    .targets([DONE])
}

fn missing_ack_context(key: &str) -> FlowError {
    FlowError::Build(format!("DHCPv4 ACK requires {key} in PacketContext"))
}

fn request_matches_context(packet: &crafter::Packet, ctx: &PacketContext) -> bool {
    let Some(expected_xid) = ctx.get_transaction_id() else {
        return false;
    };
    let Some(expected_ip) = ctx.get_offered_ipv4() else {
        return false;
    };
    let Some(expected_server_identifier) = ctx.get_server_identifier() else {
        return false;
    };

    packet.layer::<crafter::Dhcpv4>().is_some_and(|dhcp| {
        dhcp.message_type_value() == Some(crafter::Dhcpv4MessageType::Request)
            && dhcp.transaction_id_value() == expected_xid
            && dhcp.requested_ip_address_value() == Some(expected_ip)
            && dhcp.server_identifier_value() == Some(expected_server_identifier)
    })
}

fn server_ack_packet(
    server_mac: MacAddr,
    server_identifier: Ipv4Addr,
    client_mac: MacAddr,
    transaction_id: u32,
    assigned_ip: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ethernet::new().src(server_mac).dst(client_mac)
        / crafter::Ipv4::new()
            .src(server_identifier)
            .dst(Ipv4Addr::BROADCAST)
        / crafter::Udp::dhcpv4_server()
        / crafter::Dhcpv4::ack(client_mac, assigned_ip, server_identifier)
            .xid(transaction_id)
            .siaddr(server_identifier)
}

fn offer_transition() -> Transition {
    Transition::on(
        PredicateMatcher::new("DHCPv4 OFFER for stored xid", offer_matches_context),
        |packet, ctx| {
            let dhcp = packet.layer::<crafter::Dhcpv4>().ok_or_else(|| {
                FlowError::Capture("matched DHCPv4 OFFER packet has no DHCPv4 layer".to_string())
            })?;
            let offered_ip = dhcp.offered_ip_address().ok_or_else(|| {
                FlowError::Capture("matched DHCPv4 OFFER has no offered address".to_string())
            })?;
            let server_identifier = dhcp.server_identifier_value().ok_or_else(|| {
                FlowError::Capture("matched DHCPv4 OFFER has no server identifier".to_string())
            })?;

            ctx.set_offered_ipv4(offered_ip);
            ctx.set_server_identifier(server_identifier);
            Ok(Step::goto(REQUESTING))
        },
    )
    .targets([REQUESTING])
}

fn offer_matches_context(packet: &crafter::Packet, ctx: &PacketContext) -> bool {
    let Some(expected_xid) = ctx.get_transaction_id() else {
        return false;
    };

    packet.layer::<crafter::Dhcpv4>().is_some_and(|dhcp| {
        dhcp.message_type_value() == Some(crafter::Dhcpv4MessageType::Offer)
            && dhcp.transaction_id_value() == expected_xid
    })
}

fn ack_transition() -> Transition {
    Transition::on(
        PredicateMatcher::new("DHCPv4 ACK for stored xid", ack_matches_context),
        |packet, ctx| {
            let dhcp = packet.layer::<crafter::Dhcpv4>().ok_or_else(|| {
                FlowError::Capture("matched DHCPv4 ACK packet has no DHCPv4 layer".to_string())
            })?;
            let assigned_ip = dhcp.offered_ip_address().ok_or_else(|| {
                FlowError::Capture("matched DHCPv4 ACK has no assigned address".to_string())
            })?;

            ctx.set_assigned_ipv4(assigned_ip);
            Ok(Step::goto(BOUND))
        },
    )
    .targets([BOUND])
}

fn ack_matches_context(packet: &crafter::Packet, ctx: &PacketContext) -> bool {
    let Some(expected_xid) = ctx.get_transaction_id() else {
        return false;
    };

    packet.layer::<crafter::Dhcpv4>().is_some_and(|dhcp| {
        if dhcp.message_type_value() != Some(crafter::Dhcpv4MessageType::Ack)
            || dhcp.transaction_id_value() != expected_xid
        {
            return false;
        }

        match ctx.get_offered_ipv4() {
            Some(offered_ip) => dhcp.offered_ip_address() == Some(offered_ip),
            None => true,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        client_flow, server_flow, BOUND, DONE, REQUESTING, SELECTING, WAIT_DISCOVER, WAIT_REQUEST,
    };
    use crate::{docaddr, FlowError, PacketContext, Role};
    use std::net::Ipv4Addr;

    fn discover_from_client(client_mac: crafter::MacAddr, transaction_id: u32) -> crafter::Packet {
        crafter::Ethernet::new()
            .src(client_mac)
            .dst(crafter::MacAddr::BROADCAST)
            / crafter::Ipv4::new()
                .src(Ipv4Addr::UNSPECIFIED)
                .dst(Ipv4Addr::BROADCAST)
            / crafter::Udp::dhcpv4_client()
            / crafter::Dhcpv4::discover(client_mac).xid(transaction_id)
    }

    fn offer_packet(
        transaction_id: u32,
        offered_ip: Ipv4Addr,
        server_id: Ipv4Addr,
    ) -> crafter::Packet {
        crafter::Ethernet::new()
            .src(crafter::MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02]))
            .dst(crafter::MacAddr::BROADCAST)
            / crafter::Ipv4::new()
                .src(server_id)
                .dst(Ipv4Addr::BROADCAST)
            / crafter::Udp::dhcpv4_server()
            / crafter::Dhcpv4::offer(docaddr::CLIENT_MAC, offered_ip, server_id)
                .xid(transaction_id)
    }

    fn ack_packet(
        transaction_id: u32,
        assigned_ip: Ipv4Addr,
        server_id: Ipv4Addr,
    ) -> crafter::Packet {
        crafter::Ethernet::new()
            .src(crafter::MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, 0x02]))
            .dst(crafter::MacAddr::BROADCAST)
            / crafter::Ipv4::new()
                .src(server_id)
                .dst(Ipv4Addr::BROADCAST)
            / crafter::Udp::dhcpv4_server()
            / crafter::Dhcpv4::ack(docaddr::CLIENT_MAC, assigned_ip, server_id)
                .xid(transaction_id)
    }

    fn request_from_client(
        client_mac: crafter::MacAddr,
        transaction_id: u32,
        requested_ip: Ipv4Addr,
        server_id: Ipv4Addr,
    ) -> crafter::Packet {
        crafter::Ethernet::new()
            .src(client_mac)
            .dst(crafter::MacAddr::BROADCAST)
            / crafter::Ipv4::new()
                .src(Ipv4Addr::UNSPECIFIED)
                .dst(Ipv4Addr::BROADCAST)
            / crafter::Udp::dhcpv4_client()
            / crafter::Dhcpv4::request(client_mac, requested_ip, server_id)
                .xid(transaction_id)
    }

    #[test]
    fn dhcpv4_client_flow_scaffold_has_client_states() {
        let flow = client_flow(docaddr::CLIENT_MAC);

        assert_eq!(flow.role(), Role::Initiator);
        assert_eq!(flow.initial(), SELECTING);
        assert!(flow.state(SELECTING).is_some());
        assert!(flow.state(REQUESTING).is_some());
        assert!(flow.state(BOUND).is_some());
    }

    #[test]
    fn dhcpv4_server_flow_scaffold_has_responder_states() {
        let flow = server_flow(docaddr::LOCAL_MAC, docaddr::SERVER_IPV4, docaddr::CLIENT_IPV4);

        assert_eq!(flow.role(), Role::Responder);
        assert_eq!(flow.initial(), WAIT_DISCOVER);
        assert!(flow.state(WAIT_DISCOVER).is_some());
        assert!(flow.state(WAIT_REQUEST).is_some());
        assert!(flow.state(DONE).is_some());
    }

    #[test]
    fn dhcpv4_wait_discover_transition_builds_offer_and_records_context() {
        let transaction_id = 0x5000_0001;
        let offered_ip = docaddr::CLIENT_IPV4;
        let server_id = docaddr::SERVER_IPV4;
        let mut flow = server_flow(docaddr::LOCAL_MAC, server_id, offered_ip);
        let mut context = PacketContext::new();
        let discover = discover_from_client(docaddr::CLIENT_MAC, transaction_id);

        let wait_discover = flow
            .state(WAIT_DISCOVER)
            .expect("WaitDiscover state exists");
        assert!(wait_discover.transitions()[0].matches(&discover, &context));

        let step = flow
            .state_mut(WAIT_DISCOVER)
            .expect("WaitDiscover state exists")
            .find_transition(&discover, &context)
            .expect("matching DISCOVER transition")
            .fire(&discover, &mut context)
            .expect("DISCOVER handler succeeds");
        let offer = step.outgoing().expect("DISCOVER response sends OFFER");
        let ethernet = offer.layer::<crafter::Ethernet>().expect("OFFER has Ethernet");
        let ipv4 = offer.layer::<crafter::Ipv4>().expect("OFFER has IPv4");
        let udp = offer.layer::<crafter::Udp>().expect("OFFER has UDP");
        let dhcp = offer
            .layer::<crafter::Dhcpv4>()
            .expect("OFFER has DHCPv4");

        assert_eq!(step.target(), Some(WAIT_REQUEST));
        assert_eq!(context.get_client_mac(), Some(docaddr::CLIENT_MAC));
        assert_eq!(context.get_transaction_id(), Some(transaction_id));
        assert_eq!(context.get_offered_ipv4(), Some(offered_ip));
        assert_eq!(ethernet.destination(), Some(docaddr::CLIENT_MAC));
        assert_eq!(ipv4.source(), server_id);
        assert_eq!(udp.destination_port_value(), crafter::DHCPV4_CLIENT_PORT);
        assert_eq!(
            dhcp.message_type_value(),
            Some(crafter::Dhcpv4MessageType::Offer)
        );
        assert_eq!(dhcp.client_mac_value(), Some(docaddr::CLIENT_MAC));
        assert_eq!(dhcp.transaction_id_value(), transaction_id);
        assert_eq!(dhcp.offered_ip_address(), Some(offered_ip));
        assert_eq!(dhcp.server_identifier_value(), Some(server_id));
        assert_eq!(dhcp.server_ip_address_value(), server_id);
        assert_eq!(dhcp.routers(), vec![server_id]);
        assert_eq!(dhcp.domain_name_servers(), vec![server_id]);
    }

    #[test]
    fn dhcpv4_wait_request_transition_builds_ack_and_targets_done() {
        let transaction_id = 0x5100_0001;
        let assigned_ip = docaddr::CLIENT_IPV4;
        let server_id = docaddr::SERVER_IPV4;
        let mut flow = server_flow(docaddr::LOCAL_MAC, server_id, assigned_ip);
        let mut context = PacketContext::new();
        context.set_client_mac(docaddr::CLIENT_MAC);
        context.set_transaction_id(transaction_id);
        context.set_offered_ipv4(assigned_ip);
        context.set_server_identifier(server_id);
        let request =
            request_from_client(docaddr::CLIENT_MAC, transaction_id, assigned_ip, server_id);
        let wrong_requested_ip = request_from_client(
            docaddr::CLIENT_MAC,
            transaction_id,
            Ipv4Addr::new(192, 0, 2, 99),
            server_id,
        );

        let wait_request = flow.state(WAIT_REQUEST).expect("WaitRequest state exists");
        assert!(wait_request.transitions()[0].matches(&request, &context));
        assert!(!wait_request.transitions()[0].matches(&wrong_requested_ip, &context));

        let step = flow
            .state_mut(WAIT_REQUEST)
            .expect("WaitRequest state exists")
            .find_transition(&request, &context)
            .expect("matching REQUEST transition")
            .fire(&request, &mut context)
            .expect("REQUEST handler succeeds");
        let ack = step.outgoing().expect("REQUEST response sends ACK");
        let ethernet = ack.layer::<crafter::Ethernet>().expect("ACK has Ethernet");
        let ipv4 = ack.layer::<crafter::Ipv4>().expect("ACK has IPv4");
        let udp = ack.layer::<crafter::Udp>().expect("ACK has UDP");
        let dhcp = ack.layer::<crafter::Dhcpv4>().expect("ACK has DHCPv4");
        let terminal_step = flow
            .state_mut(DONE)
            .expect("Done state exists")
            .run_entry(&mut context)
            .expect("Done entry succeeds")
            .expect("Done entry returns terminal step");

        assert_eq!(step.target(), Some(DONE));
        assert_eq!(context.get_assigned_ipv4(), Some(assigned_ip));
        assert_eq!(ethernet.source(), Some(docaddr::LOCAL_MAC));
        assert_eq!(ethernet.destination(), Some(docaddr::CLIENT_MAC));
        assert_eq!(ipv4.source(), server_id);
        assert_eq!(udp.destination_port_value(), crafter::DHCPV4_CLIENT_PORT);
        assert_eq!(
            dhcp.message_type_value(),
            Some(crafter::Dhcpv4MessageType::Ack)
        );
        assert_eq!(dhcp.client_mac_value(), Some(docaddr::CLIENT_MAC));
        assert_eq!(dhcp.transaction_id_value(), transaction_id);
        assert_eq!(dhcp.offered_ip_address(), Some(assigned_ip));
        assert_eq!(dhcp.server_identifier_value(), Some(server_id));
        assert_eq!(dhcp.server_ip_address_value(), server_id);
        assert!(terminal_step.is_terminal());
    }

    #[test]
    fn dhcpv4_client_flow_validates_and_show_lists_conversation() {
        let flow = client_flow(docaddr::CLIENT_MAC);

        flow.validate().expect("DHCPv4 client flow validates");
        let show = flow.show();

        for expected in [
            SELECTING,
            REQUESTING,
            BOUND,
            "DHCPv4 DISCOVER",
            "DHCPv4 OFFER",
            "DHCPv4 REQUEST",
            "DHCPv4 ACK",
        ] {
            assert!(
                show.contains(expected),
                "flow show should contain {expected}: {show}"
            );
        }
    }

    #[test]
    fn dhcpv4_selecting_entry_builds_discover_and_records_context() {
        let mut flow = client_flow(docaddr::CLIENT_MAC);
        let mut context = PacketContext::new();

        let step = flow
            .state_mut(SELECTING)
            .expect("Selecting state exists")
            .run_entry(&mut context)
            .expect("entry succeeds")
            .expect("entry returns a send step");
        let packet = step.outgoing().expect("Selecting sends DISCOVER");
        let ethernet = packet
            .layer::<crafter::Ethernet>()
            .expect("DISCOVER has Ethernet");
        let ipv4 = packet.layer::<crafter::Ipv4>().expect("DISCOVER has IPv4");
        let udp = packet.layer::<crafter::Udp>().expect("DISCOVER has UDP");
        let dhcp = packet
            .layer::<crafter::Dhcpv4>()
            .expect("DISCOVER has DHCPv4");

        assert_eq!(context.get_client_mac(), Some(docaddr::CLIENT_MAC));
        assert_eq!(
            context.get_transaction_id(),
            Some(dhcp.transaction_id_value())
        );
        assert_eq!(ethernet.destination(), Some(crafter::MacAddr::BROADCAST));
        assert_eq!(ipv4.source(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(ipv4.destination(), Ipv4Addr::BROADCAST);
        assert_eq!(udp.destination_port_value(), crafter::DHCPV4_SERVER_PORT);
        assert_eq!(
            dhcp.message_type_value(),
            Some(crafter::Dhcpv4MessageType::Discover)
        );
        assert!(step.target().is_none());
    }

    #[test]
    fn dhcpv4_offer_transition_records_offer_details_and_rejects_wrong_xid() {
        let offered_ip = Ipv4Addr::new(192, 0, 2, 44);
        let server_id = docaddr::SERVER_IPV4;
        let mut flow = client_flow(docaddr::CLIENT_MAC);
        let mut context = PacketContext::new();
        let discover = flow
            .state_mut(SELECTING)
            .expect("Selecting state exists")
            .run_entry(&mut context)
            .expect("entry succeeds")
            .expect("entry returns DISCOVER");
        assert!(discover.outgoing().is_some());
        let transaction_id = context
            .get_transaction_id()
            .expect("Selecting stores transaction id");
        let offer = offer_packet(transaction_id, offered_ip, server_id);
        let wrong_xid_offer = offer_packet(transaction_id.wrapping_add(1), offered_ip, server_id);

        let selecting = flow.state(SELECTING).expect("Selecting state exists");
        assert!(selecting.transitions()[0].matches(&offer, &context));
        assert!(!selecting.transitions()[0].matches(&wrong_xid_offer, &context));

        let step = flow
            .state_mut(SELECTING)
            .expect("Selecting state exists")
            .find_transition(&offer, &context)
            .expect("matching OFFER transition")
            .fire(&offer, &mut context)
            .expect("OFFER handler succeeds");

        assert_eq!(step.target(), Some(REQUESTING));
        assert_eq!(context.get_offered_ipv4(), Some(offered_ip));
        assert_eq!(context.get_server_identifier(), Some(server_id));
    }

    #[test]
    fn dhcpv4_requesting_entry_builds_request_from_context() {
        let offered_ip = Ipv4Addr::new(192, 0, 2, 44);
        let server_id = docaddr::SERVER_IPV4;
        let transaction_id = 0x4100_002b;
        let mut flow = client_flow(docaddr::CLIENT_MAC);
        let mut context = PacketContext::new();
        context.set_client_mac(docaddr::CLIENT_MAC);
        context.set_transaction_id(transaction_id);
        context.set_offered_ipv4(offered_ip);
        context.set_server_identifier(server_id);

        let step = flow
            .state_mut(REQUESTING)
            .expect("Requesting state exists")
            .run_entry(&mut context)
            .expect("entry succeeds")
            .expect("entry returns REQUEST");
        let packet = step.outgoing().expect("Requesting sends REQUEST");
        let udp = packet.layer::<crafter::Udp>().expect("REQUEST has UDP");
        let dhcp = packet
            .layer::<crafter::Dhcpv4>()
            .expect("REQUEST has DHCPv4");

        assert_eq!(udp.destination_port_value(), crafter::DHCPV4_SERVER_PORT);
        assert_eq!(
            dhcp.message_type_value(),
            Some(crafter::Dhcpv4MessageType::Request)
        );
        assert_eq!(dhcp.transaction_id_value(), transaction_id);
        assert_eq!(dhcp.requested_ip_address_value(), Some(offered_ip));
        assert_eq!(dhcp.server_identifier_value(), Some(server_id));
        assert!(step.target().is_none());
    }

    #[test]
    fn dhcpv4_requesting_entry_reports_missing_context() {
        let mut flow = client_flow(docaddr::CLIENT_MAC);
        let mut context = PacketContext::new();

        let error = flow
            .state_mut(REQUESTING)
            .expect("Requesting state exists")
            .run_entry(&mut context)
            .expect_err("missing context should fail");

        assert!(matches!(error, FlowError::Build(_)));
        assert!(error.to_string().contains("client_mac"));
    }

    #[test]
    fn dhcpv4_ack_transition_records_assigned_address_and_targets_bound() {
        let assigned_ip = Ipv4Addr::new(192, 0, 2, 44);
        let server_id = docaddr::SERVER_IPV4;
        let transaction_id = 0x4400_0001;
        let mut flow = client_flow(docaddr::CLIENT_MAC);
        let mut context = PacketContext::new();
        context.set_transaction_id(transaction_id);
        context.set_offered_ipv4(assigned_ip);
        let ack = ack_packet(transaction_id, assigned_ip, server_id);

        let requesting = flow.state(REQUESTING).expect("Requesting state exists");
        assert!(requesting.transitions()[0].matches(&ack, &context));

        let step = flow
            .state_mut(REQUESTING)
            .expect("Requesting state exists")
            .find_transition(&ack, &context)
            .expect("matching ACK transition")
            .fire(&ack, &mut context)
            .expect("ACK handler succeeds");
        let terminal_step = flow
            .state_mut(BOUND)
            .expect("Bound state exists")
            .run_entry(&mut context)
            .expect("Bound entry succeeds")
            .expect("Bound entry returns terminal step");

        assert_eq!(step.target(), Some(BOUND));
        assert_eq!(context.get_assigned_ipv4(), Some(assigned_ip));
        assert!(terminal_step.is_terminal());
    }
}
