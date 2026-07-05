//! DHCPv4 flow templates.

use std::net::Ipv4Addr;

use crafter::MacAddr;

use crate::{
    Flow, FlowBuilderExt, FlowError, FlowState, PacketContext, PredicateMatcher, Role, Step,
    Transition,
};

/// Initial client state: send DISCOVER and wait for OFFER.
pub const SELECTING: &str = "Selecting";
/// Client state after receiving an OFFER: send REQUEST and wait for ACK.
pub const REQUESTING: &str = "Requesting";
/// Terminal client state after ACK.
pub const BOUND: &str = "Bound";

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
    use super::{client_flow, BOUND, REQUESTING, SELECTING};
    use crate::{docaddr, FlowError, PacketContext, Role};
    use std::net::Ipv4Addr;

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
