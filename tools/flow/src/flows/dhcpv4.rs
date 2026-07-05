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
        .on(offer_transition());
    let requesting = FlowState::new(REQUESTING);
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

#[cfg(test)]
mod tests {
    use super::{client_flow, BOUND, REQUESTING, SELECTING};
    use crate::{docaddr, PacketContext, Role};
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
}
