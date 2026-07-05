//! DHCPv4 flow templates.

use std::net::Ipv4Addr;

use crafter::MacAddr;

use crate::{Flow, FlowBuilderExt, FlowState, Role, Step};

/// Initial client state: send DISCOVER and wait for OFFER.
pub const SELECTING: &str = "Selecting";
/// Client state after receiving an OFFER: send REQUEST and wait for ACK.
pub const REQUESTING: &str = "Requesting";
/// Terminal client state after ACK.
pub const BOUND: &str = "Bound";

const INITIAL_TRANSACTION_ID: u32 = 0x3903_f326;

/// Build the DHCPv4 client flow scaffold.
pub fn client_flow(client_mac: MacAddr) -> Flow {
    let selecting = FlowState::new(SELECTING).on_entry(move |ctx| {
        let transaction_id = INITIAL_TRANSACTION_ID;
        ctx.set_client_mac(client_mac);
        ctx.set_transaction_id(transaction_id);
        Ok(Step::send(discover_packet(client_mac, transaction_id)))
    });
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

#[cfg(test)]
mod tests {
    use super::{client_flow, BOUND, REQUESTING, SELECTING};
    use crate::{docaddr, PacketContext, Role};
    use std::net::Ipv4Addr;

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
}
