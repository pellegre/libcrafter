//! ARP flow templates.

use std::net::Ipv4Addr;

use crafter::MacAddr;

use crate::{Flow, FlowBuilderExt, FlowState, Role, Step};

/// Initial injector state: announce an ARP binding and watch for who-has.
pub const ANNOUNCE: &str = "Announce";

/// Build an ARP injector flow scaffold.
///
/// The asserted binding is `bind_ip -> bind_mac`: this injector claims that
/// `bind_ip` is reachable at `bind_mac`. Tracked examples and tests should pass
/// documentation-space values from [`crate::docaddr`].
pub fn injector_flow(bind_ip: Ipv4Addr, bind_mac: MacAddr) -> Flow {
    let announce = FlowState::new(ANNOUNCE)
        .on_entry(move |_ctx| Ok(Step::emit(gratuitous_arp(bind_ip, bind_mac))))
        .entry_description("gratuitous ARP is-at");

    Flow::new("arp-injector")
        .role(Role::Injector)
        .state(announce)
        .initial(ANNOUNCE)
}

fn gratuitous_arp(bind_ip: Ipv4Addr, bind_mac: MacAddr) -> crafter::Packet {
    crafter::Ethernet::new()
        .src(bind_mac)
        .dst(MacAddr::BROADCAST)
        / crafter::Arp::is_at(bind_ip, bind_mac, bind_ip, MacAddr::BROADCAST)
}

#[cfg(test)]
mod tests {
    use super::{injector_flow, ANNOUNCE};
    use crate::{docaddr, PacketContext, Role};

    #[test]
    fn arp_injector_flow_scaffold_has_injector_role_and_initial_announce() {
        let flow = injector_flow(docaddr::SERVER_IPV4, docaddr::LOCAL_MAC);

        assert_eq!(flow.role(), Role::Injector);
        assert_eq!(flow.initial(), ANNOUNCE);
    }

    #[test]
    fn arp_announce_entry_emits_gratuitous_arp() {
        let bind_ip = docaddr::SERVER_IPV4;
        let bind_mac = docaddr::LOCAL_MAC;
        let mut flow = injector_flow(bind_ip, bind_mac);
        let mut context = PacketContext::new();

        let step = flow
            .state_mut(ANNOUNCE)
            .expect("Announce state exists")
            .run_entry(&mut context)
            .expect("entry succeeds")
            .expect("entry returns an ARP announcement");
        let packet = step.outgoing().expect("Announce emits a packet");
        let ethernet = packet
            .layer::<crafter::Ethernet>()
            .expect("announcement has Ethernet");
        let arp = packet
            .layer::<crafter::Arp>()
            .expect("announcement has ARP");

        assert!(!step.expects_reply());
        assert_eq!(step.target(), None);
        assert_eq!(ethernet.source(), Some(bind_mac));
        assert_eq!(ethernet.destination(), Some(crafter::MacAddr::BROADCAST));
        assert_eq!(arp.opcode_value(), crafter::ArpOperation::Reply.into());
        assert_eq!(arp.sender_ipv4(), Some(bind_ip));
        assert_eq!(arp.sender_mac(), Some(bind_mac));
        assert_eq!(arp.target_ipv4(), Some(bind_ip));
        assert_eq!(arp.target_mac(), Some(crafter::MacAddr::BROADCAST));
    }
}
