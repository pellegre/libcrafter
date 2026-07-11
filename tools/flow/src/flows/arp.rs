//! ARP flow templates.

use std::net::Ipv4Addr;

use crafter::MacAddr;

use crate::matcher::LayerMatcher;
use crate::{Flow, FlowBuilderExt, FlowError, FlowState, Role, Step, Transition};

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
        .entry_description("gratuitous ARP is-at")
        .on(who_has_transition(bind_ip, bind_mac));

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

fn who_has_transition(target_ip: Ipv4Addr, bind_mac: MacAddr) -> Transition {
    Transition::on(
        LayerMatcher::where_layer::<crafter::Arp>("who-has target protocol address", move |arp| {
            arp.opcode_value() == u16::from(crafter::ArpOperation::Request)
                && arp.target_ipv4() == Some(target_ip)
        }),
        move |packet, _ctx| {
            let arp = packet.layer::<crafter::Arp>().ok_or_else(|| {
                FlowError::Capture("matched ARP who-has packet has no ARP layer".to_string())
            })?;
            let requester_ip = arp.sender_ipv4().ok_or_else(|| {
                FlowError::Capture("matched ARP who-has has no requester IPv4".to_string())
            })?;
            let requester_mac = arp.sender_mac().ok_or_else(|| {
                FlowError::Capture("matched ARP who-has has no requester MAC".to_string())
            })?;
            let requested_ip = arp.target_ipv4().ok_or_else(|| {
                FlowError::Capture("matched ARP who-has has no target IPv4".to_string())
            })?;

            Ok(Step::emit(unicast_arp_reply(
                requested_ip,
                bind_mac,
                requester_ip,
                requester_mac,
            )))
        },
    )
}

fn unicast_arp_reply(
    requested_ip: Ipv4Addr,
    bind_mac: MacAddr,
    requester_ip: Ipv4Addr,
    requester_mac: MacAddr,
) -> crafter::Packet {
    crafter::Ethernet::new().src(bind_mac).dst(requester_mac)
        / crafter::Arp::is_at(requested_ip, bind_mac, requester_ip, requester_mac)
}

#[cfg(test)]
mod tests {
    use super::{injector_flow, ANNOUNCE};
    use crate::{docaddr, PacketContext, Role};
    use std::net::Ipv4Addr;

    fn who_has(
        requester_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        requester_mac: crafter::MacAddr,
    ) -> crafter::Packet {
        crafter::Ethernet::new()
            .src(requester_mac)
            .dst(crafter::MacAddr::BROADCAST)
            / crafter::Arp::who_has(requester_ip, target_ip, requester_mac)
    }

    #[test]
    fn arp_injector_flow_scaffold_has_injector_role_and_initial_announce() {
        let flow = injector_flow(docaddr::SERVER_IPV4, docaddr::LOCAL_MAC);

        assert_eq!(flow.role(), Role::Injector);
        assert_eq!(flow.initial(), ANNOUNCE);
    }

    #[test]
    fn arp_injector_flow_validates_and_show_lists_emission_and_reaction() {
        let flow = injector_flow(docaddr::SERVER_IPV4, docaddr::LOCAL_MAC);

        flow.validate().expect("ARP injector flow validates");
        assert_eq!(flow.role(), Role::Injector);

        let show = flow.show();
        for expected in [
            ANNOUNCE,
            "Injector",
            "gratuitous ARP is-at",
            "who-has target protocol address",
        ] {
            assert!(
                show.contains(expected),
                "flow show should contain {expected}: {show}"
            );
        }
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
        assert_eq!(
            arp.opcode_value(),
            u16::from(crafter::ArpOperation::Reply)
        );
        assert_eq!(arp.sender_ipv4(), Some(bind_ip));
        assert_eq!(arp.sender_mac(), Some(bind_mac));
        assert_eq!(arp.target_ipv4(), Some(bind_ip));
        assert_eq!(arp.target_mac(), Some(crafter::MacAddr::BROADCAST));
    }

    #[test]
    fn arp_announce_reacts_to_who_has_for_bound_ip_with_unicast_is_at() {
        let bind_ip = docaddr::SERVER_IPV4;
        let bind_mac = docaddr::LOCAL_MAC;
        let requester_ip = docaddr::CLIENT_IPV4;
        let requester_mac = docaddr::CLIENT_MAC;
        let mut flow = injector_flow(bind_ip, bind_mac);
        let mut context = PacketContext::new();
        let request = who_has(requester_ip, bind_ip, requester_mac);
        let wrong_target = who_has(requester_ip, docaddr::GATEWAY_IPV4, requester_mac);

        let announce = flow.state(ANNOUNCE).expect("Announce state exists");
        assert!(announce.transitions()[0].matches(&request, &context));
        assert!(!announce.transitions()[0].matches(&wrong_target, &context));

        let step = flow
            .state_mut(ANNOUNCE)
            .expect("Announce state exists")
            .find_transition(&request, &context)
            .expect("matching ARP who-has transition")
            .fire(&request, &mut context)
            .expect("ARP who-has handler succeeds");
        let reply = step.outgoing().expect("who-has emits ARP reply");
        let ethernet = reply
            .layer::<crafter::Ethernet>()
            .expect("reply has Ethernet");
        let arp = reply.layer::<crafter::Arp>().expect("reply has ARP");

        assert!(!step.expects_reply());
        assert_eq!(step.target(), None);
        assert_eq!(ethernet.source(), Some(bind_mac));
        assert_eq!(ethernet.destination(), Some(requester_mac));
        assert_eq!(
            arp.opcode_value(),
            u16::from(crafter::ArpOperation::Reply)
        );
        assert_eq!(arp.sender_ipv4(), Some(bind_ip));
        assert_eq!(arp.sender_mac(), Some(bind_mac));
        assert_eq!(arp.target_ipv4(), Some(requester_ip));
        assert_eq!(arp.target_mac(), Some(requester_mac));
    }
}
