//! ARP flow templates.

use std::net::Ipv4Addr;

use crafter::MacAddr;

use crate::{Flow, FlowBuilderExt, FlowState, Role};

/// Initial injector state: announce an ARP binding and watch for who-has.
pub const ANNOUNCE: &str = "Announce";

/// Build an ARP injector flow scaffold.
///
/// The asserted binding is `bind_ip -> bind_mac`: this injector claims that
/// `bind_ip` is reachable at `bind_mac`. Tracked examples and tests should pass
/// documentation-space values from [`crate::docaddr`].
pub fn injector_flow(bind_ip: Ipv4Addr, bind_mac: MacAddr) -> Flow {
    let _ = (bind_ip, bind_mac);
    let announce = FlowState::new(ANNOUNCE);

    Flow::new("arp-injector")
        .role(Role::Injector)
        .state(announce)
        .initial(ANNOUNCE)
}

#[cfg(test)]
mod tests {
    use super::{injector_flow, ANNOUNCE};
    use crate::{docaddr, Role};

    #[test]
    fn arp_injector_flow_scaffold_has_injector_role_and_initial_announce() {
        let flow = injector_flow(docaddr::SERVER_IPV4, docaddr::LOCAL_MAC);

        assert_eq!(flow.role(), Role::Injector);
        assert_eq!(flow.initial(), ANNOUNCE);
    }
}
