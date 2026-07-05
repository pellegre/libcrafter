//! DHCPv4 flow templates.

use crafter::MacAddr;

use crate::{Flow, FlowBuilderExt, FlowState, Role, Step};

/// Initial client state: send DISCOVER and wait for OFFER.
pub const SELECTING: &str = "Selecting";
/// Client state after receiving an OFFER: send REQUEST and wait for ACK.
pub const REQUESTING: &str = "Requesting";
/// Terminal client state after ACK.
pub const BOUND: &str = "Bound";

/// Build the DHCPv4 client flow scaffold.
pub fn client_flow(client_mac: MacAddr) -> Flow {
    let selecting = FlowState::new(SELECTING).on_entry(move |ctx| {
        ctx.set_client_mac(client_mac);
        Ok(Step::stay())
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

#[cfg(test)]
mod tests {
    use super::{client_flow, BOUND, REQUESTING, SELECTING};
    use crate::{docaddr, Role};

    #[test]
    fn dhcpv4_client_flow_scaffold_has_client_states() {
        let flow = client_flow(docaddr::CLIENT_MAC);

        assert_eq!(flow.role(), Role::Initiator);
        assert_eq!(flow.initial(), SELECTING);
        assert!(flow.state(SELECTING).is_some());
        assert!(flow.state(REQUESTING).is_some());
        assert!(flow.state(BOUND).is_some());
    }
}
