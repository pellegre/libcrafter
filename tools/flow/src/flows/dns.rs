//! DNS flow templates.

use std::net::Ipv4Addr;

use crate::{Flow, FlowBuilderExt, FlowState, Role};

/// Initial injector state: watch for the spoofed DNS query.
pub const WATCH: &str = "Watch";

/// Build a DNS spoofing injector flow scaffold.
///
/// Tracked examples and tests should pass an `answer_ip` from `192.0.2.0/24`.
/// Query matching and forged response emission are filled in by the next DNS
/// flow steps.
pub fn spoof_flow(spoof_name: &str, answer_ip: Ipv4Addr) -> Flow {
    let _ = (spoof_name, answer_ip);
    let watch = FlowState::new(WATCH);

    Flow::new("dns-spoof")
        .role(Role::Injector)
        .state(watch)
        .initial(WATCH)
}

#[cfg(test)]
mod tests {
    use super::{spoof_flow, WATCH};
    use crate::{docaddr, Role};

    #[test]
    fn dns_spoof_flow_scaffold_has_injector_role_and_initial_watch() {
        let flow = spoof_flow("www.example.test.", docaddr::CLIENT_IPV4);

        assert_eq!(flow.role(), Role::Injector);
        assert_eq!(flow.initial(), WATCH);
        assert!(flow.state(WATCH).is_some());
    }
}
