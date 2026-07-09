//! Built-in protocol flow templates.

pub mod arp;
pub mod dhcpv4;
pub mod dns;
pub mod tcp;

#[cfg(test)]
mod tests {
    use crate as crafter_flow;
    use std::net::Ipv4Addr;

    #[test]
    fn tcp_flow_entrypoints_are_public() {
        use crafter_flow::flows::tcp::{client_flow, server_flow};

        let _client_flow: fn(Ipv4Addr, Ipv4Addr, u16, Option<Vec<u8>>) -> crafter_flow::Flow =
            client_flow;
        let _server_flow: fn(Ipv4Addr, u16, Option<Vec<u8>>) -> crafter_flow::Flow = server_flow;
    }
}
