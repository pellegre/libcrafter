//! DNS flow templates.

use std::net::Ipv4Addr;

use crate::matcher::LayerMatcher;
use crate::{Flow, FlowBuilderExt, FlowState, Role};

/// Initial injector state: watch for the spoofed DNS query.
pub const WATCH: &str = "Watch";

/// DNS query values captured from a matched request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// DNS transaction id to reuse in the forged answer.
    pub transaction_id: u16,
    /// First question name in canonical trailing-dot presentation form.
    pub question_name: String,
}

/// Build a DNS spoofing injector flow scaffold.
///
/// Tracked examples and tests should pass an `answer_ip` from `192.0.2.0/24`.
/// The query matcher lives in this module; forged response emission is filled in
/// by the next DNS flow step.
pub fn spoof_flow(spoof_name: &str, answer_ip: Ipv4Addr) -> Flow {
    let _ = (spoof_name, answer_ip);
    let watch = FlowState::new(WATCH);

    Flow::new("dns-spoof")
        .role(Role::Injector)
        .state(watch)
        .initial(WATCH)
}

/// Match DNS queries whose first question name equals `spoof_name`.
pub fn query_matcher(spoof_name: &str) -> LayerMatcher {
    let spoof_name = canonical_dns_name(spoof_name);

    LayerMatcher::where_layer::<crafter::Dns>("query for spoofed name", move |dns| {
        extract_query(dns)
            .is_some_and(|query| query.question_name.eq_ignore_ascii_case(&spoof_name))
    })
}

/// Extract the transaction id and first question name from a DNS query.
pub fn extract_query(dns: &crafter::Dns) -> Option<DnsQuery> {
    if dns.is_response() {
        return None;
    }

    dns.questions().first().map(|question| DnsQuery {
        transaction_id: dns.id_value(),
        question_name: question.name().to_string(),
    })
}

fn canonical_dns_name(name: &str) -> String {
    crafter::DnsName::parse(name)
        .map(|name| name.presentation().to_string())
        .unwrap_or_else(|_| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::{extract_query, query_matcher, spoof_flow, WATCH};
    use crate::{docaddr, Matcher, PacketContext, Role};

    fn decoded_dns_message(
        dns: crafter::Dns,
        source_port: u16,
        destination_port: u16,
    ) -> crafter::Packet {
        let packet = crafter::Ipv4::new()
            .src(docaddr::CLIENT_IPV4)
            .dst(docaddr::SERVER_IPV4)
            / crafter::Udp::new()
                .source_port(source_port)
                .destination_port(destination_port)
            / dns;
        let compiled = packet.compile().expect("DNS packet should compile");

        crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("DNS packet should decode")
    }

    #[test]
    fn dns_spoof_flow_scaffold_has_injector_role_and_initial_watch() {
        let flow = spoof_flow("www.example.test.", docaddr::CLIENT_IPV4);

        assert_eq!(flow.role(), Role::Injector);
        assert_eq!(flow.initial(), WATCH);
        assert!(flow.state(WATCH).is_some());
    }

    #[test]
    fn dns_query_matcher_accepts_spoofed_name_and_extracts_query_values() {
        let transaction_id = 0x4a5b;
        let query = decoded_dns_message(
            crafter::Dns::query("WWW.Example.Test", crafter::DNS_TYPE_A).id(transaction_id),
            53000,
            crafter::DNS_PORT,
        );
        let other_query = decoded_dns_message(
            crafter::Dns::query("other.example.test.", crafter::DNS_TYPE_A).id(transaction_id),
            53001,
            crafter::DNS_PORT,
        );
        let response = decoded_dns_message(
            crafter::Dns::query("www.example.test.", crafter::DNS_TYPE_A)
                .id(transaction_id)
                .response(true),
            crafter::DNS_PORT,
            53000,
        );
        let matcher = query_matcher("www.example.test.");
        let context = PacketContext::new();

        assert!(matcher.matches(&query, &context));
        assert!(!matcher.matches(&other_query, &context));
        assert!(!matcher.matches(&response, &context));

        let dns = query.layer::<crafter::Dns>().expect("query has DNS layer");
        let extracted = extract_query(dns).expect("query values should extract");

        assert_eq!(extracted.transaction_id, transaction_id);
        assert_eq!(extracted.question_name, "WWW.Example.Test.");
    }
}
