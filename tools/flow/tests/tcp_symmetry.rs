use crafter_flow::flows::tcp::{
    client_flow, server_flow, CLOSED, CLOSE_WAIT, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, LAST_ACK,
    LISTEN, SYN_RECEIVED, SYN_SENT,
};
use crafter_flow::{docaddr, Flow, PacketContext, Role, Step};

const LISTEN_PORT: u16 = 8080;

struct StepDriver {
    flow: Flow,
    state: String,
    context: PacketContext,
    sent: Vec<crafter::Packet>,
    visited: Vec<String>,
    completed: bool,
}

impl StepDriver {
    fn new(flow: Flow) -> Self {
        let state = flow.initial().to_string();

        Self {
            flow,
            state: state.clone(),
            context: PacketContext::new(),
            sent: Vec::new(),
            visited: vec![state],
            completed: false,
        }
    }

    fn start(&mut self) {
        self.settle_entry();
    }

    fn receive(&mut self, packet: &crafter::Packet) -> bool {
        let step = {
            let state = self
                .flow
                .state_mut(&self.state)
                .expect("current state exists");
            let Some(transition) = state.find_transition(packet, &self.context) else {
                return false;
            };

            transition
                .fire(packet, &mut self.context)
                .expect("matched transition fires")
        };

        if self.apply_step(step) {
            self.settle_entry();
        }

        true
    }

    fn settle_entry(&mut self) {
        while !self.completed {
            let step = self
                .flow
                .state_mut(&self.state)
                .expect("current state exists")
                .run_entry(&mut self.context)
                .expect("state entry runs");
            let Some(step) = step else {
                return;
            };

            if !self.apply_step(step) {
                return;
            }
        }
    }

    fn apply_step(&mut self, step: Step) -> bool {
        let Step {
            outgoing,
            target,
            terminal,
            ..
        } = step;

        if let Some(packet) = outgoing {
            self.sent.push(packet);
        }

        if let Some(target) = target {
            self.state = target;
            self.visited.push(self.state.clone());
            if terminal {
                self.completed = true;
                return false;
            }
            return true;
        }

        if terminal {
            self.completed = true;
        }

        false
    }
}

fn tcp(packet: &crafter::Packet) -> &crafter::Tcp {
    packet.layer::<crafter::Tcp>().expect("packet has TCP")
}

fn raw(packet: &crafter::Packet) -> &[u8] {
    packet
        .layer::<crafter::Raw>()
        .expect("packet has Raw payload")
        .as_bytes()
}

fn payload_bytes(packets: &[crafter::Packet]) -> Vec<u8> {
    packets
        .iter()
        .filter_map(|packet| packet.layer::<crafter::Raw>())
        .flat_map(|raw| raw.as_bytes().iter().copied())
        .collect()
}

#[test]
fn tcp_client_and_server_drive_each_other_offline() {
    let client_payload = b"client bytes over offline TCP".to_vec();
    let server_payload = b"server bytes over offline TCP".to_vec();

    // Both halves use the same TCP segment grammar; only Role and open direction differ.
    let client_flow = client_flow(
        docaddr::CLIENT_IPV4,
        docaddr::SERVER_IPV4,
        LISTEN_PORT,
        Some(client_payload.clone()),
    );
    let server_flow = server_flow(
        docaddr::SERVER_IPV4,
        LISTEN_PORT,
        Some(server_payload.clone()),
    );
    assert_eq!(client_flow.role(), Role::Initiator);
    assert_eq!(server_flow.role(), Role::Responder);

    let mut client = StepDriver::new(client_flow);
    let mut server = StepDriver::new(server_flow);

    client.start();
    assert_eq!(client.sent.len(), 1);
    assert!(server.receive(&client.sent[0]));
    assert!(client.receive(&server.sent[0]));
    assert!(server.receive(&client.sent[1]));
    assert!(server.receive(&client.sent[2]));
    assert!(client.receive(&server.sent[1]));
    assert!(!server.receive(&client.sent[3]));
    assert!(server.receive(&client.sent[4]));
    assert!(client.receive(&server.sent[2]));
    assert!(client.receive(&server.sent[3]));
    assert!(server.receive(&client.sent[5]));

    assert!(client.completed);
    assert!(server.completed);
    assert_eq!(client.state, CLOSED);
    assert_eq!(server.state, CLOSED);
    assert_eq!(
        client.visited,
        [
            SYN_SENT.to_string(),
            ESTABLISHED.to_string(),
            FIN_WAIT_1.to_string(),
            FIN_WAIT_2.to_string(),
            CLOSED.to_string(),
        ]
    );
    assert_eq!(
        server.visited,
        [
            LISTEN.to_string(),
            SYN_RECEIVED.to_string(),
            ESTABLISHED.to_string(),
            CLOSE_WAIT.to_string(),
            LAST_ACK.to_string(),
            CLOSED.to_string(),
        ]
    );

    assert_eq!(payload_bytes(&client.sent), client_payload);
    assert_eq!(payload_bytes(&server.sent), server_payload);
    assert_eq!(
        client.context.tcp_received_payload(),
        server_payload.as_slice()
    );
    assert_eq!(
        server.context.tcp_received_payload(),
        client_payload.as_slice()
    );

    let client_syn = tcp(&client.sent[0]);
    let client_port = client_syn.source_port_value();
    let client_iss = client_syn.sequence_number_value();
    let client_snd_nxt = client_iss.wrapping_add(1);

    assert_eq!(client_syn.destination_port_value(), LISTEN_PORT);
    assert_eq!(client_syn.acknowledgment_number_value(), 0);
    assert_eq!(client_syn.flags_value(), crafter::TCP_FLAG_SYN);

    let server_syn_ack = tcp(&server.sent[0]);
    let server_iss = server_syn_ack.sequence_number_value();
    let server_snd_nxt = server_iss.wrapping_add(1);
    let client_data_end = client_snd_nxt.wrapping_add(client_payload.len() as u32);
    let server_data_end = server_snd_nxt.wrapping_add(server_payload.len() as u32);
    let client_fin_end = client_data_end.wrapping_add(1);
    let server_fin_end = server_data_end.wrapping_add(1);

    assert_eq!(server_syn_ack.source_port_value(), LISTEN_PORT);
    assert_eq!(server_syn_ack.destination_port_value(), client_port);
    assert_eq!(server_syn_ack.acknowledgment_number_value(), client_snd_nxt);
    assert_eq!(
        server_syn_ack.flags_value(),
        crafter::TCP_FLAG_SYN | crafter::TCP_FLAG_ACK
    );

    let client_handshake_ack = tcp(&client.sent[1]);
    assert_eq!(client_handshake_ack.sequence_number_value(), client_snd_nxt);
    assert_eq!(
        client_handshake_ack.acknowledgment_number_value(),
        server_snd_nxt
    );
    assert_eq!(client_handshake_ack.flags_value(), crafter::TCP_FLAG_ACK);

    let client_data = tcp(&client.sent[2]);
    assert_eq!(client_data.sequence_number_value(), client_snd_nxt);
    assert_eq!(client_data.acknowledgment_number_value(), server_snd_nxt);
    assert_eq!(
        client_data.flags_value(),
        crafter::TCP_FLAG_PSH | crafter::TCP_FLAG_ACK
    );
    assert_eq!(raw(&client.sent[2]), client_payload.as_slice());

    let server_data = tcp(&server.sent[1]);
    assert_eq!(server_data.sequence_number_value(), server_snd_nxt);
    assert_eq!(server_data.acknowledgment_number_value(), client_data_end);
    assert_eq!(
        server_data.flags_value(),
        crafter::TCP_FLAG_PSH | crafter::TCP_FLAG_ACK
    );
    assert_eq!(raw(&server.sent[1]), server_payload.as_slice());

    let client_data_ack = tcp(&client.sent[3]);
    assert_eq!(client_data_ack.sequence_number_value(), client_data_end);
    assert_eq!(
        client_data_ack.acknowledgment_number_value(),
        server_data_end
    );
    assert_eq!(client_data_ack.flags_value(), crafter::TCP_FLAG_ACK);

    let client_fin = tcp(&client.sent[4]);
    assert_eq!(client_fin.sequence_number_value(), client_data_end);
    assert_eq!(client_fin.acknowledgment_number_value(), server_data_end);
    assert_eq!(
        client_fin.flags_value(),
        crafter::TCP_FLAG_FIN | crafter::TCP_FLAG_ACK
    );

    let server_fin_ack = tcp(&server.sent[2]);
    assert_eq!(server_fin_ack.sequence_number_value(), server_data_end);
    assert_eq!(server_fin_ack.acknowledgment_number_value(), client_fin_end);
    assert_eq!(server_fin_ack.flags_value(), crafter::TCP_FLAG_ACK);

    let server_fin = tcp(&server.sent[3]);
    assert_eq!(server_fin.sequence_number_value(), server_data_end);
    assert_eq!(server_fin.acknowledgment_number_value(), client_fin_end);
    assert_eq!(
        server_fin.flags_value(),
        crafter::TCP_FLAG_FIN | crafter::TCP_FLAG_ACK
    );

    let client_final_ack = tcp(&client.sent[5]);
    assert_eq!(client_final_ack.sequence_number_value(), client_fin_end);
    assert_eq!(
        client_final_ack.acknowledgment_number_value(),
        server_fin_end
    );
    assert_eq!(client_final_ack.flags_value(), crafter::TCP_FLAG_ACK);
}
