#![cfg(feature = "quic-endpoint")]

use std::{cell::RefCell, rc::Rc};

use crafter::{Ipv4, NetworkLayer, Packet, Quic, QuicLongHeaderPacket, QuicPacketNumber, Udp};
use crafter_flow::prelude::*;

fn provider_batch() -> (Vec<Packet>, Vec<Vec<u8>>) {
    let initial = QuicLongHeaderPacket::initial_builder()
        .packet_number(QuicPacketNumber::new(1))
        .payload([0xbe])
        .build()
        .expect("bounded Initial fixture builds");
    let handshake = QuicLongHeaderPacket::handshake_builder()
        .packet_number(QuicPacketNumber::new(2))
        .payload([0xef])
        .build()
        .expect("bounded Handshake fixture builds");
    let mut coalesced = initial.as_bytes().to_vec();
    coalesced.extend_from_slice(handshake.as_bytes());

    // Generic packet inspection deliberately keeps this endpoint-context-dependent
    // short header opaque. These are synthetic protected bytes, not a traffic key.
    let short_header = vec![0x40, 0x11, 0x22, 0x33, 0x44, 0xaa, 0xbb];
    let payloads = vec![coalesced, short_header];
    let packets = payloads
        .iter()
        .cloned()
        .map(|payload| {
            Ipv4::new()
                .src(docaddr::CLIENT_IPV4)
                .dst(docaddr::SERVER_IPV4)
                / Udp::new().sport(44_300).dport(443)
                / Quic::from_bytes(payload)
        })
        .collect();

    (packets, payloads)
}

#[test]
fn provider_output_uses_normal_offline_packet_surfaces() {
    let (packets, expected_payloads) = provider_batch();
    let expected_payloads_for_flow = expected_payloads.clone();
    let mut flow = Flow::new("quic-packet-surface")
        .role(Role::Initiator)
        .state(
            FlowState::new("Emit")
                .on_entry(move |_context| {
                    Ok(Step::send_regeneration_only_batch(packets.clone()).goto("Done"))
                })
                .entry_targets(["Done"]),
        )
        .state(
            FlowState::new("Done")
                .on_entry(|_context| Ok(Step::done()))
                .entry_terminal(),
        )
        .initial("Emit");

    let visits = Rc::new(RefCell::new(Vec::<Packet>::new()));
    let visits_for_mutator = Rc::clone(&visits);
    let mutator = FnMutator::new("record-quic-provider-order", move |packet, _, _| {
        assert!(packet.layer::<Ipv4>().is_some());
        assert!(packet.layer::<Udp>().is_some());
        assert!(packet.layer::<Quic>().is_some());
        visits_for_mutator.borrow_mut().push(packet.clone());
        Ok(packet)
    });
    let options = RunOptions::default().binding(Binding::default().network_layer());
    let mut runner = Runner::with_options(options)
        .expect("dry-run Conversation opens without sockets")
        .mutator(mutator);

    assert!(runner.is_dry_run());
    assert_eq!(runner.live_sender_open_count(), 0);
    let report = runner
        .run(&mut flow)
        .expect("offline packet surface run completes");

    assert_eq!(
        visits
            .borrow()
            .iter()
            .map(|packet| packet.layer::<Quic>().unwrap().payload_bytes().to_vec())
            .collect::<Vec<_>>(),
        expected_payloads_for_flow
    );
    assert_eq!(visits.borrow().len(), runner.send_reports().len());
    assert_eq!(report.outcome(), &FlowOutcome::Completed);
    assert!(report.is_dry_run());
    assert_eq!(report.sent_count(), runner.send_reports().len());
    assert_eq!(report.received_count(), 0);
    // Protected transport bytes are not application payload observations.
    assert_eq!(report.bytes_sent(), 0);
    assert_eq!(report.bytes_received(), 0);

    let planned_bytes = runner
        .send_reports()
        .iter()
        .map(|send| {
            assert!(send.is_dry_run());
            assert_eq!(send.bytes_sent(), send.plan().len());
            send.bytes_sent()
        })
        .sum::<usize>();
    assert!(planned_bytes > expected_payloads.iter().map(Vec::len).sum());

    for (index, ((send, expected_payload), visited)) in runner
        .send_reports()
        .iter()
        .zip(expected_payloads.iter())
        .zip(visits.borrow().iter())
        .enumerate()
    {
        let packet = Packet::decode_from_l3(NetworkLayer::Ipv4, send.plan().bytes())
            .expect("dry-run plan decodes through the normal IPv4 entrypoint");
        let ipv4 = packet.layer::<Ipv4>().expect("typed IPv4 layer");
        let udp = packet.layer::<Udp>().expect("typed UDP layer");
        let quic = visited.layer::<Quic>().expect("typed QUIC layer");

        assert_eq!(ipv4.source(), docaddr::CLIENT_IPV4);
        assert_eq!(ipv4.destination(), docaddr::SERVER_IPV4);
        assert_eq!(udp.source_port_value(), 44_300);
        assert_eq!(udp.destination_port_value(), 443);
        assert_eq!(quic.payload_bytes(), expected_payload);
        assert!(visited.summary().contains("Ipv4"));
        assert!(visited.summary().contains("Udp"));
        assert!(visited.summary().contains("Quic"));
        assert!(visited.show().contains("[2] Quic"));
        packet.compile().expect("inspected packet recompiles");

        if index == 0 {
            let decoded_quic = packet.layer::<Quic>().expect("coalesced QUIC decodes");
            assert_eq!(
                decoded_quic.packets().len(),
                2,
                "coalesced packet order survives"
            );
            assert_eq!(
                Packet::from_layer(decoded_quic.clone())
                    .compile()
                    .unwrap()
                    .as_bytes(),
                expected_payload
            );
        } else {
            assert!(quic.packets().is_empty());
            assert_eq!(quic.payload_bytes(), expected_payload);
            let raw = packet
                .layer::<crafter::Raw>()
                .expect("ambiguous short header stays raw");
            assert_eq!(raw.as_bytes(), expected_payload);
        }
    }

    let rendered = format!("{}\n{}", report.summary(), report.show());
    assert!(rendered.contains("dry_run=true") || rendered.contains("dry-run: true"));
    assert!(!rendered.contains("PRIVATE KEY"));
    assert!(!rendered.contains("traffic secret"));
    assert!(!rendered.contains("credential"));
}
