//! RFC 7641 Observe integration coverage through the public packet API.
//!
//! Every network envelope uses documentation addresses and remains offline.
//! Observe registration state, cancellation state, retransmission, and timers
//! deliberately remain outside these packet-local tests.

use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const CLIENT_PORT: u16 = 49_152;
const TOKEN: &[u8] = &[0xaa];
const UNKNOWN_OPTION: u16 = 2_048;

const REGISTRATION: &[u8] = &[
    0x41, 0x01, 0x10, 0x01, 0xaa, // V1, CON, TKL 1, GET, MID 0x1001, token.
    0x60, // Observe 6: delta 6, empty uint value 0.
    0x57, b's', b'e', b'n', b's', b'o', b'r', b's', // Uri-Path 11: delta 5, length 7.
];

const DEREGISTRATION: &[u8] = &[
    0x41, 0x01, 0x10, 0x02, 0xaa, // V1, CON, TKL 1, GET, MID 0x1002, token.
    0x61, 0x01, // Observe 6: delta 6, one-byte uint value 1.
    0x57, b's', b'e', b'n', b's', b'o', b'r', b's', // Uri-Path 11: delta 5, length 7.
];

const INITIAL_RESPONSE: &[u8] = &[
    0x61, 0x45, 0x10, 0x01, 0xaa, // V1, ACK, TKL 1, 2.05, MID 0x1001, token.
    0x41, 0x10, // ETag 4: delta 4, length 1.
    0x20, // Observe 6: delta 2, empty uint value 0.
    0x60, // Content-Format 12: delta 6, empty uint value 0.
    0x21, 0x1e, // Max-Age 14: delta 2, one-byte uint value 30.
    0xff, b'2', b'2', // Payload marker and representation.
];

const CHANGED_NOTIFICATION: &[u8] = &[
    0x51, 0x45, 0x10, 0x02, 0xaa, // V1, NON, TKL 1, 2.05, MID 0x1002, token.
    0x41, 0x11, // ETag 4: delta 4, length 1.
    0x21, 0x01, // Observe 6: delta 2, one-byte uint value 1.
    0x81, 0x05, // Max-Age 14: delta 8, one-byte uint value 5.
    0xe2, 0x06, 0xe5, 0xde, 0xad, // Unknown 2048: delta 2034 => 14 + 0x06e5, length 2.
    0xff, b'2', b'3', // Payload marker and representation.
];

fn registration(message_id: u16) -> Coap {
    Coap::observe_registration()
        .confirmable()
        .message_id(message_id)
        .token(CoapToken::from_bytes(TOKEN))
        .uri_path("sensors")
}

fn deregistration(message_id: u16) -> Coap {
    Coap::observe_deregistration()
        .confirmable()
        .message_id(message_id)
        .token(CoapToken::from_bytes(TOKEN))
        .uri_path("sensors")
}

fn initial_response() -> Coap {
    Coap::content()
        .acknowledgement()
        .message_id(0x1001)
        .token(CoapToken::from_bytes(TOKEN))
        .etag(vec![0x10])
        .observe(CoapObserve::register())
        .content_format(CoapContentFormat::new(0))
        .option(CoapOption::from(CoapMaxAge::new(30)))
        .payload(b"22".to_vec())
}

fn changed_notification() -> Coap {
    Coap::content()
        .non_confirmable()
        .message_id(0x1002)
        .token(CoapToken::from_bytes(TOKEN))
        .etag(vec![0x11])
        .observe(CoapObserve::new(1))
        .option(CoapOption::from(CoapMaxAge::new(5)))
        .option(CoapOption::new(UNKNOWN_OPTION, [0xde, 0xad]))
        .payload(b"23".to_vec())
}

fn compile_coap(message: Coap) -> Result<Vec<u8>> {
    Ok(Packet::from_layer(message).compile()?.into_bytes())
}

#[test]
fn registration_deregistration_initial_response_and_reset_are_byte_exact() -> Result<()> {
    assert_eq!(compile_coap(registration(0x1001))?, REGISTRATION);
    assert_eq!(compile_coap(deregistration(0x1002))?, DEREGISTRATION);
    assert_eq!(compile_coap(initial_response())?, INITIAL_RESPONSE);

    let registration = decode_coap(REGISTRATION)?;
    assert!(registration.is_observe_request());
    assert!(registration.is_observe_registration());
    assert!(!registration.is_observe_deregistration());
    let registration_value = registration.observe_value().expect("Observe option")?;
    assert_eq!(registration_value.value(), 0);
    assert_eq!(registration_value.as_bytes(), b"");
    assert_eq!(compile_coap(registration)?, REGISTRATION);

    let deregistration = decode_coap(DEREGISTRATION)?;
    assert!(deregistration.is_observe_request());
    assert!(deregistration.is_observe_deregistration());
    assert_eq!(
        deregistration
            .observe_value()
            .expect("Observe option")?
            .as_bytes(),
        &[0x01]
    );
    assert_eq!(compile_coap(deregistration)?, DEREGISTRATION);

    let initial = decode_coap(INITIAL_RESPONSE)?;
    assert!(initial.is_observe_notification());
    assert_eq!(
        initial
            .observe_notification()
            .expect("notification")?
            .value(),
        0
    );
    let options = initial.options_value();
    let etag = CoapEtag::try_from(&options[0])?;
    let max_age = CoapMaxAge::try_from(&options[3])?;
    assert_eq!(etag.as_bytes(), &[0x10]);
    assert_eq!(max_age.value(), 30);
    assert_eq!(CoapMaxAge::effective_response_seconds(Some(&max_age)), 30);
    assert_eq!(CoapMaxAge::effective_response_seconds(None), 60);
    assert_eq!(compile_coap(initial.clone())?, INITIAL_RESPONSE);
    assert_eq!(
        initial.summary(),
        "Coap(version=1, type=acknowledgement, code=2.05(Content), mid=0x1001, token_len=1, options=4, marker=present, payload=2 bytes)"
    );
    let show = Packet::from_layer(initial).show();
    assert!(show.contains("ETag(4,len=1,hex=10)"), "{show}");
    assert!(show.contains("Observe(6,len=0,hex=)"), "{show}");
    assert!(show.contains("Max-Age(14,len=1,hex=1e)"), "{show}");

    let reset_bytes = [0x70, 0x00, 0x10, 0x02];
    assert_eq!(compile_coap(Coap::empty_reset(0x1002))?, reset_bytes);
    let reset = decode_coap(&reset_bytes)?;
    assert!(reset.is_reset());
    assert!(reset.is_empty());
    assert!(!reset.has_observe());
    assert!(reset.validate().is_clean());
    assert_eq!(compile_coap(reset)?, reset_bytes);

    Ok(())
}

#[test]
fn notifications_preserve_etag_max_age_unknown_options_and_inspection() -> Result<()> {
    assert_eq!(compile_coap(changed_notification())?, CHANGED_NOTIFICATION);
    assert_eq!(
        &CHANGED_NOTIFICATION[5..16],
        &[0x41, 0x11, 0x21, 0x01, 0x81, 0x05, 0xe2, 0x06, 0xe5, 0xde, 0xad]
    );

    let initial = decode_coap(INITIAL_RESPONSE)?;
    let changed = decode_coap(CHANGED_NOTIFICATION)?;
    assert!(changed.is_observe_notification());
    assert_eq!(
        changed
            .observe_notification()
            .expect("notification")?
            .value(),
        1
    );
    assert_eq!(changed.options_value().len(), 4);

    let initial_etag = CoapEtag::try_from(&initial.options_value()[0])?;
    let changed_etag = CoapEtag::try_from(&changed.options_value()[0])?;
    assert_eq!(initial_etag.as_bytes(), &[0x10]);
    assert_eq!(changed_etag.as_bytes(), &[0x11]);
    assert_ne!(initial_etag, changed_etag);

    let max_age = CoapMaxAge::try_from(&changed.options_value()[2])?;
    assert_eq!(max_age.value(), 5);
    assert_eq!(max_age.as_bytes(), &[0x05]);
    assert_eq!(changed.options_value()[3].number().value(), UNKNOWN_OPTION);
    assert_eq!(changed.options_value()[3].value(), &[0xde, 0xad]);
    assert_eq!(compile_coap(changed.clone())?, CHANGED_NOTIFICATION);

    let packet = Packet::from_layer(changed);
    assert!(packet.summary().contains("options=4"));
    let show = packet.show();
    assert!(show.contains("Observe(6,len=1,hex=01)"), "{show}");
    assert!(show.contains("option-2048(2048,len=2,hex=dead)"), "{show}");

    Ok(())
}

#[test]
fn observe_serial_ordering_handles_wraparound_without_subscription_state() {
    let maximum = CoapObserve::new(CoapObserve::MAX_VALUE);
    let zero = CoapObserve::new(0);
    let one = CoapObserve::new(1);
    let half_range = CoapObserve::new(1 << 23);

    assert_eq!(maximum.as_bytes(), &[0xff, 0xff, 0xff]);
    assert_eq!(zero.as_bytes(), b"");
    assert_eq!(zero.is_newer_than(&maximum), CoapObserveOrdering::Newer);
    assert!(zero.is_newer_than(&maximum).is_newer());
    assert_eq!(maximum.is_newer_than(&zero), CoapObserveOrdering::Older);
    assert_eq!(one.is_newer_than(&zero), CoapObserveOrdering::Newer);
    assert_eq!(one.is_newer_than(&one), CoapObserveOrdering::Duplicate);
    assert!(one.is_newer_than(&one).is_duplicate());
    assert_eq!(
        half_range.is_newer_than(&zero),
        CoapObserveOrdering::Ambiguous
    );
}

#[test]
fn observe_packets_round_trip_through_ipv4_and_ipv6_udp_stacks() -> Result<()> {
    let ipv4_client = Ipv4Addr::new(192, 0, 2, 10);
    let ipv4_server = Ipv4Addr::new(198, 51, 100, 20);
    let request = Ipv4::with_addresses(ipv4_client, ipv4_server)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / registration(0x1001);
    let request_bytes = request.compile()?;
    let decoded_request = Packet::decode_from_l3(NetworkLayer::Ipv4, request_bytes.as_bytes())?;
    let observe_request = decoded_request.layer::<Coap>().expect("typed CoAP request");
    assert!(observe_request.is_observe_registration());
    assert_eq!(
        observe_request
            .observe_value()
            .expect("Observe option")?
            .as_bytes(),
        b""
    );
    assert_eq!(
        decoded_request.compile()?.as_bytes(),
        request_bytes.as_bytes()
    );

    let ipv6_server = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20);
    let ipv6_client = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
    let response = Ipv6::with_addresses(ipv6_server, ipv6_client)
        / Udp::new().sport(COAP_PORT).dport(CLIENT_PORT)
        / changed_notification();
    let response_bytes = response.compile()?;
    let decoded_response = Packet::decode_from_l3(NetworkLayer::Ipv6, response_bytes.as_bytes())?;
    let notification = decoded_response
        .layer::<Coap>()
        .expect("typed CoAP notification");
    assert!(notification.is_observe_notification());
    assert_eq!(
        notification.options_value()[3].number().value(),
        UNKNOWN_OPTION
    );
    assert_eq!(notification.options_value()[3].value(), &[0xde, 0xad]);
    assert_eq!(
        decoded_response.compile()?.as_bytes(),
        response_bytes.as_bytes()
    );

    Ok(())
}

#[test]
fn malformed_option_lengths_remain_raw_and_opt_in_validation_reports_them() -> Result<()> {
    const MALFORMED: &[u8] = &[
        0x50, 0x45, 0x30, 0x01, // V1, NON, TKL 0, 2.05, MID 0x3001.
        0x40, // Empty ETag: delta 4, length 0.
        0x24, 0x00, 0x00, 0x00, 0x02, // Four-byte Observe: delta 2, length 4.
        0x85, 0x00, 0x00, 0x00, 0x00, 0x01, // Five-byte Max-Age: delta 8, length 5.
    ];

    let built = Coap::content()
        .non_confirmable()
        .message_id(0x3001)
        .option(CoapOption::new(COAP_OPTION_ETAG, []))
        .option(CoapOption::new(
            COAP_OPTION_OBSERVE,
            [0x00, 0x00, 0x00, 0x02],
        ))
        .option(CoapOption::new(
            COAP_OPTION_MAX_AGE,
            [0x00, 0x00, 0x00, 0x00, 0x01],
        ));
    assert_eq!(compile_coap(built)?, MALFORMED);

    let decoded = decode_coap(MALFORMED)?;
    assert_eq!(decoded.options_value()[0].value(), b"");
    assert_eq!(
        decoded.options_value()[1].value(),
        &[0x00, 0x00, 0x00, 0x02]
    );
    assert_eq!(
        decoded.options_value()[2].value(),
        &[0x00, 0x00, 0x00, 0x00, 0x01]
    );
    assert!(CoapEtag::try_from(&decoded.options_value()[0]).is_err());
    assert!(decoded.observe_value().expect("Observe option").is_err());
    assert!(CoapMaxAge::try_from(&decoded.options_value()[2]).is_err());
    assert_eq!(compile_coap(decoded.clone())?, MALFORMED);

    let validation = decoded.validate();
    let length_fields = validation
        .issues()
        .iter()
        .filter(|issue| issue.category() == CoapValidationCategory::OptionLength)
        .map(|issue| issue.field())
        .collect::<Vec<_>>();
    assert_eq!(
        length_fields,
        [
            "coap.options[0].value",
            "coap.options[1].value",
            "coap.options[2].value",
        ]
    );
    assert!(validation.has_errors());

    Ok(())
}
