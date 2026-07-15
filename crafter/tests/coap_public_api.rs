use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const CLIENT_PORT: u16 = 49_152;
const MESSAGE_ID: u16 = 0x1234;
const UNKNOWN_OPTION_NUMBER: u16 = 65_021;

fn request() -> Coap {
    Coap::get()
        .message_id(MESSAGE_ID)
        .token(CoapToken::new([0xaa, 0xbb]).expect("base token is valid"))
        .option(CoapOption::from_string(COAP_OPTION_URI_PATH, "status"))
        .option(CoapOption::new(UNKNOWN_OPTION_NUMBER, [0xde, 0xad]))
        .payload(b"probe".to_vec())
}

fn assert_request_round_trip(packet: Packet, network_layer: NetworkLayer) -> Result<()> {
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(network_layer, compiled.as_bytes())?;

    assert!(decoded.layer::<Udp>().is_some());
    let coap = decoded.layer::<Coap>().expect("registry decoded CoAP");
    assert_eq!(coap.version_value(), CoapVersion::current());
    assert_eq!(coap.message_type_value(), CoapMessageType::Confirmable);
    assert_eq!(coap.code_value(), CoapCode::get());
    assert_eq!(coap.message_id_value(), MESSAGE_ID);
    assert_eq!(coap.token_value().as_bytes(), [0xaa, 0xbb]);
    assert_eq!(coap.options_value().len(), 2);
    assert_eq!(
        coap.options_value()[0].number(),
        CoapOptionNumber::from_wire(COAP_OPTION_URI_PATH)
    );
    assert_eq!(coap.options_value()[0].value(), b"status");
    assert_eq!(
        coap.options_value()[1].number(),
        CoapOptionNumber::from_wire(UNKNOWN_OPTION_NUMBER)
    );
    assert_eq!(coap.options_value()[1].value(), [0xde, 0xad]);
    assert_eq!(coap.payload_value(), b"probe");

    let summary = decoded.summary();
    assert!(summary.contains("Coap("), "{summary}");
    assert!(summary.contains("code=0.01(GET)"), "{summary}");
    assert!(summary.contains("options=2"), "{summary}");
    assert!(summary.contains("payload=5 bytes"), "{summary}");

    let show = decoded.show();
    assert!(show.contains("[2] Coap"), "{show}");
    assert!(show.contains("message_id: 0x1234"), "{show}");
    assert!(show.contains("options: 2 ["), "{show}");
    assert!(show.contains("payload_length: 5"), "{show}");

    assert_eq!(decoded.compile()?.as_bytes(), compiled.as_bytes());
    Ok(())
}

#[test]
fn prelude_builds_and_decodes_ipv4_requests_from_slash_and_helper_paths() -> Result<()> {
    let client = Ipv4Addr::new(192, 0, 2, 10);
    let server = Ipv4Addr::new(198, 51, 100, 20);

    let composed = Ipv4::with_addresses(client, server)
        / Udp::new().sport(CLIENT_PORT).dport(COAP_PORT)
        / request();
    assert_request_round_trip(composed, NetworkLayer::Ipv4)?;

    let helper = coap_ipv4_request(client, server, request());
    assert_request_round_trip(helper, NetworkLayer::Ipv4)
}

#[test]
fn prelude_builds_and_decodes_ipv6_requests_from_slash_and_helper_paths() -> Result<()> {
    let client = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10);
    let server = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20);

    let composed = Ipv6::with_addresses(client, server)
        / coap_request_udp().source_port(CLIENT_PORT)
        / request();
    assert_request_round_trip(composed, NetworkLayer::Ipv6)?;

    let helper = coap_ipv6_request(client, server, request());
    assert_request_round_trip(helper, NetworkLayer::Ipv6)
}

#[test]
fn coap_symbols_resolve_through_every_public_surface() -> Result<()> {
    fn assert_layer<T: Layer>() {}

    assert_layer::<crafter::protocols::coap::Coap>();
    assert_layer::<crafter::Coap>();
    assert_layer::<crafter::core::Coap>();
    assert_layer::<crafter::prelude::Coap>();

    let unknown_code = crafter::CoapCode::from_wire(0x1f);
    let unknown_option = crafter::core::CoapOption::new(
        crafter::protocols::coap::CoapOptionNumber::from_wire(UNKNOWN_OPTION_NUMBER),
        [0xca, 0xfe],
    );
    let message = crafter::prelude::Coap::request(unknown_code)
        .message_id(0xabcd)
        .option(unknown_option);

    let compiled = Packet::from_layer(message).compile()?;
    let decoded = crafter::protocols::coap::decode_coap(compiled.as_bytes())?;
    assert_eq!(decoded.code_value(), unknown_code);
    assert_eq!(
        decoded.options_value()[0].number().value(),
        UNKNOWN_OPTION_NUMBER
    );
    assert_eq!(decoded.options_value()[0].value(), [0xca, 0xfe]);

    let _: fn(&[u8]) -> crafter::Result<crafter::Coap> = crafter::decode_coap;
    let _: fn(&[u8]) -> crafter::Result<crafter::core::Coap> = crafter::core::decode_coap;
    let _: fn(&[u8]) -> crafter::Result<crafter::prelude::Coap> = crafter::prelude::decode_coap;

    Ok(())
}
