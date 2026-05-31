use super::{Arp, ArpOperation, Ethernet, ETHERTYPE_ARP};
use crate::{CrafterError, LinkType, MacAddr, Packet, Raw};
use core::net::Ipv4Addr;

const ARP_REQUEST_FIXTURE: &[u8] = fixture_bytes!("bytes/arp-who-has.bin");

fn src_mac() -> MacAddr {
    "02:00:5e:00:53:01".parse().unwrap()
}

/// The standard Ethernet/IPv4 ARP reply wire bytes, mirroring the
/// `bytes/ethernet-arp-reply.hex` fixture. A reply built from the public
/// `Arp::is_at` helper must reproduce these bytes exactly so the expanded
/// ARP implementation cannot regress the standard reply golden.
const ARP_REPLY_GOLDEN: &[u8] = &[
    0x02, 0x00, 0x5e, 0x00, 0x53, 0x01, // Ethernet dst = target hardware
    0x02, 0x00, 0x5e, 0x00, 0x53, 0x02, // Ethernet src = sender hardware
    0x08, 0x06, // EtherType = ARP (autofilled)
    0x00, 0x01, // HRD = Ethernet
    0x08, 0x00, // PRO = IPv4
    0x06, // HLN = 6
    0x04, // PLN = 4
    0x00, 0x02, // OP = reply
    0x02, 0x00, 0x5e, 0x00, 0x53, 0x02, // sender hardware
    0xc0, 0x00, 0x02, 0x01, // sender protocol 192.0.2.1
    0x02, 0x00, 0x5e, 0x00, 0x53, 0x01, // target hardware
    0xc0, 0x00, 0x02, 0x0a, // target protocol 192.0.2.10
];

fn sender_mac() -> MacAddr {
    "02:00:5e:00:53:02".parse().unwrap()
}

#[test]
fn arp_request_matches_golden_bytes() {
    let packet = Ethernet::new().src(src_mac())
        / Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            src_mac(),
        );

    assert_eq!(packet.compile().unwrap().as_bytes(), ARP_REQUEST_FIXTURE);
}

#[test]
fn arp_reply_builder_matches_golden_bytes() {
    // A standard Ethernet/IPv4 reply built through `Arp::is_at` plus an
    // Ethernet header (src = sender MAC, dst = target MAC) must compile to
    // the exact reply golden bytes. The Ethernet EtherType is left unset so
    // this also exercises ARP ethertype autofill on the reply path.
    let packet = Ethernet::new().src(sender_mac()).dst(src_mac())
        / Arp::is_at(
            Ipv4Addr::new(192, 0, 2, 1),
            sender_mac(),
            Ipv4Addr::new(192, 0, 2, 10),
            src_mac(),
        );

    assert_eq!(packet.compile().unwrap().as_bytes(), ARP_REPLY_GOLDEN);
}

#[test]
fn arp_who_has_builder_sets_request_fields_and_autofills_ethertype() {
    // `who_has` must produce a request opcode, copy the sender/target
    // protocol addresses, set the sender hardware address, and zero the
    // unknown target hardware address. Wrapping it in a bare Ethernet header
    // (no explicit EtherType) must autofill the ARP EtherType.
    let arp = Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 1),
        src_mac(),
    );
    assert_eq!(arp.opcode_value(), ArpOperation::Request as u16);
    assert_eq!(arp.sender_mac(), Some(src_mac()));
    assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(arp.target_mac(), Some(MacAddr::ZERO));
    assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));

    let frame = (Ethernet::new().src(src_mac()) / arp).compile().unwrap();
    assert_eq!(&frame.as_bytes()[12..14], &ETHERTYPE_ARP.to_be_bytes());
}

#[test]
fn arp_is_at_builder_sets_reply_fields() {
    // `is_at` must produce a reply opcode and place each address in the
    // correct sender/target slot.
    let arp = Arp::is_at(
        Ipv4Addr::new(192, 0, 2, 1),
        sender_mac(),
        Ipv4Addr::new(192, 0, 2, 10),
        src_mac(),
    );
    assert_eq!(arp.opcode_value(), ArpOperation::Reply as u16);
    assert_eq!(arp.sender_mac(), Some(sender_mac()));
    assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(arp.target_mac(), Some(src_mac()));
    assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
}

#[test]
fn arp_compile_decode_round_trip_preserves_standard_request_fields() {
    // A standard request decodes back to the same field values and
    // recompiles byte-exact, locking the compile/decode preservation path
    // for common Ethernet/IPv4 ARP.
    let packet = Ethernet::new().src(src_mac())
        / Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            src_mac(),
        );
    let compiled = packet.compile().unwrap();
    let wire = compiled.as_bytes().to_vec();

    let decoded = Packet::decode_from_link(LinkType::Ethernet, &wire).unwrap();
    let arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(arp.hardware_type_value(), 1);
    assert_eq!(arp.protocol_type_value(), super::ETHERTYPE_IPV4);
    assert_eq!(arp.hardware_len_value(), 6);
    assert_eq!(arp.protocol_len_value(), 4);
    assert_eq!(arp.opcode_value(), ArpOperation::Request as u16);
    assert_eq!(arp.sender_mac(), Some(src_mac()));
    assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(arp.target_mac(), Some(MacAddr::ZERO));
    assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));

    assert_eq!(decoded.compile().unwrap().as_bytes(), wire.as_slice());
}

#[test]
fn arp_decode_exposes_ipv4_and_mac_fields() {
    let decoded = Packet::decode_from_link(LinkType::Ethernet, ARP_REQUEST_FIXTURE).unwrap();
    let arp = decoded.layer::<Arp>().unwrap();

    assert_eq!(arp.hardware_type_value(), 1);
    assert_eq!(arp.protocol_type_value(), super::ETHERTYPE_IPV4);
    assert_eq!(arp.opcode_value(), ArpOperation::Request as u16);
    assert_eq!(arp.sender_mac(), Some(src_mac()));
    assert_eq!(arp.target_mac(), Some(MacAddr::ZERO));
    assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(decoded.compile().unwrap().as_bytes(), ARP_REQUEST_FIXTURE);
}

#[test]
fn arp_rejects_inconsistent_address_lengths() {
    let packet = Packet::new().push(
        Arp::new()
            .hardware_len(5)
            .sender_hardware_addr(src_mac())
            .target_hardware_addr(MacAddr::ZERO),
    );
    let err = packet.compile().unwrap_err();

    // The conflict surfaces as a structured error naming the failing field
    // and both the declared length (5) and the supplied byte count (6).
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "arp.sender_hardware_addr");
            assert_eq!(required, 5);
            assert_eq!(available, 6);
        }
        other => panic!("expected a structured length error, got {other:?}"),
    }
}

#[test]
fn arp_length_matching_explicit_lengths_compile_without_false_positive() {
    // Explicit length fields that agree with the supplied byte vectors must
    // not trip the conflict check. A nonstandard but self-consistent
    // 8-octet hardware / 16-octet protocol body compiles cleanly and the
    // declared lengths reach the wire unchanged.
    let sender_hw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
    let sender_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let target_hw = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let target_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    let arp = Arp::new()
        .hardware_len(8)
        .protocol_len(16)
        .sender_hardware_bytes(sender_hw.clone())
        .sender_protocol_bytes(sender_pa.clone())
        .target_hardware_bytes(target_hw.clone())
        .target_protocol_bytes(target_pa.clone());

    let frame = Ethernet::new().src(src_mac()) / arp;
    let compiled = frame.compile().expect("matching lengths must compile");
    let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes()).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.hardware_len_value(), 8);
    assert_eq!(decoded_arp.protocol_len_value(), 16);
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);
}

#[test]
fn arp_length_mismatch_on_protocol_field_returns_structured_error() {
    // A length conflict on the protocol address field (not just the
    // hardware field) is rejected with a structured error that names the
    // failing field and the declared vs. supplied lengths. This guards
    // against a validation gap that only checks one of the two length
    // fields.
    let packet = Packet::new().push(
        Arp::new()
            .protocol_len(6)
            .sender_protocol_bytes(vec![192, 0, 2, 10]),
    );
    let err = packet.compile().unwrap_err();
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "arp.sender_protocol_addr");
            assert_eq!(required, 6);
            assert_eq!(available, 4);
        }
        other => panic!("expected a structured length error, got {other:?}"),
    }
}

#[test]
fn arp_length_mismatch_on_target_field_returns_structured_error() {
    // The conflict check covers the target address fields as well, so a
    // target hardware byte vector that disagrees with the declared
    // hardware length is rejected with the failing field named.
    let packet = Packet::new().push(
        Arp::new()
            .hardware_len(6)
            .target_hardware_bytes(vec![0xde, 0xad, 0xbe]),
    );
    let err = packet.compile().unwrap_err();
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "arp.target_hardware_addr");
            assert_eq!(required, 6);
            assert_eq!(available, 3);
        }
        other => panic!("expected a structured length error, got {other:?}"),
    }
}

#[test]
fn arp_length_zero_length_addresses_compile_and_round_trip() {
    // Zero-length addresses are valid generic-format ARP per the scope
    // decision (target/arp-rfc/scope.md). An explicit zero length that
    // agrees with empty byte vectors must not be flagged as a conflict,
    // and the eight-byte fixed header round-trips byte-exact.
    let arp = Arp::new()
        .hardware_len(0)
        .protocol_len(0)
        .sender_hardware_bytes(Vec::new())
        .sender_protocol_bytes(Vec::new())
        .target_hardware_bytes(Vec::new())
        .target_protocol_bytes(Vec::new());

    let frame = Ethernet::new().src(src_mac()) / arp;
    let compiled = frame.compile().expect("zero-length ARP must compile");
    let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes()).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.hardware_len_value(), 0);
    assert_eq!(decoded_arp.protocol_len_value(), 0);
    assert!(decoded_arp.sender_hardware_bytes_value().is_empty());
    assert!(decoded_arp.target_protocol_bytes_value().is_empty());
}

#[test]
fn arp_length_zero_length_field_against_nonempty_bytes_is_a_conflict() {
    // A zero-length field paired with a non-empty byte vector is still a
    // conflict: zero-length is only valid when the bytes are also empty.
    let packet = Packet::new().push(Arp::new().protocol_len(0).sender_protocol_bytes(vec![0x01]));
    let err = packet.compile().unwrap_err();
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "arp.sender_protocol_addr");
            assert_eq!(required, 0);
            assert_eq!(available, 1);
        }
        other => panic!("expected a structured length error, got {other:?}"),
    }
}

#[test]
fn arp_length_maximum_u8_length_arithmetic_does_not_overflow() {
    // The maximum representable ARP length is u8::MAX (255). A byte vector
    // of exactly that width agrees with an explicit u8::MAX length and must
    // compile; the encoded_len arithmetic (fixed header + len*2 + len*2)
    // must not overflow. encoded_len reports 8 + 255*2 + 255*2 = 1028.
    let max = u8::MAX;
    let full = vec![0x5a_u8; max as usize];

    let arp = Arp::new()
        .hardware_len(max)
        .protocol_len(max)
        .sender_hardware_bytes(full.clone())
        .sender_protocol_bytes(full.clone())
        .target_hardware_bytes(full.clone())
        .target_protocol_bytes(full.clone());

    assert_eq!(arp.hardware_len_value(), max);
    assert_eq!(arp.protocol_len_value(), max);

    let frame = Ethernet::new().src(src_mac()) / arp;
    let compiled = frame
        .compile()
        .expect("maximum-width ARP addresses must compile");
    let decoded = Packet::decode_from_link(LinkType::Ethernet, compiled.as_bytes()).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.hardware_len_value(), max);
    assert_eq!(decoded_arp.protocol_len_value(), max);
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), full);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), full);
}

#[test]
fn arp_length_oversized_byte_vector_saturates_then_conflicts() {
    // A byte vector beyond the u8 length field saturates the auto-filled
    // length to u8::MAX rather than wrapping, so the genuine mismatch
    // (300 bytes vs. a 255 length ceiling) is caught by the conflict check
    // at compile time instead of silently aliasing a small length.
    let oversized = vec![0u8; 300];
    let arp = Arp::new().sender_hardware(oversized);
    assert_eq!(arp.hardware_len_value(), u8::MAX);

    let err = (Ethernet::new().src(src_mac()) / arp)
        .compile()
        .unwrap_err();
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "arp.sender_hardware_addr");
            assert_eq!(required, u8::MAX as usize);
            assert_eq!(available, 300);
        }
        other => panic!("expected a structured length error, got {other:?}"),
    }
}

#[test]
fn arp_reply_builder_sets_expected_operation() {
    let arp = Arp::is_at(
        Ipv4Addr::new(192, 0, 2, 10),
        src_mac(),
        Ipv4Addr::new(192, 0, 2, 1),
        MacAddr::BROADCAST,
    );

    assert_eq!(arp.opcode_value(), ArpOperation::Reply as u16);
    assert_eq!(arp.sender_mac(), Some(src_mac()));
}

#[test]
fn arp_constants_match_source_backed_codepoints() {
    use super::{
        ARP_HRD_ATM, ARP_HRD_ETHERNET, ARP_HRD_FIBRE_CHANNEL, ARP_HRD_IEEE_802, ARP_HRD_INFINIBAND,
        ARP_HRD_MAPOS, ARP_OP_ARP_NAK, ARP_OP_DRARP_ERROR, ARP_OP_DRARP_REPLY,
        ARP_OP_DRARP_REQUEST, ARP_OP_EXP1, ARP_OP_EXP2, ARP_OP_INARP_REPLY, ARP_OP_INARP_REQUEST,
        ARP_OP_MAPOS_UNARP, ARP_OP_RARP_REPLY, ARP_OP_RARP_REQUEST, ARP_OP_REPLY, ARP_OP_REQUEST,
        ARP_OP_RESERVED, ARP_OP_RESERVED_MAX, ARP_PRO_IPV4, ETHERTYPE_IPV4,
    };

    // Operation codepoints (IANA arp-parameters-1).
    assert_eq!(ARP_OP_RESERVED, 0);
    assert_eq!(ARP_OP_REQUEST, 1);
    assert_eq!(ARP_OP_REPLY, 2);
    assert_eq!(ARP_OP_RARP_REQUEST, 3);
    assert_eq!(ARP_OP_RARP_REPLY, 4);
    assert_eq!(ARP_OP_DRARP_REQUEST, 5);
    assert_eq!(ARP_OP_DRARP_REPLY, 6);
    assert_eq!(ARP_OP_DRARP_ERROR, 7);
    assert_eq!(ARP_OP_INARP_REQUEST, 8);
    assert_eq!(ARP_OP_INARP_REPLY, 9);
    assert_eq!(ARP_OP_ARP_NAK, 10);
    assert_eq!(ARP_OP_MAPOS_UNARP, 23);
    assert_eq!(ARP_OP_EXP1, 24);
    assert_eq!(ARP_OP_EXP2, 25);
    assert_eq!(ARP_OP_RESERVED_MAX, 65535);

    // Named operations agree with the existing ArpOperation enum.
    assert_eq!(ARP_OP_REQUEST, ArpOperation::Request as u16);
    assert_eq!(ARP_OP_REPLY, ArpOperation::Reply as u16);

    // Hardware-type codepoints (IANA arp-parameters-2).
    assert_eq!(ARP_HRD_ETHERNET, 1);
    assert_eq!(ARP_HRD_IEEE_802, 6);
    assert_eq!(ARP_HRD_FIBRE_CHANNEL, 18);
    assert_eq!(ARP_HRD_ATM, 19);
    assert_eq!(ARP_HRD_MAPOS, 25);
    assert_eq!(ARP_HRD_INFINIBAND, 32);

    // Protocol type shares the EtherType space (IANA arp-parameters-3 / RFC 5342).
    assert_eq!(ARP_PRO_IPV4, ETHERTYPE_IPV4);
}

#[test]
fn arp_constants_drive_builder_and_preserve_unknown_values() {
    use super::{ARP_HRD_INFINIBAND, ARP_OP_INARP_REQUEST};

    // Known codepoint constant works through the raw opcode escape hatch.
    let arp = Arp::new()
        .hardware_type(ARP_HRD_INFINIBAND)
        .opcode(ARP_OP_INARP_REQUEST);
    assert_eq!(arp.hardware_type_value(), ARP_HRD_INFINIBAND);
    assert_eq!(arp.opcode_value(), ARP_OP_INARP_REQUEST);

    // An unknown numeric value the constants do not name stays usable and intact.
    let unknown_op: u16 = 0x0fa0;
    let unknown = Arp::new().opcode(unknown_op);
    assert_eq!(unknown.opcode_value(), unknown_op);
}

#[test]
fn arp_constants_reexported_through_prelude() {
    use crate::prelude::{ARP_OP_REPLY, ARP_OP_REQUEST};

    assert_eq!(ARP_OP_REQUEST, 1);
    assert_eq!(ARP_OP_REPLY, 2);
}

#[test]
fn arp_operation_names_known_source_backed_codepoints() {
    use super::{
        ARP_OP_ARP_NAK, ARP_OP_DRARP_ERROR, ARP_OP_DRARP_REPLY, ARP_OP_DRARP_REQUEST,
        ARP_OP_INARP_REPLY, ARP_OP_INARP_REQUEST, ARP_OP_MAPOS_UNARP, ARP_OP_RARP_REPLY,
        ARP_OP_RARP_REQUEST, ARP_OP_REPLY, ARP_OP_REQUEST,
    };
    use crate::packet::Layer;

    // Every named operation round-trips opcode <-> enum (IANA arp-parameters-1).
    let named = [
        (ArpOperation::Request, ARP_OP_REQUEST),
        (ArpOperation::Reply, ARP_OP_REPLY),
        (ArpOperation::RarpRequest, ARP_OP_RARP_REQUEST),
        (ArpOperation::RarpReply, ARP_OP_RARP_REPLY),
        (ArpOperation::DrarpRequest, ARP_OP_DRARP_REQUEST),
        (ArpOperation::DrarpReply, ARP_OP_DRARP_REPLY),
        (ArpOperation::DrarpError, ARP_OP_DRARP_ERROR),
        (ArpOperation::InArpRequest, ARP_OP_INARP_REQUEST),
        (ArpOperation::InArpReply, ARP_OP_INARP_REPLY),
        (ArpOperation::ArpNak, ARP_OP_ARP_NAK),
        (ArpOperation::MaposUnarp, ARP_OP_MAPOS_UNARP),
    ];

    for (operation, opcode) in named {
        assert_eq!(operation.opcode(), opcode);
        assert_eq!(u16::from(operation), opcode);
        assert_eq!(ArpOperation::from_opcode(opcode), Some(operation));
        assert_eq!(ArpOperation::try_from(opcode), Ok(operation));

        // Building through the typed setter records the same opcode.
        let arp = Arp::new().operation(operation);
        assert_eq!(arp.opcode_value(), opcode);
    }

    // request/reply keep their historic short summary labels (golden output).
    assert_eq!(ArpOperation::Request.label(), "request");
    assert_eq!(ArpOperation::Reply.label(), "reply");
    // ARP-family operations are surfaced in summaries by name.
    assert_eq!(ArpOperation::InArpRequest.label(), "inarp-request");

    let reply = Arp::new().operation(ArpOperation::Reply);
    assert!(reply.summary().contains("op=reply"));
    let inarp = Arp::new().operation(ArpOperation::InArpRequest);
    assert!(inarp.summary().contains("op=inarp-request"));
}

#[test]
fn arp_unknown_opcode_stays_numeric_and_round_trips() {
    use crate::packet::Layer;
    use crate::{LinkType, Packet};

    // Values the enum does not name have no conversion but stay usable.
    for unknown in [0_u16, 11, 22, 24, 25, 1024, 0x1234, 65279, 65535] {
        assert_eq!(ArpOperation::from_opcode(unknown), None);
        assert_eq!(ArpOperation::try_from(unknown), Err(unknown));

        let arp = Arp::new().opcode(unknown);
        assert_eq!(arp.opcode_value(), unknown);
        // Unknown opcodes show as their numeric value in summaries.
        assert!(arp.summary().contains(&format!("op={unknown}")));
    }

    // An unknown opcode survives a full Ethernet/ARP compile -> decode cycle.
    let unknown_op: u16 = 0x0fa0;
    let packet = Ethernet::new().src(src_mac())
        / Arp::who_has(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 1),
            src_mac(),
        )
        .opcode(unknown_op);
    let bytes = packet.compile().unwrap();
    let decoded = Packet::decode_from_link(LinkType::Ethernet, bytes.as_bytes()).unwrap();
    let arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(arp.opcode_value(), unknown_op);
    assert_eq!(ArpOperation::from_opcode(arp.opcode_value()), None);
}

#[test]
fn arp_hardware_type_labels_known_source_backed_codepoints() {
    use super::{
        arp_hardware_type_label, ARP_HRD_ATM, ARP_HRD_ETHERNET, ARP_HRD_FIBRE_CHANNEL,
        ARP_HRD_IEEE_802, ARP_HRD_INFINIBAND, ARP_HRD_MAPOS,
    };

    // Each scoped hardware-type constant (IANA arp-parameters-2) gets a label.
    let named = [
        (ARP_HRD_ETHERNET, "ethernet"),
        (ARP_HRD_IEEE_802, "ieee-802"),
        (ARP_HRD_FIBRE_CHANNEL, "fibre-channel"),
        (ARP_HRD_ATM, "atm"),
        (ARP_HRD_MAPOS, "mapos"),
        (ARP_HRD_INFINIBAND, "infiniband"),
    ];

    for (value, label) in named {
        assert_eq!(arp_hardware_type_label(value), Some(label));

        // The same lookup is reachable from a built packet's accessor, and
        // setting the value through the raw u16 setter is preserved intact.
        let arp = Arp::new().hardware_type(value);
        assert_eq!(arp.hardware_type_value(), value);
        assert_eq!(arp.hardware_type_label(), Some(label));
    }
}

#[test]
fn arp_hardware_type_unknown_values_stay_raw_and_unlabeled() {
    use super::{arp_hardware_type_label, ARP_HRD_ETHERNET};

    // Values the registry lookup does not name return None but remain
    // fully usable through the raw hardware_type(u16) setter.
    for unknown in [0_u16, 2, 7, 100, 0x1234, 65535] {
        assert_eq!(arp_hardware_type_label(unknown), None);

        let arp = Arp::new().hardware_type(unknown);
        assert_eq!(arp.hardware_type_value(), unknown);
        assert_eq!(arp.hardware_type_label(), None);
    }

    // The default hardware type (unset) is still Ethernet and labels as such.
    let default_arp = Arp::new();
    assert_eq!(default_arp.hardware_type_value(), ARP_HRD_ETHERNET);
    assert_eq!(default_arp.hardware_type_label(), Some("ethernet"));
}

#[test]
fn arp_hardware_type_label_reexported_through_prelude() {
    use crate::prelude::{arp_hardware_type_label, ARP_HRD_INFINIBAND};

    assert_eq!(
        arp_hardware_type_label(ARP_HRD_INFINIBAND),
        Some("infiniband")
    );
    assert_eq!(arp_hardware_type_label(0x4242), None);
}

#[test]
fn arp_protocol_type_label_known_source_backed_codepoint() {
    use super::{arp_protocol_type_label, ARP_PRO_IPV4, ETHERTYPE_IPV4};

    // The only source-backed known protocol type is IPv4: arp-parameters-3
    // shares the EtherType space and returned no records of its own
    // (scope.md assumption 3). ARP_PRO_IPV4 == ETHERTYPE_IPV4.
    assert_eq!(ARP_PRO_IPV4, ETHERTYPE_IPV4);
    assert_eq!(arp_protocol_type_label(ARP_PRO_IPV4), Some("ipv4"));

    // The label is reachable from a built packet's accessor, and the raw
    // u16 setter preserves the value intact.
    let arp = Arp::new().protocol_type(ARP_PRO_IPV4);
    assert_eq!(arp.protocol_type_value(), ARP_PRO_IPV4);
    assert_eq!(arp.protocol_type_label(), Some("ipv4"));

    // The default protocol type (unset) is still IPv4 and labels as such.
    let default_arp = Arp::new();
    assert_eq!(default_arp.protocol_type_value(), ETHERTYPE_IPV4);
    assert_eq!(default_arp.protocol_type_label(), Some("ipv4"));
}

#[test]
fn arp_protocol_type_unknown_values_stay_raw_and_unlabeled() {
    use super::arp_protocol_type_label;

    // Non-IPv4 protocol identifiers (e.g. IPv6's EtherType, experimental or
    // arbitrary values) are not narrowed: the lookup returns None but the
    // raw protocol_type(u16) setter round-trips the value byte-exact.
    for unknown in [0_u16, 0x0805, 0x86dd, 0x1234, 65535] {
        assert_eq!(arp_protocol_type_label(unknown), None);

        let arp = Arp::new().protocol_type(unknown);
        assert_eq!(arp.protocol_type_value(), unknown);
        assert_eq!(arp.protocol_type_label(), None);
    }
}

#[test]
fn arp_protocol_type_label_reexported_through_prelude() {
    use crate::prelude::{arp_protocol_type_label, ARP_PRO_IPV4};

    assert_eq!(arp_protocol_type_label(ARP_PRO_IPV4), Some("ipv4"));
    assert_eq!(arp_protocol_type_label(0x4242), None);
}

#[test]
fn arp_raw_address_builders_fill_lengths_from_byte_count() {
    let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb];
    let sender_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, 0xcc, 0xdd];
    let target_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    let arp = Arp::new()
        .sender_hardware(sender_hw.clone())
        .sender_protocol(sender_pa.clone())
        .target_hardware(target_hw.clone())
        .target_protocol(target_pa.clone());

    // Lengths follow the supplied byte counts.
    assert_eq!(arp.hardware_len_value(), 8);
    assert_eq!(arp.protocol_len_value(), 16);

    // Raw bytes are preserved exactly.
    assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(arp.target_protocol_bytes_value(), target_pa);

    // The variable-length packet compiles and round-trips byte-exact
    // through an Ethernet frame.
    let frame = Ethernet::new().src(src_mac()) / arp;
    let bytes = frame.compile().unwrap().as_bytes().to_vec();
    let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.hardware_len_value(), 8);
    assert_eq!(decoded_arp.protocol_len_value(), 16);
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);
}

#[test]
fn arp_raw_address_builders_honor_explicit_length_override() {
    // An explicit length set before the bytes is not overwritten, so a
    // deliberately inconsistent packet stays expressible for the later
    // compile-time validation path.
    let arp = Arp::new()
        .hardware_len(5)
        .sender_hardware(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]);
    assert_eq!(arp.hardware_len_value(), 5);
    assert_eq!(
        arp.sender_hardware_bytes_value(),
        vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11]
    );

    // An explicit length set after the bytes is likewise honored.
    let arp = Arp::new()
        .target_protocol(vec![0x0a, 0x0b, 0x0c, 0x0d])
        .protocol_len(2);
    assert_eq!(arp.protocol_len_value(), 2);
    assert_eq!(
        arp.target_protocol_bytes_value(),
        vec![0x0a, 0x0b, 0x0c, 0x0d]
    );
}

#[test]
fn arp_raw_address_builders_accept_zero_length_addresses() {
    let arp = Arp::new()
        .sender_hardware(Vec::<u8>::new())
        .sender_protocol(Vec::<u8>::new())
        .target_hardware(Vec::<u8>::new())
        .target_protocol(Vec::<u8>::new());

    assert_eq!(arp.hardware_len_value(), 0);
    assert_eq!(arp.protocol_len_value(), 0);
    assert!(arp.sender_hardware_bytes_value().is_empty());

    // A zero-length ARP body is just the eight-byte fixed header and
    // round-trips through an Ethernet frame.
    let frame = Ethernet::new().src(src_mac()) / arp;
    let bytes = frame.compile().unwrap().as_bytes().to_vec();
    let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.hardware_len_value(), 0);
    assert_eq!(decoded_arp.protocol_len_value(), 0);
}

#[test]
fn arp_raw_address_builder_saturates_oversized_length() {
    // A byte vector longer than a u8 length field saturates rather than
    // wrapping, so the mismatch is caught by length validation later
    // instead of silently aliasing a small length.
    let oversized = vec![0u8; 300];
    let arp = Arp::new().sender_hardware(oversized);
    assert_eq!(arp.hardware_len_value(), u8::MAX);
    assert_eq!(arp.sender_hardware_bytes_value().len(), 300);
}

#[test]
fn arp_preserves_explicit_fields_through_compile_and_decode() {
    // Every fixed-header field is set explicitly to a value that disagrees
    // with the Ethernet/IPv4 defaults, including the deliberately unusual
    // hardware/protocol types and an unknown opcode. compile() fills nothing
    // it did not need to; each explicit value must reach the wire untouched.
    let sender_hw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
    let sender_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let target_hw = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let target_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    let arp = Arp::new()
        .hardware_type(super::ARP_HRD_INFINIBAND)
        .protocol_type(0x86dd)
        .hardware_len(8)
        .protocol_len(16)
        .opcode(0x0fa0)
        .sender_hardware_bytes(sender_hw.clone())
        .sender_protocol_bytes(sender_pa.clone())
        .target_hardware_bytes(target_hw.clone())
        .target_protocol_bytes(target_pa.clone());

    // The builder records exactly what was set.
    assert_eq!(arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
    assert_eq!(arp.protocol_type_value(), 0x86dd);
    assert_eq!(arp.hardware_len_value(), 8);
    assert_eq!(arp.protocol_len_value(), 16);
    assert_eq!(arp.opcode_value(), 0x0fa0);
    assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(arp.target_protocol_bytes_value(), target_pa);

    // Those values survive a full Ethernet/ARP compile -> decode round trip.
    let frame = Ethernet::new().src(src_mac()) / arp;
    let bytes = frame.compile().unwrap().as_bytes().to_vec();
    let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
    assert_eq!(decoded_arp.protocol_type_value(), 0x86dd);
    assert_eq!(decoded_arp.hardware_len_value(), 8);
    assert_eq!(decoded_arp.protocol_len_value(), 16);
    assert_eq!(decoded_arp.opcode_value(), 0x0fa0);
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(decoded_arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(decoded_arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);
}

#[test]
fn arp_preserves_intentionally_malformed_address_bytes() {
    // A consistent but nonstandard 3-octet hardware / 1-octet protocol body:
    // the bytes are wrong for a real Ethernet/IPv4 ARP yet must compile and
    // round-trip exactly, since generated tools need malformed packets to
    // exercise a stack.
    let arp = Arp::new()
        .hardware_len(3)
        .protocol_len(1)
        .opcode(0)
        .sender_hardware_bytes(vec![0xde, 0xad, 0xbe])
        .sender_protocol_bytes(vec![0x01])
        .target_hardware_bytes(vec![0xca, 0xfe, 0x99])
        .target_protocol_bytes(vec![0x02]);

    let frame = Ethernet::new().src(src_mac()) / arp;
    let bytes = frame.compile().unwrap().as_bytes().to_vec();
    let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();

    assert_eq!(decoded_arp.hardware_len_value(), 3);
    assert_eq!(decoded_arp.protocol_len_value(), 1);
    assert_eq!(decoded_arp.opcode_value(), 0);
    assert_eq!(
        decoded_arp.sender_hardware_bytes_value(),
        vec![0xde, 0xad, 0xbe]
    );
    assert_eq!(decoded_arp.sender_protocol_bytes_value(), vec![0x01]);
    assert_eq!(
        decoded_arp.target_hardware_bytes_value(),
        vec![0xca, 0xfe, 0x99]
    );
    assert_eq!(decoded_arp.target_protocol_bytes_value(), vec![0x02]);
}

#[test]
fn arp_preserves_user_values_against_later_helper_defaults() {
    // Helper defaults (set_default_if_unset / length auto-fill) must only
    // touch UNSET fields. Setting the lengths and protocol type explicitly
    // first, then calling the convenience MAC/IPv4 helpers, must leave the
    // explicit values intact even though those helpers would otherwise
    // default them to 6 / 4 / IPv4.
    let arp = Arp::new()
        .hardware_len(9)
        .protocol_len(7)
        .protocol_type(0xbeef)
        .sender_hardware_addr(MacAddr::ZERO)
        .sender_protocol_addr(Ipv4Addr::new(192, 0, 2, 10))
        .target_hardware_addr(MacAddr::BROADCAST)
        .target_protocol_addr(Ipv4Addr::new(192, 0, 2, 1));

    assert_eq!(arp.hardware_len_value(), 9);
    assert_eq!(arp.protocol_len_value(), 7);
    assert_eq!(arp.protocol_type_value(), 0xbeef);

    // The raw byte payloads the MAC/IPv4 helpers wrote are themselves never
    // rewritten by any later default.
    assert_eq!(
        arp.sender_hardware_bytes_value(),
        MacAddr::ZERO.octets().to_vec()
    );
    assert_eq!(
        arp.target_protocol_bytes_value(),
        Ipv4Addr::new(192, 0, 2, 1).octets().to_vec()
    );
}

#[test]
fn arp_override_of_helper_defaulted_lengths_and_types_is_honored() {
    // The generic address builders auto-fill lengths only as a Defaulted
    // value, so a later explicit override of the length or type wins, and
    // the raw bytes set by the builder are preserved unchanged.
    let arp = Arp::new()
        .sender_hardware(vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb])
        .hardware_len(4)
        .protocol_type(0x86dd);

    assert_eq!(arp.hardware_len_value(), 4);
    assert_eq!(arp.protocol_type_value(), 0x86dd);
    assert_eq!(
        arp.sender_hardware_bytes_value(),
        vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb]
    );
}

#[test]
fn arp_override_of_opcode_and_types_survives_who_has_helper() {
    // Building from the who_has helper (which sets request opcode and IPv4
    // addresses) and then overriding the opcode, hardware type, and protocol
    // type must keep every override; who_has supplied no explicit override
    // for these so the later setters take effect and are not reset.
    let arp = Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 1),
        src_mac(),
    )
    .opcode(0x1234)
    .hardware_type(super::ARP_HRD_ATM)
    .protocol_type(0x0805);

    assert_eq!(arp.opcode_value(), 0x1234);
    assert_eq!(arp.hardware_type_value(), super::ARP_HRD_ATM);
    assert_eq!(arp.protocol_type_value(), 0x0805);

    // The overrides reach the wire and decode back unchanged.
    let frame = Ethernet::new().src(src_mac()) / arp;
    let bytes = frame.compile().unwrap().as_bytes().to_vec();
    let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.opcode_value(), 0x1234);
    assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_ATM);
    assert_eq!(decoded_arp.protocol_type_value(), 0x0805);
}

#[test]
fn arp_decode_variable_hardware_length_preserves_bytes() {
    // A nonstandard 8-octet hardware address with a standard 4-octet IPv4
    // protocol address is structurally valid generic-format ARP. Decode
    // splits the four address fields by HLN/PLN and preserves the exact
    // bytes. The wider hardware address is not a MAC, so sender_mac() and
    // target_mac() report None while the raw byte accessors stay exact.
    let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb];
    let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, 0xcc, 0xdd];
    let sender_pa = vec![192, 0, 2, 10];
    let target_pa = vec![192, 0, 2, 1];

    let mut bytes = vec![
        0x00, 0x20, // HRD = 32 (InfiniBand)
        0x08, 0x00, // PRO = IPv4
        0x08, // HLN = 8
        0x04, // PLN = 4
        0x00, 0x01, // OP = request
    ];
    bytes.extend_from_slice(&sender_hw);
    bytes.extend_from_slice(&sender_pa);
    bytes.extend_from_slice(&target_hw);
    bytes.extend_from_slice(&target_pa);

    let arp = decode_arp_layer(&bytes);

    assert_eq!(arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
    assert_eq!(arp.protocol_type_value(), super::ETHERTYPE_IPV4);
    assert_eq!(arp.hardware_len_value(), 8);
    assert_eq!(arp.protocol_len_value(), 4);
    assert_eq!(arp.opcode_value(), ArpOperation::Request as u16);
    assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(arp.target_protocol_bytes_value(), target_pa);

    // Eight-octet hardware addresses are not MACs.
    assert_eq!(arp.sender_mac(), None);
    assert_eq!(arp.target_mac(), None);
    // The protocol is IPv4 with a four-octet address, so the IPv4 typed
    // accessors still resolve.
    assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));

    // The decoded packet re-compiles to the exact input bytes.
    let frame = Ethernet::new().src(src_mac()) / arp;
    let recompiled =
        Packet::decode_from_link(LinkType::Ethernet, frame.compile().unwrap().as_bytes()).unwrap();
    assert_eq!(
        recompiled
            .layer::<Arp>()
            .unwrap()
            .sender_hardware_bytes_value(),
        sender_hw
    );
}

#[test]
fn arp_decode_variable_protocol_length_preserves_bytes() {
    // A standard 6-octet MAC with a nonstandard 16-octet protocol address
    // (e.g. an IPv6-sized payload) under an unknown protocol type. Decode
    // splits by HLN/PLN and preserves exact bytes; the wide protocol field
    // is not IPv4 so sender_ipv4()/target_ipv4() report None.
    let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10];
    let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20];
    let sender_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let target_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    let mut bytes = vec![
        0x00, 0x01, // HRD = Ethernet
        0x86, 0xdd, // PRO = IPv6 EtherType (not IPv4)
        0x06, // HLN = 6
        0x10, // PLN = 16
        0x00, 0x02, // OP = reply
    ];
    bytes.extend_from_slice(&sender_hw);
    bytes.extend_from_slice(&sender_pa);
    bytes.extend_from_slice(&target_hw);
    bytes.extend_from_slice(&target_pa);

    let arp = decode_arp_layer(&bytes);

    assert_eq!(arp.hardware_len_value(), 6);
    assert_eq!(arp.protocol_len_value(), 16);
    assert_eq!(arp.protocol_type_value(), 0x86dd);
    assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(arp.target_protocol_bytes_value(), target_pa);

    // Six-octet hardware addresses are valid MACs.
    assert_eq!(
        arp.sender_mac().map(|m| m.octets().to_vec()),
        Some(sender_hw)
    );
    assert_eq!(
        arp.target_mac().map(|m| m.octets().to_vec()),
        Some(target_hw)
    );
    // The protocol type is not IPv4 (and the address is 16 octets), so the
    // typed IPv4 accessors decline.
    assert_eq!(arp.sender_ipv4(), None);
    assert_eq!(arp.target_ipv4(), None);
}

#[test]
fn arp_decode_unknown_type_combination_preserves_fields() {
    // A fully nonstandard packet: unknown hardware type, unknown protocol
    // type, unknown operation, and matching nonstandard address lengths.
    // Decode must accept it structurally, preserve every field and address
    // byte, and decline both typed accessor families.
    let sender_hw = vec![0xde, 0xad, 0xbe];
    let target_hw = vec![0xca, 0xfe, 0x99];
    let sender_pa = vec![0x11, 0x22];
    let target_pa = vec![0x33, 0x44];

    let mut bytes = vec![
        0xab, 0xcd, // HRD = 0xabcd (unknown)
        0x12, 0x34, // PRO = 0x1234 (unknown)
        0x03, // HLN = 3
        0x02, // PLN = 2
        0x04, 0x00, // OP = 1024 (unknown numeric)
    ];
    bytes.extend_from_slice(&sender_hw);
    bytes.extend_from_slice(&sender_pa);
    bytes.extend_from_slice(&target_hw);
    bytes.extend_from_slice(&target_pa);

    let arp = decode_arp_layer(&bytes);

    assert_eq!(arp.hardware_type_value(), 0xabcd);
    assert_eq!(arp.protocol_type_value(), 0x1234);
    assert_eq!(arp.hardware_len_value(), 3);
    assert_eq!(arp.protocol_len_value(), 2);
    assert_eq!(arp.opcode_value(), 1024);
    assert_eq!(arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(arp.target_protocol_bytes_value(), target_pa);

    // Neither typed accessor family matches a 3-octet hardware address or a
    // non-IPv4 2-octet protocol address.
    assert_eq!(arp.sender_mac(), None);
    assert_eq!(arp.target_mac(), None);
    assert_eq!(arp.sender_ipv4(), None);
    assert_eq!(arp.target_ipv4(), None);
    // The unknown operation has no named label.
    assert_eq!(ArpOperation::from_opcode(1024), None);
}

#[test]
fn arp_decode_zero_length_addresses_does_not_overflow() {
    // Zero-length hardware and protocol fields are valid generic-format ARP
    // and decode to the bare eight-byte fixed header. The address-split
    // arithmetic must not over-read or panic on empty fields.
    let bytes = vec![
        0x00, 0x01, // HRD
        0x08, 0x00, // PRO
        0x00, // HLN = 0
        0x00, // PLN = 0
        0x00, 0x01, // OP
    ];

    let arp = decode_arp_layer(&bytes);

    assert_eq!(arp.hardware_len_value(), 0);
    assert_eq!(arp.protocol_len_value(), 0);
    assert!(arp.sender_hardware_bytes_value().is_empty());
    assert!(arp.sender_protocol_bytes_value().is_empty());
    assert!(arp.target_hardware_bytes_value().is_empty());
    assert!(arp.target_protocol_bytes_value().is_empty());
    // Empty hardware/protocol fields are neither a MAC nor an IPv4 address.
    assert_eq!(arp.sender_mac(), None);
    assert_eq!(arp.sender_ipv4(), None);
}

#[test]
fn arp_decode_truncated_header_returns_structured_error() {
    // A buffer shorter than the eight-byte fixed header fails with a
    // structured BufferTooShort naming the failing context and the
    // required/available byte counts, never a panic.
    let bytes = [0x00, 0x01, 0x08, 0x00, 0x06]; // 5 bytes, header needs 8
    let err = Packet::decode_from_link(LinkType::Ethernet, arp_frame(&bytes)).unwrap_err();
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "arp header");
            assert_eq!(required, 8);
            assert_eq!(available, 5);
        }
        other => panic!("expected a structured truncation error, got {other:?}"),
    }
}

#[test]
fn arp_decode_truncated_address_fields_returns_structured_error() {
    // A complete fixed header declaring 6/4 address lengths but with the
    // address bytes truncated fails with a BufferTooShort naming the
    // address context and the required vs. available lengths.
    let bytes = vec![
        0x00, 0x01, // HRD
        0x08, 0x00, // PRO
        0x06, // HLN = 6
        0x04, // PLN = 4
        0x00, 0x01, // OP
        0xaa, 0xbb, 0xcc, // only 3 of the 20 declared address bytes
    ];
    let err = Packet::decode_from_link(LinkType::Ethernet, arp_frame(&bytes)).unwrap_err();
    match err {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "arp addresses");
            // Fixed header (8) + 6*2 + 4*2 = 28 required; 11 available.
            assert_eq!(required, 28);
            assert_eq!(available, 11);
        }
        other => panic!("expected a structured truncation error, got {other:?}"),
    }
}

#[test]
fn arp_variable_lengths_decode_round_trips_byte_exact() {
    // An end-to-end variable-length round trip: build a nonstandard
    // 8-octet-hardware / 16-octet-protocol ARP through the raw byte
    // builders, compile inside an Ethernet frame, decode, and confirm every
    // field and byte survives the split-by-length decode path unchanged.
    let sender_hw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
    let sender_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let target_hw = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let target_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    let arp = Arp::new()
        .hardware_type(super::ARP_HRD_INFINIBAND)
        .protocol_type(0x86dd)
        .opcode(0x0fa0)
        .sender_hardware(sender_hw.clone())
        .sender_protocol(sender_pa.clone())
        .target_hardware(target_hw.clone())
        .target_protocol(target_pa.clone());

    let frame = Ethernet::new().src(src_mac()) / arp;
    let bytes = frame.compile().unwrap().as_bytes().to_vec();
    let decoded = Packet::decode_from_link(LinkType::Ethernet, &bytes).unwrap();
    let decoded_arp = decoded.layer::<Arp>().unwrap();

    assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
    assert_eq!(decoded_arp.protocol_type_value(), 0x86dd);
    assert_eq!(decoded_arp.hardware_len_value(), 8);
    assert_eq!(decoded_arp.protocol_len_value(), 16);
    assert_eq!(decoded_arp.opcode_value(), 0x0fa0);
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(decoded_arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(decoded_arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);

    // Nonstandard widths decline the typed accessors.
    assert_eq!(decoded_arp.sender_mac(), None);
    assert_eq!(decoded_arp.target_mac(), None);
    assert_eq!(decoded_arp.sender_ipv4(), None);
    assert_eq!(decoded_arp.target_ipv4(), None);

    // The full frame re-compiles to the identical bytes.
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
}

#[test]
fn arp_variable_zero_protocol_length_with_ipv4_type_returns_none() {
    // sender_ipv4()/target_ipv4() must key off BOTH the protocol type and a
    // four-octet length. An IPv4 protocol type with a zero-length address
    // is not a valid IPv4 address, so the typed accessor declines even
    // though the protocol type matches.
    let bytes = vec![
        0x00, 0x01, // HRD = Ethernet
        0x08, 0x00, // PRO = IPv4
        0x06, // HLN = 6
        0x00, // PLN = 0
        0x00, 0x01, // OP
        0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, // sender hardware (6 octets)
        // sender protocol: 0 octets
        0x00, 0x00, 0x5e, 0x00, 0x53,
        0x20, // target hardware (6 octets)
              // target protocol: 0 octets
    ];

    let arp = decode_arp_layer(&bytes);

    assert_eq!(arp.protocol_type_value(), super::ETHERTYPE_IPV4);
    assert_eq!(arp.protocol_len_value(), 0);
    // MACs still resolve, but the IPv4 accessors decline on a zero-length
    // protocol address.
    assert!(arp.sender_mac().is_some());
    assert_eq!(arp.sender_ipv4(), None);
    assert_eq!(arp.target_ipv4(), None);
}

/// A complete Ethernet/IPv4 ARP request body followed by extra octets.
/// Per repo policy the decoder validates the fixed header plus the four
/// address fields (sized by HLN/PLN), then preserves any leftover bytes as
/// a trailing `Raw` payload rather than rejecting the frame.
const ARP_TRAILER: &[u8] = b"trailing-after-arp";

fn arp_body_ipv4_request() -> Vec<u8> {
    vec![
        0x00, 0x01, // HRD = Ethernet
        0x08, 0x00, // PRO = IPv4
        0x06, // HLN = 6
        0x04, // PLN = 4
        0x00, 0x01, // OP = request
        0x02, 0x00, 0x5e, 0x00, 0x53, 0x01, // sender hardware
        0xc0, 0x00, 0x02, 0x0a, // sender protocol 192.0.2.10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target hardware
        0xc0, 0x00, 0x02, 0x01, // target protocol 192.0.2.1
    ]
}

#[test]
fn arp_trailing_bytes_decode_as_raw_after_arp_layer() {
    // A structurally complete ARP body carries trailing padding/junk. The
    // ARP header decodes intact and the leftover bytes land in a Raw layer.
    let mut body = arp_body_ipv4_request();
    body.extend_from_slice(ARP_TRAILER);
    let frame = arp_frame(&body);

    let decoded = Packet::decode_from_link(LinkType::Ethernet, &frame)
        .expect("complete ARP body with a trailer must decode");

    let arp = decoded
        .layer::<Arp>()
        .expect("decoded packet must carry an Arp layer");
    assert_eq!(arp.opcode_value(), ArpOperation::Request as u16);
    assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
    assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));

    let raw = decoded
        .layer::<Raw>()
        .expect("trailing bytes must surface as a Raw layer");
    assert_eq!(raw.as_bytes(), ARP_TRAILER);
}

#[test]
fn arp_trailing_bytes_recompile_preserves_payload_byte_exact() {
    // Re-compiling the decoded stack must reproduce the original frame
    // byte-for-byte, including the trailing Raw payload.
    let mut body = arp_body_ipv4_request();
    body.extend_from_slice(ARP_TRAILER);
    let frame = arp_frame(&body);

    let decoded = Packet::decode_from_link(LinkType::Ethernet, &frame).unwrap();

    assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_slice());
}

#[test]
fn raw_after_arp_preserved_with_nonstandard_address_lengths() {
    // Trailing bytes survive even when the ARP body uses nonstandard
    // hardware/protocol address widths: the decoder splits the addresses by
    // HLN/PLN and the remainder still becomes a Raw layer.
    let mut body = vec![
        0x00, 0x19, // HRD = ATM (nonstandard for this test)
        0x86, 0xdd, // PRO = IPv6 ethertype
        0x02, // HLN = 2
        0x03, // PLN = 3
        0x04, 0x00, // OP = 0x0400 (unknown numeric opcode)
        0xaa, 0xbb, // sender hardware (2 octets)
        0x01, 0x02, 0x03, // sender protocol (3 octets)
        0xcc, 0xdd, // target hardware (2 octets)
        0x04, 0x05, 0x06, // target protocol (3 octets)
    ];
    let trailer: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
    body.extend_from_slice(trailer);
    let frame = arp_frame(&body);

    let decoded = Packet::decode_from_link(LinkType::Ethernet, &frame)
        .expect("nonstandard but complete ARP body must decode");

    let arp = decoded.layer::<Arp>().expect("expected an Arp layer");
    assert_eq!(arp.hardware_len_value(), 2);
    assert_eq!(arp.protocol_len_value(), 3);
    assert_eq!(arp.opcode_value(), 0x0400);

    let raw = decoded
        .layer::<Raw>()
        .expect("trailing bytes must surface as a Raw layer");
    assert_eq!(raw.as_bytes(), trailer);

    // The full frame round-trips byte-exact through the packet stack.
    assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_slice());
}

#[test]
fn raw_after_arp_absent_when_body_is_exact() {
    // A body that ends exactly at the ARP boundary leaves no trailing Raw
    // layer; this guards the trailing-Raw path against off-by-one slicing.
    let frame = arp_frame(&arp_body_ipv4_request());

    let decoded = Packet::decode_from_link(LinkType::Ethernet, &frame).unwrap();

    assert!(decoded.layer::<Arp>().is_some());
    assert!(
        decoded.layer::<Raw>().is_none(),
        "an exact ARP body must not synthesize a Raw layer"
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_slice());
}

/// Decode a bare ARP body inside an Ethernet frame and return the `Arp`
/// layer, panicking on any decode error. Centralizes the variable-length
/// decode assertions so each test reads as data plus expectations.
fn decode_arp_layer(body: &[u8]) -> Arp {
    let frame = arp_frame(body);
    let decoded = Packet::decode_from_link(LinkType::Ethernet, &frame)
        .expect("structurally valid ARP body must decode");
    decoded
        .layer::<Arp>()
        .expect("decoded packet must carry an Arp layer")
        .clone()
}

/// Wrap an ARP body in a minimal Ethernet header (broadcast dst, the test
/// source MAC, EtherType 0x0806) so it decodes through the link root.
fn arp_frame(body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + body.len());
    frame.extend_from_slice(&MacAddr::BROADCAST.octets());
    frame.extend_from_slice(&src_mac().octets());
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

/// Look up a single inspection field by key, panicking when absent so a
/// renamed or dropped field surfaces as a test failure rather than a silent
/// `None`.
fn inspection_value(arp: &Arp, key: &str) -> String {
    use crate::packet::Layer;

    arp.inspection_fields()
        .into_iter()
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("expected inspection field `{key}`"))
}

#[test]
fn arp_summary_standard_ethernet_ipv4_stays_concise_and_readable() {
    use crate::packet::Layer;

    // The canonical Ethernet/IPv4 reply summary must match the historic
    // short form exactly (this is the byte-stable golden fixture shape):
    // operation label plus dotted sender/target protocol addresses.
    let reply = Arp::is_at(
        Ipv4Addr::new(192, 0, 2, 1),
        "02:00:5e:00:53:02".parse().unwrap(),
        Ipv4Addr::new(192, 0, 2, 10),
        "02:00:5e:00:53:01".parse().unwrap(),
    );

    assert_eq!(
        reply.summary(),
        "Arp(op=reply, psrc=192.0.2.1, pdst=192.0.2.10)"
    );

    let request = Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 1),
        src_mac(),
    );
    assert_eq!(
        request.summary(),
        "Arp(op=request, psrc=192.0.2.10, pdst=192.0.2.1)"
    );
}

#[test]
fn arp_summary_unknown_operation_and_nonstandard_protocol_stay_visible() {
    use crate::packet::Layer;

    // An unknown numeric opcode renders as its raw number, and a protocol
    // address that is not standard IPv4 (here an 8-octet protocol field)
    // falls back to a hex byte rendering so the summary never hides what
    // was built.
    let arp = Arp::new()
        .opcode(0x0400)
        .protocol_type(super::ETHERTYPE_IPV4)
        .sender_protocol(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        .target_protocol(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    let summary = arp.summary();
    assert!(summary.contains("op=1024"), "summary was {summary}");
    assert!(
        summary.contains("psrc=01 02 03 04 05 06 07 08"),
        "summary was {summary}"
    );
    assert!(
        summary.contains("pdst=11 22 33 44 55 66 77 88"),
        "summary was {summary}"
    );
}

#[test]
fn arp_inspection_standard_ethernet_ipv4_exposes_named_fields() {
    // Standard Ethernet/IPv4 inspection shows human-readable type labels
    // alongside the raw codepoints, the operation name with its number, the
    // header lengths, and both typed addresses and their raw bytes.
    let request = Arp::who_has(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 1),
        src_mac(),
    );

    assert_eq!(
        inspection_value(&request, "hardware_type"),
        "ethernet (0x0001)"
    );
    assert_eq!(inspection_value(&request, "protocol_type"), "ipv4 (0x0800)");
    assert_eq!(inspection_value(&request, "hardware_len"), "6");
    assert_eq!(inspection_value(&request, "protocol_len"), "4");
    assert_eq!(inspection_value(&request, "operation"), "request (1)");
    assert_eq!(
        inspection_value(&request, "sender_hardware_addr"),
        "02:00:5e:00:53:01"
    );
    assert_eq!(
        inspection_value(&request, "sender_protocol_addr"),
        "192.0.2.10"
    );
    assert_eq!(
        inspection_value(&request, "target_protocol_addr"),
        "192.0.2.1"
    );
    // Raw byte views accompany the typed renderings.
    assert_eq!(
        inspection_value(&request, "sender_hardware_bytes"),
        "02 00 5e 00 53 01"
    );
    assert_eq!(
        inspection_value(&request, "sender_protocol_bytes"),
        "c0 00 02 0a"
    );
}

#[test]
fn arp_inspection_nonstandard_values_remain_inspectable() {
    // Nonstandard hardware/protocol types, an unknown opcode, and variable
    // address widths must all remain inspectable: unknown types render as
    // bare hex codepoints, the opcode keeps its raw number, and the address
    // fields surface raw bytes when typed formatting does not apply.
    let arp = Arp::new()
        .hardware_type(0x4242)
        .protocol_type(0x86dd)
        .opcode(0x0400)
        .sender_hardware(vec![0xaa, 0xbb])
        .sender_protocol(vec![0x01, 0x02, 0x03])
        .target_hardware(vec![0xcc, 0xdd])
        .target_protocol(vec![0x04, 0x05, 0x06]);

    assert_eq!(inspection_value(&arp, "hardware_type"), "0x4242");
    assert_eq!(inspection_value(&arp, "protocol_type"), "0x86dd");
    assert_eq!(inspection_value(&arp, "operation"), "1024");
    assert_eq!(inspection_value(&arp, "hardware_len"), "2");
    assert_eq!(inspection_value(&arp, "protocol_len"), "3");
    // No standard MAC/IPv4 view applies, so the typed fields fall back to
    // the raw hex bytes and the explicit *_bytes fields agree.
    assert_eq!(inspection_value(&arp, "sender_hardware_addr"), "aa bb");
    assert_eq!(inspection_value(&arp, "sender_hardware_bytes"), "aa bb");
    assert_eq!(inspection_value(&arp, "sender_protocol_addr"), "01 02 03");
    assert_eq!(inspection_value(&arp, "sender_protocol_bytes"), "01 02 03");
    assert_eq!(inspection_value(&arp, "target_protocol_bytes"), "04 05 06");
}

#[test]
fn arp_codepoint_known_operations_compile_decode_and_round_trip() {
    use super::{
        ARP_OP_ARP_NAK, ARP_OP_DRARP_ERROR, ARP_OP_DRARP_REPLY, ARP_OP_DRARP_REQUEST,
        ARP_OP_INARP_REPLY, ARP_OP_INARP_REQUEST, ARP_OP_MAPOS_UNARP, ARP_OP_RARP_REPLY,
        ARP_OP_RARP_REQUEST, ARP_OP_REPLY, ARP_OP_REQUEST,
    };
    use crate::packet::Layer;

    // Every source-backed known operation included by scope.md
    // (IANA arp-parameters-1): REQUEST/REPLY (RFC 826), RARP req/reply
    // (RFC 903), DRARP req/reply/error (RFC 1931), InARP req/reply
    // (RFC 2390), ARP-NAK (RFC 1577), MAPOS-UNARP (RFC 2176). Each must be
    // ergonomic through the named enum *and* compile, decode, summarize, and
    // round-trip byte-exact over a full Ethernet/ARP stack.
    let known = [
        (ArpOperation::Request, ARP_OP_REQUEST, "request"),
        (ArpOperation::Reply, ARP_OP_REPLY, "reply"),
        (
            ArpOperation::RarpRequest,
            ARP_OP_RARP_REQUEST,
            "rarp-request",
        ),
        (ArpOperation::RarpReply, ARP_OP_RARP_REPLY, "rarp-reply"),
        (
            ArpOperation::DrarpRequest,
            ARP_OP_DRARP_REQUEST,
            "drarp-request",
        ),
        (ArpOperation::DrarpReply, ARP_OP_DRARP_REPLY, "drarp-reply"),
        (ArpOperation::DrarpError, ARP_OP_DRARP_ERROR, "drarp-error"),
        (
            ArpOperation::InArpRequest,
            ARP_OP_INARP_REQUEST,
            "inarp-request",
        ),
        (ArpOperation::InArpReply, ARP_OP_INARP_REPLY, "inarp-reply"),
        (ArpOperation::ArpNak, ARP_OP_ARP_NAK, "arp-nak"),
        (ArpOperation::MaposUnarp, ARP_OP_MAPOS_UNARP, "mapos-unarp"),
    ];

    for (operation, opcode, label) in known {
        // The named enum is the ergonomic surface and agrees with the
        // numeric codepoint constant in both directions.
        assert_eq!(operation.opcode(), opcode);
        assert_eq!(ArpOperation::from_opcode(opcode), Some(operation));
        assert_eq!(operation.label(), label);

        // Build a standard Ethernet/IPv4 body carrying this operation and
        // confirm it compiles, then decodes back to the same opcode.
        let arp = Arp::new()
            .operation(operation)
            .sender_hardware(sender_mac().octets().to_vec())
            .sender_protocol(Ipv4Addr::new(192, 0, 2, 1).octets().to_vec())
            .target_hardware(src_mac().octets().to_vec())
            .target_protocol(Ipv4Addr::new(192, 0, 2, 10).octets().to_vec());
        assert_eq!(arp.opcode_value(), opcode);

        // Summaries surface every known operation by its name.
        assert!(
            arp.summary().contains(&format!("op={label}")),
            "summary for {label} was {}",
            arp.summary()
        );

        let frame = (Ethernet::new().src(sender_mac()).dst(src_mac()) / arp.clone())
            .compile()
            .expect("known-codepoint ARP must compile");

        let decoded = Packet::decode_from_link(LinkType::Ethernet, frame.as_bytes())
            .expect("known-codepoint ARP must decode");
        let decoded_arp = decoded
            .layer::<Arp>()
            .expect("decoded packet must carry an Arp layer");
        assert_eq!(decoded_arp.opcode_value(), opcode);
        assert_eq!(
            ArpOperation::from_opcode(decoded_arp.opcode_value()),
            Some(operation)
        );

        // The decoded stack recompiles to the exact original bytes.
        assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_bytes());
    }
}

#[test]
fn arp_unknown_codepoints_are_not_rejected() {
    use super::{arp_hardware_type_label, arp_protocol_type_label};
    use crate::packet::Layer;

    // Numeric values that no scoped registry names must NOT be rejected
    // solely because they are unknown: an unknown opcode, an unknown
    // hardware type, and an unknown protocol type all compile, decode,
    // round-trip byte-exact, and remain visible as their raw numbers.
    let unknown_opcode: u16 = 0x0fa0; // 4000, not an IANA arp-parameters-1 op
    let unknown_hardware: u16 = 0x1234; // not in ARP_HRD_*
    let unknown_protocol: u16 = 0x88b5; // IEEE local-experimental ethertype

    // The lookups disclaim these values rather than rejecting them.
    assert_eq!(ArpOperation::from_opcode(unknown_opcode), None);
    assert_eq!(arp_hardware_type_label(unknown_hardware), None);
    assert_eq!(arp_protocol_type_label(unknown_protocol), None);

    let arp = Arp::new()
        .hardware_type(unknown_hardware)
        .protocol_type(unknown_protocol)
        .opcode(unknown_opcode)
        .sender_hardware(vec![0xaa, 0xbb, 0xcc])
        .sender_protocol(vec![0x01, 0x02])
        .target_hardware(vec![0xdd, 0xee, 0xff])
        .target_protocol(vec![0x03, 0x04]);

    // All three unknown values are preserved on the builder, unchanged.
    assert_eq!(arp.hardware_type_value(), unknown_hardware);
    assert_eq!(arp.protocol_type_value(), unknown_protocol);
    assert_eq!(arp.opcode_value(), unknown_opcode);

    // The unknown opcode stays numeric and visible in the summary.
    assert!(
        arp.summary().contains(&format!("op={unknown_opcode}")),
        "summary was {}",
        arp.summary()
    );
    // Unknown hardware/protocol types render as bare hex codepoints.
    assert_eq!(
        inspection_value(&arp, "hardware_type"),
        format!("0x{unknown_hardware:04x}")
    );
    assert_eq!(
        inspection_value(&arp, "protocol_type"),
        format!("0x{unknown_protocol:04x}")
    );
    assert_eq!(
        inspection_value(&arp, "operation"),
        format!("{unknown_opcode}")
    );

    // The packet compiles (accepted, not rejected) and survives a full
    // Ethernet/ARP compile -> decode cycle with every value intact and the
    // recompiled bytes identical to the original frame.
    let frame = (Ethernet::new().src(src_mac()) / arp)
        .compile()
        .expect("unknown ARP codepoints must compile, not be rejected");

    let decoded = Packet::decode_from_link(LinkType::Ethernet, frame.as_bytes())
        .expect("unknown ARP codepoints must decode, not be rejected");
    let decoded_arp = decoded
        .layer::<Arp>()
        .expect("decoded packet must carry an Arp layer");
    assert_eq!(decoded_arp.hardware_type_value(), unknown_hardware);
    assert_eq!(decoded_arp.protocol_type_value(), unknown_protocol);
    assert_eq!(decoded_arp.opcode_value(), unknown_opcode);
    assert_eq!(decoded_arp.hardware_type_label(), None);
    assert_eq!(decoded_arp.protocol_type_label(), None);
    assert_eq!(ArpOperation::from_opcode(decoded_arp.opcode_value()), None);

    assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_bytes());
}

#[test]
fn arp_variable_length_nonstandard_hardware_and_protocol_build_compile_decode_inspect() {
    // Verify the generic ARP model end to end, independent of the oracle
    // generator: build an ARP with BOTH a nonstandard hardware length
    // (8 octets) AND a nonstandard protocol length (16 octets) through the
    // raw byte builders, compile it inside an Ethernet frame, decode it back
    // through the link root, and inspect the result. Because neither width
    // matches the standard 6-octet MAC / 4-octet IPv4 form, the typed
    // accessors must all decline (`None`) while the raw byte accessors
    // preserve every input octet exactly.
    //
    // Addresses use documentation space only: RFC 7042 MAC OUI
    // 00:00:5e:00:53:xx padded to 8 octets and RFC 3849 2001:db8:: payloads.
    let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x10, 0xaa, 0xbb];
    let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x20, 0xcc, 0xdd];
    let sender_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ];
    let target_pa = vec![
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
    ];

    // The raw builders auto-fill the matching length fields from the byte
    // counts, so HLN/PLN follow the nonstandard widths without an explicit
    // length setter.
    let arp = Arp::new()
        .hardware_type(super::ARP_HRD_INFINIBAND)
        .protocol_type(0x86dd)
        .operation(ArpOperation::Request)
        .sender_hardware(sender_hw.clone())
        .sender_protocol(sender_pa.clone())
        .target_hardware(target_hw.clone())
        .target_protocol(target_pa.clone());

    assert_eq!(arp.hardware_len_value(), 8);
    assert_eq!(arp.protocol_len_value(), 16);

    // Compile inside an Ethernet frame (the ARP link root) and decode back.
    let frame = (Ethernet::new().src(src_mac()).dst(MacAddr::BROADCAST) / arp)
        .compile()
        .expect("nonstandard variable-length ARP must compile");
    let decoded = Packet::decode_from_link(LinkType::Ethernet, frame.as_bytes())
        .expect("nonstandard variable-length ARP must decode");
    let decoded_arp = decoded
        .layer::<Arp>()
        .expect("decoded packet must carry an Arp layer");

    // The fixed header and both nonstandard lengths survive the decode.
    assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_INFINIBAND);
    assert_eq!(decoded_arp.protocol_type_value(), 0x86dd);
    assert_eq!(decoded_arp.hardware_len_value(), 8);
    assert_eq!(decoded_arp.protocol_len_value(), 16);
    assert_eq!(decoded_arp.opcode_value(), ArpOperation::Request as u16);

    // Raw accessors preserve every input byte exactly across the round trip.
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(decoded_arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(decoded_arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);

    // Neither typed accessor family matches these nonstandard widths, so
    // every one declines rather than inventing an address.
    assert_eq!(decoded_arp.sender_mac(), None);
    assert_eq!(decoded_arp.target_mac(), None);
    assert_eq!(decoded_arp.sender_ipv4(), None);
    assert_eq!(decoded_arp.target_ipv4(), None);

    // Inspection keeps the nonstandard bytes visible: the typed *_addr
    // views fall back to raw hex and the explicit *_bytes views agree.
    assert_eq!(inspection_value(decoded_arp, "hardware_len"), "8");
    assert_eq!(inspection_value(decoded_arp, "protocol_len"), "16");
    assert_eq!(
        inspection_value(decoded_arp, "sender_hardware_addr"),
        "00 00 5e 00 53 10 aa bb"
    );
    assert_eq!(
        inspection_value(decoded_arp, "sender_hardware_bytes"),
        "00 00 5e 00 53 10 aa bb"
    );
    assert_eq!(
        inspection_value(decoded_arp, "target_protocol_bytes"),
        "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 02"
    );

    // The decoded stack recompiles to the identical frame bytes.
    assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_bytes());
}

#[test]
fn arp_variable_length_explicit_lengths_with_ipv4_type_decline_typed_ipv4() {
    // A second variable-length case anchored on an EXPLICIT length setter:
    // an IPv4 protocol type carried over a deliberately nonstandard 2-octet
    // protocol address and a 3-octet hardware address. Decode splits by the
    // honored HLN/PLN and preserves the bytes, but because the widths do not
    // match standard MAC/IPv4 the typed accessors decline even though the
    // protocol type is IPv4 -- the typed IPv4 view keys off BOTH the type
    // and a four-octet length.
    let sender_hw = vec![0xde, 0xad, 0xbe];
    let target_hw = vec![0xca, 0xfe, 0x99];
    let sender_pa = vec![0xc0, 0x00]; // 192.0 -- truncated, only 2 octets
    let target_pa = vec![0x02, 0x01];

    let arp = Arp::new()
        .protocol_type(super::ETHERTYPE_IPV4)
        .hardware_len(3)
        .protocol_len(2)
        .operation(ArpOperation::Request)
        .sender_hardware(sender_hw.clone())
        .sender_protocol(sender_pa.clone())
        .target_hardware(target_hw.clone())
        .target_protocol(target_pa.clone());

    let frame = (Ethernet::new().src(src_mac()).dst(MacAddr::BROADCAST) / arp)
        .compile()
        .expect("explicit nonstandard lengths must compile");
    let decoded = Packet::decode_from_link(LinkType::Ethernet, frame.as_bytes())
        .expect("explicit nonstandard lengths must decode");
    let decoded_arp = decoded
        .layer::<Arp>()
        .expect("decoded packet must carry an Arp layer");

    assert_eq!(decoded_arp.protocol_type_value(), super::ETHERTYPE_IPV4);
    assert_eq!(decoded_arp.hardware_len_value(), 3);
    assert_eq!(decoded_arp.protocol_len_value(), 2);

    // Raw accessors preserve the exact bytes...
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(decoded_arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(decoded_arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);

    // ...while every typed accessor declines: 3-octet hardware is not a MAC,
    // and a 2-octet protocol address is not an IPv4 address even under the
    // IPv4 protocol type.
    assert_eq!(decoded_arp.sender_mac(), None);
    assert_eq!(decoded_arp.target_mac(), None);
    assert_eq!(decoded_arp.sender_ipv4(), None);
    assert_eq!(decoded_arp.target_ipv4(), None);

    assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_bytes());
}

#[test]
fn arp_raw_address_nonstandard_lengths_round_trip_byte_exact_and_decline_typed() {
    // A raw-address-focused variable-length case (named for the
    // arp_raw_address filter): build with the canonical raw byte setters at
    // nonstandard widths, compile, decode, and confirm the raw byte
    // accessors round-trip byte-exact while the typed MAC/IPv4 accessors
    // return None. This proves the raw byte path -- not the convenience
    // MAC/IPv4 helpers -- is the generic backbone of the model.
    //
    // Documentation address space only: RFC 7042 MAC OUI extended to 7
    // octets, RFC 3849 2001:db8:: protocol payloads at 5 octets.
    let sender_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x30, 0x77];
    let target_hw = vec![0x00, 0x00, 0x5e, 0x00, 0x53, 0x40, 0x88];
    let sender_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0x05];
    let target_pa = vec![0x20, 0x01, 0x0d, 0xb8, 0x06];

    let arp = Arp::new()
        .hardware_type(super::ARP_HRD_ATM)
        .protocol_type(0x86dd)
        .opcode(0x0fa0) // unknown numeric opcode, preserved as-is
        .sender_hardware_bytes(sender_hw.clone())
        .target_hardware_bytes(target_hw.clone())
        .sender_protocol_bytes(sender_pa.clone())
        .target_protocol_bytes(target_pa.clone())
        .hardware_len(7)
        .protocol_len(5);

    let frame = (Ethernet::new().src(src_mac()).dst(MacAddr::BROADCAST) / arp)
        .compile()
        .expect("raw nonstandard-length ARP must compile");
    let decoded = Packet::decode_from_link(LinkType::Ethernet, frame.as_bytes())
        .expect("raw nonstandard-length ARP must decode");
    let decoded_arp = decoded
        .layer::<Arp>()
        .expect("decoded packet must carry an Arp layer");

    assert_eq!(decoded_arp.hardware_type_value(), super::ARP_HRD_ATM);
    assert_eq!(decoded_arp.protocol_type_value(), 0x86dd);
    assert_eq!(decoded_arp.hardware_len_value(), 7);
    assert_eq!(decoded_arp.protocol_len_value(), 5);
    assert_eq!(decoded_arp.opcode_value(), 0x0fa0);

    // Raw byte accessors preserve every octet.
    assert_eq!(decoded_arp.sender_hardware_bytes_value(), sender_hw);
    assert_eq!(decoded_arp.target_hardware_bytes_value(), target_hw);
    assert_eq!(decoded_arp.sender_protocol_bytes_value(), sender_pa);
    assert_eq!(decoded_arp.target_protocol_bytes_value(), target_pa);

    // Typed accessors decline the nonstandard widths.
    assert_eq!(decoded_arp.sender_mac(), None);
    assert_eq!(decoded_arp.target_mac(), None);
    assert_eq!(decoded_arp.sender_ipv4(), None);
    assert_eq!(decoded_arp.target_ipv4(), None);

    assert_eq!(decoded.compile().unwrap().as_bytes(), frame.as_bytes());
}
