use crafter::{
    Ssdp, SsdpHeaderName, SsdpHeaderNameKind, SsdpHeaderValue, SsdpMethod, SsdpParseErrorKind,
};

fn parse_roundtrip(bytes: &[u8]) -> Ssdp {
    let parsed = Ssdp::parse(bytes).expect("bounded SSDP property payload should parse");
    assert_eq!(parsed.to_bytes(), bytes);
    parsed
}

#[test]
fn header_names_and_values_preserve_supported_wire_forms() {
    let cases: &[(&str, &[u8], SsdpHeaderNameKind)] = &[
        ("HOST", b"239.255.255.250:1900", SsdpHeaderNameKind::Host),
        ("host", b"239.255.255.250:1900", SsdpHeaderNameKind::Host),
        ("X-DEVICE.UPNP.ORG", b"opaque", SsdpHeaderNameKind::Unknown),
        ("01-NLS", b"17", SsdpHeaderNameKind::NlsPrefixed),
        (
            "A!#$%&'*+-.^_`|~Z",
            b"\xffbinary",
            SsdpHeaderNameKind::Unknown,
        ),
        ("EXT", b"", SsdpHeaderNameKind::Ext),
    ];

    for (name, value, expected_kind) in cases {
        let parsed_name = SsdpHeaderName::try_from(*name).expect("valid bounded header name");
        assert_eq!(parsed_name.original(), *name);
        assert_eq!(parsed_name.kind(), *expected_kind);

        let ssdp = Ssdp::m_search()
            .with_raw_header(*name, SsdpHeaderValue::from_bytes(value.to_vec()))
            .expect("bounded raw header should be valid");
        let parsed = parse_roundtrip(&ssdp.to_bytes());
        let header = parsed.headers().iter().next().expect("header should parse");

        assert_eq!(header.name().original(), *name);
        assert_eq!(header.name().kind(), *expected_kind);
        assert_eq!(header.value().as_bytes(), *value);
    }
}

#[test]
fn duplicate_headers_remain_ordered_and_lookup_preserves_all_values() {
    let ssdp = Ssdp::m_search()
        .with_raw_header("ST", "ssdp:all")
        .expect("first ST header")
        .with_raw_header("HOST", "239.255.255.250:1900")
        .expect("HOST header")
        .with_raw_header("st", "upnp:rootdevice")
        .expect("second ST header")
        .with_raw_header("X-DEVICE.UPNP.ORG", "one")
        .expect("first extension header")
        .with_raw_header("X-DEVICE.UPNP.ORG", "two")
        .expect("second extension header");

    let parsed = parse_roundtrip(&ssdp.to_bytes());
    let entries = parsed.headers().iter().collect::<Vec<_>>();
    let st_values = parsed
        .headers()
        .get_all(SsdpHeaderNameKind::St)
        .map(SsdpHeaderValue::as_bytes)
        .collect::<Vec<_>>();
    let extension_values = parsed
        .headers()
        .iter()
        .filter(|header| header.name().original() == "X-DEVICE.UPNP.ORG")
        .map(|header| header.value().as_bytes())
        .collect::<Vec<_>>();

    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].name().original(), "ST");
    assert_eq!(entries[1].name().original(), "HOST");
    assert_eq!(entries[2].name().original(), "st");
    assert_eq!(
        st_values,
        vec![b"ssdp:all".as_slice(), b"upnp:rootdevice".as_slice()]
    );
    assert_eq!(extension_values, vec![b"one".as_slice(), b"two".as_slice()]);
}

#[test]
fn unknown_request_methods_roundtrip_and_invalid_methods_are_structured_errors() {
    for method in ["SEARCH", "MSEARCH", "X-FOO", "PRI"] {
        let payload = format!("{method} * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n");
        let parsed = parse_roundtrip(payload.as_bytes());
        let request = parsed
            .message()
            .start_line()
            .as_request()
            .expect("unknown method should still parse as request");

        assert_eq!(request.method(), &SsdpMethod::Unknown(method.to_string()));
    }

    let invalid = Ssdp::parse(b"BAD/METHOD * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n")
        .expect_err("invalid HTTP method token should be rejected");
    assert!(matches!(
        invalid.kind(),
        SsdpParseErrorKind::InvalidRequestMethod { .. }
    ));

    let empty = Ssdp::parse(b" * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n")
        .expect_err("empty request method should be rejected");
    assert!(matches!(
        empty.kind(),
        SsdpParseErrorKind::InvalidRequestStartLine { .. }
    ));
}

#[test]
fn body_bytes_are_opaque_after_header_delimiter() {
    let bodies: &[&[u8]] = &[
        b"",
        b"plain body",
        b"\x00\xff\r\nHeader-Like: body bytes\r\n",
        b"\t leading and trailing body whitespace \t",
    ];

    for body in bodies {
        let ssdp = Ssdp::response_ok()
            .with_raw_header("EXT", SsdpHeaderValue::empty())
            .expect("EXT header")
            .with_body(body.to_vec());
        let parsed = parse_roundtrip(&ssdp.to_bytes());

        assert_eq!(parsed.body(), *body);
    }
}

#[test]
fn malformed_bounded_inputs_return_structured_errors_without_panics() {
    let cases: &[(&[u8], fn(&SsdpParseErrorKind) -> bool)] = &[
        (b"", |kind| {
            matches!(
                kind,
                SsdpParseErrorKind::Truncated {
                    context: "ssdp.payload",
                    required: 1,
                    available: 0
                }
            )
        }),
        (b"M-SEARCH * HTTP/1.1\r\nHOST: value\n\r\n", |kind| {
            matches!(kind, SsdpParseErrorKind::BadDelimiter { .. })
        }),
        (b"M-SEARCH * HTTP/1.1\r\nBad Name: value\r\n\r\n", |kind| {
            matches!(kind, SsdpParseErrorKind::InvalidHeaderName { .. })
        }),
        (b"M-SEARCH * HTTP/1.1\r\nBad\tName: value\r\n\r\n", |kind| {
            matches!(kind, SsdpParseErrorKind::InvalidHeaderName { .. })
        }),
        (b"M-SEARCH * HTTP/1.1\r\n HOST: value\r\n\r\n", |kind| {
            matches!(kind, SsdpParseErrorKind::ObsoleteFoldedHeader { .. })
        }),
        (b"HTTP/1.1 20A OK\r\nEXT:\r\n\r\n", |kind| {
            matches!(kind, SsdpParseErrorKind::InvalidResponseStatusCode { .. })
        }),
    ];

    for (bytes, matches_expected_kind) in cases {
        let error = Ssdp::parse(bytes).expect_err("bounded malformed input should be rejected");

        assert!(
            matches_expected_kind(error.kind()),
            "unexpected SSDP error kind for {bytes:?}: {error:?}"
        );
    }
}
