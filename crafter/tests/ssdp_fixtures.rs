use crafter::{
    Ssdp, SsdpHeaderNameKind, SsdpMethod, SSDP_IPV6_SITE_LOCAL_HOST, SSDP_ST_ALL,
    SSDP_TARGET_ROOTDEVICE,
};

enum ExpectedFixture {
    MSearch,
    Notify,
    Response,
}

struct FixtureCase {
    name: &'static str,
    bytes: &'static [u8],
    expected: ExpectedFixture,
}

enum AdvancedFixture {
    ExtensionHeaders,
    DuplicateHeaders,
    BodyBytes,
    MulticastHost,
    UnknownPreservation,
}

struct AdvancedFixtureCase {
    name: &'static str,
    hex: &'static str,
    expected: AdvancedFixture,
}

#[test]
fn valid_ssdp_fixtures_parse_and_roundtrip() -> crafter::Result<()> {
    let cases = [
        FixtureCase {
            name: "m-search",
            bytes: include_bytes!("fixtures/ssdp/valid-m-search.ssdp"),
            expected: ExpectedFixture::MSearch,
        },
        FixtureCase {
            name: "notify",
            bytes: include_bytes!("fixtures/ssdp/valid-notify.ssdp"),
            expected: ExpectedFixture::Notify,
        },
        FixtureCase {
            name: "response",
            bytes: include_bytes!("fixtures/ssdp/valid-response.ssdp"),
            expected: ExpectedFixture::Response,
        },
    ];

    for case in cases {
        let ssdp = Ssdp::parse(case.bytes)
            .unwrap_or_else(|err| panic!("{} fixture should parse as SSDP: {err}", case.name));

        assert_eq!(ssdp.to_bytes(), case.bytes, "{}", case.name);
        assert!(ssdp.body().is_empty(), "{}", case.name);

        match case.expected {
            ExpectedFixture::MSearch => {
                let request = ssdp
                    .message()
                    .start_line()
                    .as_request()
                    .expect("request line");
                assert_eq!(request.method(), &SsdpMethod::MSearch);
                assert_eq!(
                    ssdp.headers()
                        .get_first(SsdpHeaderNameKind::St)
                        .expect("ST header")
                        .as_bytes(),
                    SSDP_ST_ALL.as_bytes()
                );
            }
            ExpectedFixture::Notify => {
                let request = ssdp
                    .message()
                    .start_line()
                    .as_request()
                    .expect("request line");
                assert_eq!(request.method(), &SsdpMethod::Notify);
                assert!(ssdp.headers().get_first(SsdpHeaderNameKind::Nts).is_some());
            }
            ExpectedFixture::Response => {
                let response = ssdp
                    .message()
                    .start_line()
                    .as_response()
                    .expect("response line");
                assert!(response.code().is_ok());
                assert!(ssdp.headers().get_first(SsdpHeaderNameKind::Ext).is_some());
            }
        }
    }

    Ok(())
}

#[test]
fn advanced_ssdp_fixtures_parse_roundtrip_and_preserve_structure() -> crafter::Result<()> {
    let cases = [
        AdvancedFixtureCase {
            name: "extension-headers",
            hex: include_str!("fixtures/ssdp/advanced-extension-headers.hex"),
            expected: AdvancedFixture::ExtensionHeaders,
        },
        AdvancedFixtureCase {
            name: "duplicate-headers",
            hex: include_str!("fixtures/ssdp/advanced-duplicate-headers.hex"),
            expected: AdvancedFixture::DuplicateHeaders,
        },
        AdvancedFixtureCase {
            name: "body-bytes",
            hex: include_str!("fixtures/ssdp/advanced-body-bytes.hex"),
            expected: AdvancedFixture::BodyBytes,
        },
        AdvancedFixtureCase {
            name: "multicast-ipv6",
            hex: include_str!("fixtures/ssdp/advanced-multicast-ipv6.hex"),
            expected: AdvancedFixture::MulticastHost,
        },
        AdvancedFixtureCase {
            name: "unknown-preservation",
            hex: include_str!("fixtures/ssdp/advanced-unknown-preservation.hex"),
            expected: AdvancedFixture::UnknownPreservation,
        },
    ];

    for case in cases {
        let bytes = hex_bytes(case.hex);
        let ssdp = Ssdp::parse(&bytes)
            .unwrap_or_else(|err| panic!("{} fixture should parse as SSDP: {err}", case.name));

        assert_eq!(ssdp.to_bytes(), bytes, "{}", case.name);

        match case.expected {
            AdvancedFixture::ExtensionHeaders => {
                assert_eq!(
                    ssdp.headers()
                        .get_first(SsdpHeaderNameKind::Host)
                        .expect("HOST header")
                        .as_bytes(),
                    SSDP_IPV6_SITE_LOCAL_HOST.as_bytes()
                );
                assert_eq!(
                    ssdp.headers()
                        .get_first(SsdpHeaderNameKind::Opt)
                        .expect("OPT header")
                        .as_bytes(),
                    b"\"http://schemas.upnp.org/upnp/1/0/\"; ns=01"
                );
                let nls = ssdp
                    .headers()
                    .iter()
                    .find(|header| header.name().kind() == SsdpHeaderNameKind::NlsPrefixed)
                    .expect("NLS header");
                assert_eq!(nls.name().original(), "01-NLS");
                assert_eq!(nls.name().nls_namespace(), Some("01"));
                assert_eq!(nls.value().as_bytes(), b"12345678");
            }
            AdvancedFixture::DuplicateHeaders => {
                let st_values = ssdp
                    .headers()
                    .get_all(SsdpHeaderNameKind::St)
                    .map(|value| value.as_bytes())
                    .collect::<Vec<_>>();
                assert_eq!(
                    st_values,
                    vec![SSDP_ST_ALL.as_bytes(), SSDP_TARGET_ROOTDEVICE.as_bytes()]
                );

                let duplicate_values = ssdp
                    .headers()
                    .iter()
                    .filter(|header| header.name().original() == "X-DUP")
                    .map(|header| header.value().as_bytes())
                    .collect::<Vec<_>>();
                assert_eq!(
                    duplicate_values,
                    vec![b"first".as_slice(), b"second".as_slice()]
                );
            }
            AdvancedFixture::BodyBytes => {
                assert_eq!(ssdp.body(), b"opaque-body\0bytes");
                assert!(ssdp.message().start_line().as_response().is_some());
            }
            AdvancedFixture::MulticastHost => {
                assert_eq!(
                    ssdp.headers()
                        .get_first(SsdpHeaderNameKind::Host)
                        .expect("HOST header")
                        .as_bytes(),
                    SSDP_IPV6_SITE_LOCAL_HOST.as_bytes()
                );
                assert_eq!(
                    ssdp.headers()
                        .get_first(SsdpHeaderNameKind::St)
                        .expect("ST header")
                        .as_bytes(),
                    SSDP_TARGET_ROOTDEVICE.as_bytes()
                );
            }
            AdvancedFixture::UnknownPreservation => {
                let request = ssdp
                    .message()
                    .start_line()
                    .as_request()
                    .expect("request line");
                assert_eq!(request.method().as_str(), "X-SEARCH");
                assert_eq!(request.target().as_str(), "/device.xml");
                assert_eq!(request.version().as_str(), "HTTP/1.0");
                assert_eq!(
                    ssdp.headers()
                        .get_first(SsdpHeaderNameKind::Unknown)
                        .expect("unknown header")
                        .as_bytes(),
                    b"opaque"
                );
            }
        }
    }

    Ok(())
}

fn hex_bytes(input: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut high = None;

    for byte in input.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let nibble = hex_nibble(byte);
        if let Some(previous) = high.take() {
            bytes.push((previous << 4) | nibble);
        } else {
            high = Some(nibble);
        }
    }

    assert!(high.is_none(), "hex fixture has an odd number of digits");
    bytes
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte: {byte:#x}"),
    }
}
