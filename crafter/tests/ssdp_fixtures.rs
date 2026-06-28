use crafter::{Ssdp, SsdpHeaderNameKind, SsdpMethod, SSDP_ST_ALL};

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

#[test]
fn valid_ssdp_fixtures_parse_and_roundtrip() -> crafter::Result<()> {
    let cases = [
        FixtureCase {
            name: "m-search",
            bytes: include_bytes!("fixtures/ssdp/valid_m_search.ssdp"),
            expected: ExpectedFixture::MSearch,
        },
        FixtureCase {
            name: "notify",
            bytes: include_bytes!("fixtures/ssdp/valid_notify.ssdp"),
            expected: ExpectedFixture::Notify,
        },
        FixtureCase {
            name: "response",
            bytes: include_bytes!("fixtures/ssdp/valid_response.ssdp"),
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
