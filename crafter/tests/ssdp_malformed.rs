use crafter::{Ssdp, SsdpParseErrorKind, SsdpParseField};

#[test]
fn malformed_ssdp_fixtures_return_structured_errors() {
    let missing_delimiter = Ssdp::parse(include_bytes!(
        "fixtures/ssdp/malformed-missing-delimiter.ssdp"
    ))
    .expect_err("missing delimiter fixture is malformed");
    assert!(matches!(
        missing_delimiter.kind(),
        SsdpParseErrorKind::MissingHeaderDelimiter { .. }
    ));
    assert!(missing_delimiter.to_string().contains("CRLF CRLF"));

    let bare_lf = Ssdp::parse(include_bytes!("fixtures/ssdp/malformed-bare-lf.ssdp"))
        .expect_err("bare LF fixture is malformed");
    assert!(matches!(
        bare_lf.kind(),
        SsdpParseErrorKind::BadDelimiter {
            field: SsdpParseField::LineDelimiter,
            ..
        }
    ));

    let bad_header = Ssdp::parse(include_bytes!("fixtures/ssdp/malformed-bad-header.ssdp"))
        .expect_err("bad header fixture is malformed");
    assert!(matches!(
        bad_header.kind(),
        SsdpParseErrorKind::BadHeaderDelimiter { .. }
    ));

    let bad_status = Ssdp::parse(include_bytes!("fixtures/ssdp/malformed-bad-status.ssdp"))
        .expect_err("bad status fixture is malformed");
    assert!(matches!(
        bad_status.kind(),
        SsdpParseErrorKind::InvalidResponseStatusCode { .. }
    ));
}
