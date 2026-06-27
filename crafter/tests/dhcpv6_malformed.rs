#[macro_use]
mod support;

use crafter::protocols::dhcp::Dhcpv6;
use crafter::CrafterError;

#[derive(Debug, Clone, Copy)]
enum TypedAccessor {
    ClientDuid,
    IaNa,
    IaAddr,
    IaPd,
    IaPrefix,
    NestedIaNa,
}

struct DecodeCase {
    name: &'static str,
    hex: &'static str,
    expected: CrafterError,
}

struct TypedCase {
    name: &'static str,
    hex: &'static str,
    accessor: TypedAccessor,
    expected: CrafterError,
}

#[test]
fn dhcpv6_malformed_decode_fixtures_report_structured_errors() {
    let cases = [
        DecodeCase {
            name: "empty input",
            hex: fixture_str!("malformed/dhcpv6-empty.hex"),
            expected: CrafterError::buffer_too_short("dhcpv6.client_server_header", 4, 0),
        },
        DecodeCase {
            name: "short client/server header",
            hex: fixture_str!("malformed/dhcpv6-client-header-short.hex"),
            expected: CrafterError::buffer_too_short("dhcpv6.client_server_header", 4, 3),
        },
        DecodeCase {
            name: "short relay header",
            hex: fixture_str!("malformed/dhcpv6-relay-header-short.hex"),
            expected: CrafterError::buffer_too_short("dhcpv6.relay_header", 34, 33),
        },
        DecodeCase {
            name: "truncated option code",
            hex: fixture_str!("malformed/dhcpv6-option-code-short.hex"),
            expected: CrafterError::buffer_too_short("dhcpv6.option.code", 2, 1),
        },
        DecodeCase {
            name: "truncated option length",
            hex: fixture_str!("malformed/dhcpv6-option-length-short.hex"),
            expected: CrafterError::buffer_too_short("dhcpv6.option.length", 4, 3),
        },
        DecodeCase {
            name: "truncated option payload",
            hex: fixture_str!("malformed/dhcpv6-option-payload-short.hex"),
            expected: CrafterError::buffer_too_short("dhcpv6.option.payload", 8, 5),
        },
    ];

    for case in cases {
        let bytes = parse_hex(case.name, case.hex);
        assert_eq!(
            Dhcpv6::decode(&bytes).unwrap_err(),
            case.expected,
            "{} should return a structured decode error",
            case.name
        );
    }
}

#[test]
fn dhcpv6_malformed_typed_accessors_report_structured_errors() {
    let cases = [
        TypedCase {
            name: "truncated DUID",
            hex: fixture_str!("malformed/dhcpv6-clientid-duid-short.hex"),
            accessor: TypedAccessor::ClientDuid,
            expected: CrafterError::buffer_too_short("dhcpv6.duid.type", 2, 1),
        },
        TypedCase {
            name: "truncated IA_NA",
            hex: fixture_str!("malformed/dhcpv6-ia-na-short.hex"),
            accessor: TypedAccessor::IaNa,
            expected: CrafterError::buffer_too_short("dhcpv6.option.ia_na", 12, 11),
        },
        TypedCase {
            name: "truncated IAADDR",
            hex: fixture_str!("malformed/dhcpv6-iaaddr-short.hex"),
            accessor: TypedAccessor::IaAddr,
            expected: CrafterError::buffer_too_short("dhcpv6.option.iaaddr", 24, 23),
        },
        TypedCase {
            name: "truncated IA_PD",
            hex: fixture_str!("malformed/dhcpv6-ia-pd-short.hex"),
            accessor: TypedAccessor::IaPd,
            expected: CrafterError::buffer_too_short("dhcpv6.option.ia_pd", 12, 11),
        },
        TypedCase {
            name: "truncated IAPREFIX",
            hex: fixture_str!("malformed/dhcpv6-iaprefix-short.hex"),
            accessor: TypedAccessor::IaPrefix,
            expected: CrafterError::buffer_too_short("dhcpv6.option.iaprefix", 25, 24),
        },
        TypedCase {
            name: "nested option overrun",
            hex: fixture_str!("malformed/dhcpv6-nested-option-overrun.hex"),
            accessor: TypedAccessor::NestedIaNa,
            expected: CrafterError::buffer_too_short("dhcpv6.option.payload", 8, 5),
        },
    ];

    for case in cases {
        let bytes = parse_hex(case.name, case.hex);
        let message = Dhcpv6::decode(&bytes)
            .unwrap_or_else(|err| panic!("{} envelope should decode: {err}", case.name));
        let error = typed_error(&message, case.accessor);
        assert_eq!(
            error, case.expected,
            "{} should return a structured typed-accessor error",
            case.name
        );
    }
}

fn typed_error(message: &Dhcpv6, accessor: TypedAccessor) -> CrafterError {
    let option = &message.options_ref()[0];
    match accessor {
        TypedAccessor::ClientDuid => message.client_duid_value().unwrap_err(),
        TypedAccessor::IaNa => option.ia_na_value().unwrap_err(),
        TypedAccessor::IaAddr => option.ia_addr_value().unwrap_err(),
        TypedAccessor::IaPd => option.ia_pd_value().unwrap_err(),
        TypedAccessor::IaPrefix => option.ia_prefix_value().unwrap_err(),
        TypedAccessor::NestedIaNa => option.ia_na_value().unwrap_err(),
    }
}

fn parse_hex(name: &str, input: &str) -> Vec<u8> {
    let mut digits = String::new();
    for line in input.lines() {
        let data = line.split('#').next().unwrap_or_default();
        digits.extend(data.chars().filter(|ch| !ch.is_whitespace()));
    }
    assert!(
        digits.len() % 2 == 0,
        "{name} fixture has an odd number of hex digits"
    );

    digits
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = core::str::from_utf8(chunk)
                .unwrap_or_else(|_| panic!("{name} fixture contains non-UTF8 hex"));
            u8::from_str_radix(byte, 16)
                .unwrap_or_else(|_| panic!("{name} fixture has invalid hex byte {byte}"))
        })
        .collect()
}
