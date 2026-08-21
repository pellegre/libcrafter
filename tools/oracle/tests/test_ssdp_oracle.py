"""Generator-stage SSDP oracle coverage."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import random
import unittest

from tools.oracle.engine.generator import PacketGenerator, load_stack_grammar
from tools.oracle.engine.model import JSONObject, PacketPlan
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.sampling import _SKIP_FIELD, _SamplingContext


_SEED = 7400
_SSDP_STACK_SUFFIX = ["udp", "ssdp"]
_SSDP_SUPPORTED_FIELDS = frozenset(
    {
        "message_kind",
        "method",
        "request_target",
        "version",
        "status_code",
        "reason_phrase",
        "headers",
        "body",
    }
)
_SSDP_CORE_CASES = {
    "ssdp-m-search",
    "ssdp-notify-alive",
    "ssdp-notify-byebye",
    "ssdp-notify-update",
    "ssdp-response-ok",
    "ssdp-unknown-preservation",
    "ssdp-body-bytes",
    "ssdp-raw-fallback",
}


def _ssdp_grammar() -> JSONObject:
    grammar = deepcopy(load_stack_grammar())

    # The layer spec keeps Scapy marked planned until backend validation steps
    # finish. These tests exercise the generator-stage sampler only, so enable
    # the in-memory support bits the same way other protocol generator tests do.
    support = grammar["layers"]["ssdp"]["backend_support"]
    assert isinstance(support, dict)
    for backend in ("scapy", "libcrafter"):
        entry = support.setdefault(backend, {})
        assert isinstance(entry, dict)
        entry["status"] = "supported"
        entry["encode"] = True
        entry["decode"] = True

    # Keep profile-level stack selection focused on the SSDP stack fragments
    # without changing the source specs during this test-only step.
    stacks = grammar["stacks"]
    assert isinstance(stacks, dict)
    for raw_stack in stacks.values():
        assert isinstance(raw_stack, dict)
        layers = raw_stack.get("layers")
        if isinstance(layers, list) and "ssdp" in layers:
            families = raw_stack.setdefault("families", [])
            assert isinstance(families, list)
            if "ssdp" not in families:
                families.append("ssdp")

    return grammar


def _ssdp_generator(*, profile: str = "ssdp-smoke") -> PacketGenerator:
    return PacketGenerator(
        seed=_SEED,
        profile=profile,
        backend="scapy",
        grammar=_ssdp_grammar(),
    )


def _plan_for(
    case: str,
    feature: str,
    *,
    root: str = "l3:ipv4",
    index: int = 0,
) -> PacketPlan:
    return _ssdp_generator().generate(
        index=index,
        root=root,
        family="ssdp",
        case=case,
        feature=feature,
        direction="backend_to_libcrafter",
    )


def _ctx(*, case: str = "ssdp-m-search") -> _SamplingContext:
    return _SamplingContext(
        rng=random.Random(17),
        profile="ssdp-smoke",
        feature_weights={
            "baseline": 10,
            "boundary": 3,
            "malformed": 0,
            "pcap": 0,
        },
        stack=["ipv4", "udp", "ssdp"],
        payload_min=0,
        payload_max=0,
        feature=None,
        case=case,
    )


def _sample_field(
    field_name: str,
    domain: object,
    *,
    case: str = "ssdp-m-search",
    current_fields: Mapping[str, object] | None = None,
) -> object:
    sampler = SAMPLER_REGISTRY.require("ssdp")
    return sampler.sample(
        _ctx(case=case),
        field_name,
        domain,
        field_spec={"name": field_name},
        current_fields=current_fields or {},
    )


def _header_values(headers: object, name: str) -> list[str]:
    assert isinstance(headers, list)
    values: list[str] = []
    for header in headers:
        assert isinstance(header, dict)
        if header.get("name") == name:
            value = header.get("value")
            assert isinstance(value, str)
            values.append(value)
    return values


def _headers(ssdp: Mapping[str, object]) -> list[Mapping[str, object]]:
    headers = ssdp.get("headers")
    assert isinstance(headers, list)
    output: list[Mapping[str, object]] = []
    for header in headers:
        assert isinstance(header, Mapping)
        output.append(header)
    return output


class SsdpSamplerRegistrationTest(unittest.TestCase):
    def test_ssdp_sampler_registers_supported_field_surface(self) -> None:
        sampler = SAMPLER_REGISTRY.require("ssdp")
        self.assertEqual(sampler.supported_fields, _SSDP_SUPPORTED_FIELDS)

    def test_start_line_field_domains_preserve_known_and_unknown_values(self) -> None:
        self.assertEqual(
            _sample_field("message_kind", "m_search", case="ssdp-raw-fallback"),
            "raw_preserved",
        )
        self.assertEqual(
            _sample_field(
                "method",
                "unknown_preserved",
                current_fields={"message_kind": "m_search"},
            ),
            "M-SEARCH-EXAMPLE",
        )
        self.assertEqual(
            _sample_field(
                "method",
                "excluded_search",
                current_fields={"message_kind": "m_search"},
            ),
            "SEARCH",
        )
        self.assertIs(
            _sample_field(
                "method", "m_search", current_fields={"message_kind": "response"}
            ),
            _SKIP_FIELD,
        )
        self.assertEqual(
            _sample_field(
                "request_target",
                "unknown_preserved",
                current_fields={"message_kind": "m_search"},
            ),
            "/example-preserved",
        )
        self.assertEqual(_sample_field("version", "explicit_preserved"), "HTTP/1.0")
        self.assertEqual(
            _sample_field(
                "status_code",
                "excluded_http_error",
                current_fields={"message_kind": "response"},
            ),
            404,
        )

    def test_header_and_body_domains_cover_duplicates_extensions_and_binary(
        self,
    ) -> None:
        duplicate_headers = _sample_field("headers", "duplicate_preserved")
        self.assertEqual(
            _header_values(duplicate_headers, "NT"),
            ["upnp:rootdevice", "uuid:device-001"],
        )
        self.assertEqual(
            _header_values(duplicate_headers, "CACHE-CONTROL"),
            ["max-age=1800", "max-age=60"],
        )

        extension_headers = _sample_field("headers", "extension_nls")
        self.assertEqual(_header_values(extension_headers, "HOST"), ["[ff05::c]:1900"])
        self.assertEqual(
            _header_values(extension_headers, "OPT"),
            ['"http://schemas.upnp.org/upnp/1/0/"; ns=01'],
        )
        self.assertEqual(_header_values(extension_headers, "01-NLS"), ["1"])

        body = _sample_field(
            "body",
            "binary",
            current_fields={"message_kind": "response"},
        )
        self.assertEqual(body, {"hex": "000d0a626f64793a6279746573ff"})


class SsdpGeneratorSelectionTest(unittest.TestCase):
    def test_core_feature_case_selection_is_deterministic(self) -> None:
        first = [
            _ssdp_generator().generate(index=index, family="ssdp", feature="ssdp_core")
            for index in range(12)
        ]
        second = [
            _ssdp_generator().generate(index=index, family="ssdp", feature="ssdp_core")
            for index in range(12)
        ]

        self.assertEqual(
            [plan.to_dict() for plan in first],
            [plan.to_dict() for plan in second],
        )
        self.assertTrue({plan.case for plan in first})
        self.assertLessEqual({plan.case for plan in first}, _SSDP_CORE_CASES)

        for plan in first:
            with self.subTest(case=plan.case, stack=plan.stack):
                self.assertEqual(plan.stack[-2:], _SSDP_STACK_SUFFIX)
                self.assertEqual(plan.metadata["feature"], "ssdp_core")
                self.assertIn("ssdp", plan.fields)
                self.assertEqual(plan.fields["udp"]["src_port"], 1900)
                self.assertEqual(plan.fields["udp"]["dst_port"], 1900)
                self.assertTrue(plan.strict_bytes)


class SsdpFeatureBehaviorTest(unittest.TestCase):
    def test_core_behaviors_materialize_search_response_and_raw_fallback(self) -> None:
        search = _plan_for("ssdp-m-search", "ssdp_core")
        search_fields = search.fields["ssdp"]
        self.assertEqual(search_fields["message_kind"], "m_search")
        self.assertEqual(search_fields["start_line"], "M-SEARCH * HTTP/1.1")
        self.assertEqual(
            _header_values(search_fields["headers"], "MAN"), ['"ssdp:discover"']
        )
        self.assertEqual(_header_values(search_fields["headers"], "ST"), ["ssdp:all"])

        response = _plan_for("ssdp-response-ok", "ssdp_core")
        response_fields = response.fields["ssdp"]
        self.assertEqual(response_fields["message_kind"], "response")
        self.assertEqual(response_fields["status_code"], 200)
        self.assertEqual(response_fields["reason_phrase"], "OK")
        self.assertEqual(_header_values(response_fields["headers"], "EXT"), [""])

        raw = _plan_for("ssdp-raw-fallback", "ssdp_core")
        raw_fields = raw.fields["ssdp"]
        self.assertEqual(raw_fields["message_kind"], "raw_preserved")
        self.assertEqual(
            raw_fields["payload"],
            {"utf8": "not an SSDP message\r\nwithout the required shape"},
        )
        self.assertNotIn("headers", raw_fields)
        self.assertNotIn("method", raw_fields)

    def test_header_behaviors_preserve_duplicates_extensions_and_boundaries(
        self,
    ) -> None:
        duplicate = _plan_for("ssdp-duplicate-headers", "ssdp_headers").fields["ssdp"]
        duplicate_names = [header["name"] for header in _headers(duplicate)]
        self.assertEqual(duplicate_names.count("NT"), 2)
        self.assertEqual(duplicate_names.count("USN"), 2)
        self.assertEqual(duplicate_names.count("CACHE-CONTROL"), 2)

        extension = _plan_for(
            "ssdp-extension-headers",
            "ssdp_headers",
            root="l3:ipv6",
        ).fields["ssdp"]
        self.assertEqual(
            _header_values(extension["headers"], "HOST"), ["[ff05::c]:1900"]
        )
        self.assertEqual(
            _header_values(extension["headers"], "TCPPORT.UPNP.ORG"), ["65535"]
        )
        self.assertEqual(_header_values(extension["headers"], "01-NLS"), ["1"])

        boundary = _plan_for("ssdp-boundary-headers", "ssdp_headers").fields["ssdp"]
        self.assertEqual(_header_values(boundary["headers"], "EXT"), [""])
        self.assertEqual(boundary["body"], {"hex": "626f64792d6279746573"})
        ows_headers = [
            header for header in _headers(boundary) if header["name"] == "X-OWS"
        ]
        self.assertEqual(
            ows_headers,
            [
                {
                    "name": "X-OWS",
                    "value": "trimmed value",
                    "wire_value": "  trimmed value\t",
                }
            ],
        )

    def test_multicast_and_malformed_behavior_hooks_are_data_driven(self) -> None:
        plugin = SAMPLER_REGISTRY.require("ssdp")
        grammar = _ssdp_grammar()

        ipv4_fields: dict[str, JSONObject] = {"ipv4": {}, "udp": {}, "ssdp": {}}
        assert plugin.apply_behavior is not None
        plugin.apply_behavior(
            ipv4_fields,
            stack=["ipv4", "udp", "ssdp"],
            feature="ssdp_multicast",
            case="ssdp-ipv4-multicast",
            behavior="ipv4-m-search-multicast",
            grammar=grammar,
        )
        self.assertEqual(ipv4_fields["ipv4"]["src"], "192.0.2.10")
        self.assertEqual(ipv4_fields["ipv4"]["dst"], "239.255.255.250")
        self.assertEqual(ipv4_fields["ipv4"]["ttl"], 2)
        self.assertEqual(
            _header_values(ipv4_fields["ssdp"]["headers"], "HOST"),
            ["239.255.255.250:1900"],
        )

        ipv6_fields: dict[str, JSONObject] = {"ipv6": {}, "udp": {}, "ssdp": {}}
        plugin.apply_behavior(
            ipv6_fields,
            stack=["ipv6", "udp", "ssdp"],
            feature="ssdp_multicast",
            case="ssdp-ipv6-multicast",
            behavior="ipv6-link-scope-m-search-multicast-override",
            grammar=grammar,
        )
        self.assertEqual(ipv6_fields["ipv6"]["dst"], "ff02::c")
        self.assertEqual(ipv6_fields["ipv6"]["hop_limit"], 1)
        self.assertEqual(ipv6_fields["udp"]["src_port"], 49152)
        self.assertEqual(
            _header_values(ipv6_fields["ssdp"]["headers"], "HOST"),
            ["[ff02::c]:1900"],
        )

        malformed_fields: dict[str, JSONObject] = {"udp": {}, "ssdp": {}}
        plugin.apply_behavior(
            malformed_fields,
            stack=["ipv4", "udp", "ssdp"],
            feature="ssdp_malformed",
            case="malformed-ssdp-bad-status",
            behavior="bad-status",
            grammar=grammar,
        )
        self.assertEqual(malformed_fields["ssdp"]["message_kind"], "malformed")
        self.assertEqual(
            malformed_fields["ssdp"]["fixture"],
            "crafter/tests/fixtures/ssdp/malformed-bad-status.ssdp",
        )
        self.assertEqual(
            malformed_fields["ssdp"]["expected_error"],
            {"kind": "InvalidResponseStatusCode", "field": "status_code"},
        )
        self.assertEqual(malformed_fields["udp"]["src_port"], 1900)
        self.assertEqual(malformed_fields["udp"]["dst_port"], 1900)


if __name__ == "__main__":
    unittest.main()
