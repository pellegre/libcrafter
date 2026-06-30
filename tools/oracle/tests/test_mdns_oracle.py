"""Offline oracle coverage for mDNS specs, generation, and backends.

The mDNS oracle models DNS messages carried over UDP/5353. These tests keep the
unit gate local and deterministic: spec/generator/materializer-contract checks
run without Scapy, and Scapy encode/decode assertions are skipped when Scapy is
not installed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import unittest

from tools.oracle.engine.backends.scapy.protocols import SCAPY_REGISTRY
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.generator import (
    PacketGenerator,
    case_byte_policy_index,
    generate_plans,
)
from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import FeatureSpec, LayerSpec, StackSpec, load_oracle_specs

try:  # pragma: no cover - environment-dependent optional dependency.
    import scapy.all as _scapy_all  # type: ignore[import-untyped]  # noqa: F401

    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when Scapy is absent.
    _SCAPY_AVAILABLE = False


_SEED = 6762
_MDNS_PORT = 5353
_CASE_FEATURES = {
    "mdns-query-udp-5353": "mdns_core",
    "mdns-response-udp-5353": "mdns_core",
    "mdns-qu-question": "mdns_core",
    "mdns-cache-flush-record": "mdns_core",
    "mdns-known-answer-query": "mdns_core",
    "mdns-goodbye-ttl-zero": "mdns_core",
    "mdns-probe-authority": "mdns_core",
    "mdns-announcement": "mdns_core",
    "mdns-unknown-record-preservation": "mdns_core",
    "mdns-dns-sd-browse": "mdns_dns_sd",
    "mdns-dns-sd-resolve": "mdns_dns_sd",
    "mdns-dns-sd-subtype": "mdns_dns_sd",
    "mdns-bonjour-txt": "mdns_dns_sd",
    "mdns-bonjour-ptr-srv-txt-addresses": "mdns_dns_sd",
    "mdns-ipv4-multicast": "mdns_multicast",
    "mdns-ipv6-multicast": "mdns_multicast",
    "mdns-pcap-raw-ipv4": "mdns_pcap",
    "mdns-pcap-ethernet-ipv4": "mdns_pcap",
    "mdns-pcap-ethernet-ipv6": "mdns_pcap",
}

_LIBCRAFTER_MDNS_FIELDS = frozenset(
    {
        "additional",
        "answers",
        "authority",
        "authorities",
        "authoritative",
        "class_bits",
        "comparison",
        "expected_stack",
        "fixture",
        "flags",
        "helper",
        "is_response",
        "link_type",
        "message_kind",
        "name_encoding",
        "opcode",
        "questions",
        "raw_dns",
        "response_code",
        "root",
        "transaction_id",
        "transport",
    }
)
_LIBCRAFTER_TRANSPORT_FIELDS = frozenset(
    {
        "destination_port",
        "service_port",
        "source_port",
        "udp_destination_port",
        "udp_source_port",
        "unicast_reply",
    }
)
_LIBCRAFTER_QUESTION_FIELDS = frozenset(
    {
        "base_class",
        "class",
        "name",
        "qclass",
        "qname",
        "qtype",
        "qu",
        "raw_class",
        "raw_question_class",
        "record_class",
        "type",
        "unicast_response_preferred",
    }
)
_LIBCRAFTER_RECORD_FIELDS = frozenset(
    {
        "address",
        "base_class",
        "cache_flush",
        "class",
        "data",
        "name",
        "port",
        "priority",
        "raw_class",
        "rclass",
        "rdata",
        "record_class",
        "record_type",
        "rrname",
        "strings",
        "target",
        "ttl",
        "type",
        "weight",
    }
)


def _mdns_plan(
    case: str,
    *,
    root: str = "l3:ipv4",
    direction: str = "backend_to_libcrafter",
) -> PacketPlan:
    plans = generate_plans(
        seed=_SEED,
        profile="mdns-smoke",
        count=1,
        backend="scapy",
        root=root,
        family="mdns",
        case=case,
        feature=_CASE_FEATURES[case],
        direction=direction,
    )
    assert len(plans) == 1
    return plans[0]


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise AssertionError(f"{name} must be a mapping")
    return value


def _section(value: object, name: str) -> list[Mapping[str, object]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise AssertionError(f"{name} must be a list")
    output: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise AssertionError(f"{name} items must be mappings")
        output.append(item)
    return output


def _presentation_name(value: object) -> str:
    if isinstance(value, Mapping) and isinstance(value.get("presentation"), str):
        return value["presentation"]
    if isinstance(value, str):
        return value
    raise AssertionError(f"expected normalized DNS name, got {value!r}")


class MdnsSpecLoadingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def test_mdns_layer_features_profiles_and_stacks_are_registered(self) -> None:
        layer = self.specs.layers.get("mdns")
        self.assertIsInstance(layer, LayerSpec)
        assert layer is not None
        self.assertIn("udp", layer.parents)
        self.assertIn("mdns-query-udp-5353", layer.coverage_cases)
        self.assertIn("mdns-bonjour-ptr-srv-txt-addresses", layer.coverage_cases)
        self.assertEqual(layer.backend_support["scapy"].status, "supported")
        self.assertEqual(layer.backend_support["wireshark"].status, "supported")
        self.assertEqual(layer.backend_support["libcrafter"].status, "supported")

        for feature_name in (
            "mdns_core",
            "mdns_dns_sd",
            "mdns_malformed",
            "mdns_multicast",
            "mdns_pcap",
        ):
            with self.subTest(feature=feature_name):
                feature = self.specs.features.get(feature_name)
                self.assertIsInstance(feature, FeatureSpec)
                assert feature is not None
                self.assertIn("mdns", feature.layers)
                self.assertIn("udp", feature.layers)

        for profile_name in ("mdns-smoke", "mdns-ci", "mdns-boundary", "mdns-pcap"):
            self.assertIn(profile_name, self.specs.profiles)
        self.assertIn("mdns", self.specs.families)

        for stack_name, root, layers in (
            ("ipv4_udp_mdns", "l3:ipv4", ("ipv4", "udp", "mdns")),
            ("ipv6_udp_mdns", "l3:ipv6", ("ipv6", "udp", "mdns")),
            ("ethernet_ipv4_udp_mdns", "link:ethernet", ("ethernet", "ipv4", "udp", "mdns")),
            ("ethernet_ipv6_udp_mdns", "link:ethernet", ("ethernet", "ipv6", "udp", "mdns")),
        ):
            with self.subTest(stack=stack_name):
                stack = self.specs.stacks.get(stack_name)
                self.assertIsInstance(stack, StackSpec)
                assert stack is not None
                self.assertEqual(stack.root, root)
                self.assertEqual(stack.layers, layers)

    def test_mdns_supported_fields_and_backend_plugins_match_layer_surface(self) -> None:
        layer = self.specs.layers["mdns"]
        layer_fields = {field.name for field in layer.fields}
        sampler = SAMPLER_REGISTRY.require("mdns")
        self.assertLessEqual(sampler.supported_fields, layer_fields)
        self.assertIn("transport", sampler.supported_fields)
        self.assertIn("class_bits", sampler.supported_fields)

        scapy = SCAPY_REGISTRY.require("mdns")
        self.assertIn("questions", scapy.supported_fields)
        self.assertIn("fixture", scapy.supported_fields)
        self.assertIn("raw_dns", scapy.supported_fields)

        wireshark = WIRESHARK_REGISTRY.require("mdns")
        self.assertIn("dns.id", wireshark.tshark_aliases["transaction_id"])

    def test_specs_declare_normalized_model_fields(self) -> None:
        layer_model = _mapping(self.specs.layers["mdns"].raw["normalized_fields"], "normalized_fields")
        self.assertIn("transport", layer_model)
        self.assertIn("message", layer_model)
        self.assertIn("question", layer_model)
        self.assertIn("record", layer_model)
        self.assertIn("dns_sd", layer_model)

        core_model = _mapping(self.specs.features["mdns_core"].raw["normalized_model"], "core_model")
        self.assertIn("message", core_model)
        self.assertIn("question", core_model)
        self.assertIn("record", core_model)
        self.assertIn("raw_record", core_model)


class MdnsGeneratorTest(unittest.TestCase):
    def test_seeded_generation_is_deterministic_and_pins_udp_5353(self) -> None:
        first = _mdns_plan("mdns-query-udp-5353")
        second = _mdns_plan("mdns-query-udp-5353")
        self.assertEqual(first.to_dict(), second.to_dict())

        self.assertEqual(first.stack, ["ipv4", "udp", "mdns"])
        self.assertEqual(first.metadata["feature"], "mdns_core")
        self.assertEqual(first.metadata["feature_behavior"], "query-udp-5353")
        self.assertTrue(first.strict_bytes)
        self.assertEqual(first.fields["udp"]["src_port"], _MDNS_PORT)
        self.assertEqual(first.fields["udp"]["dst_port"], _MDNS_PORT)

        mdns = first.fields["mdns"]
        self.assertEqual(mdns["message_kind"], "multicast_query")
        self.assertEqual(mdns["transaction_id"], 0)
        self.assertFalse(mdns["is_response"])
        self.assertEqual(mdns["transport"]["service_port"], _MDNS_PORT)
        questions = _section(mdns["questions"], "questions")
        self.assertEqual(questions[0]["name"], "printer.local.")
        self.assertEqual(questions[0]["type"], "A")

    def test_class_bit_cases_are_normalized_in_generated_fields(self) -> None:
        query = _mdns_plan("mdns-qu-question")
        question = _section(query.fields["mdns"]["questions"], "questions")[0]
        self.assertEqual(question["raw_class"], 0x8001)
        self.assertEqual(question["base_class"], "IN")
        self.assertTrue(question["unicast_response_preferred"])

        response = _mdns_plan("mdns-cache-flush-record")
        answer = _section(response.fields["mdns"]["answers"], "answers")[0]
        self.assertEqual(answer["raw_class"], 0x8001)
        self.assertEqual(answer["base_class"], "IN")
        self.assertTrue(answer["cache_flush"])

    def test_dns_sd_generation_preserves_service_and_instance_names(self) -> None:
        browse = _mdns_plan("mdns-dns-sd-browse")
        browse_question = _section(browse.fields["mdns"]["questions"], "questions")[0]
        self.assertEqual(browse.fields["mdns"]["message_kind"], "dns_sd_browse")
        self.assertEqual(browse_question["name"], "_ipp._tcp.local.")
        self.assertEqual(browse_question["type"], "PTR")

        resolve = _mdns_plan("mdns-dns-sd-resolve")
        questions = _section(resolve.fields["mdns"]["questions"], "questions")
        self.assertEqual([question["type"] for question in questions], ["SRV", "TXT"])
        self.assertTrue(
            all(
                question["name"] == "Office\\032Printer._ipp._tcp.local."
                for question in questions
            )
        )

    def test_byte_policies_drive_direction_filtering(self) -> None:
        policies = case_byte_policy_index()
        self.assertEqual(policies["mdns-query-udp-5353"], "strict_bytes")
        self.assertEqual(policies["mdns-compressed-names"], "normalized")
        self.assertEqual(policies["malformed-mdns-truncated-question-fields"], "structured_error")
        self.assertEqual(policies["mdns-pcap-ethernet-ipv4"], "strict_bytes")

        generator = PacketGenerator(seed=_SEED, profile="mdns-smoke")
        self.assertTrue(
            generator._case_supported_in_direction(
                "mdns-compressed-names",
                "backend_to_libcrafter",
            )
        )
        self.assertFalse(
            generator._case_supported_in_direction(
                "mdns-compressed-names",
                "libcrafter_to_backend",
            )
        )
        self.assertFalse(
            generator._case_supported_in_direction(
                "malformed-mdns-truncated-question-fields",
                "backend_to_libcrafter",
            )
        )


class MdnsLibcrafterMaterializerPlanTest(unittest.TestCase):
    def test_packet_materializer_safe_cases_emit_compatible_plan_fields(self) -> None:
        cases = (
            ("mdns-query-udp-5353", "l3:ipv4"),
            ("mdns-qu-question", "l3:ipv4"),
            ("mdns-cache-flush-record", "l3:ipv4"),
            ("mdns-known-answer-query", "l3:ipv4"),
            ("mdns-goodbye-ttl-zero", "l3:ipv4"),
            ("mdns-probe-authority", "l3:ipv4"),
            ("mdns-announcement", "l3:ipv4"),
            ("mdns-unknown-record-preservation", "l3:ipv4"),
            ("mdns-dns-sd-resolve", "l3:ipv4"),
            ("mdns-bonjour-txt", "l3:ipv4"),
            ("mdns-bonjour-ptr-srv-txt-addresses", "l3:ipv4"),
            ("mdns-ipv4-multicast", "l3:ipv4"),
            ("mdns-ipv6-multicast", "l3:ipv6"),
        )
        for case, root in cases:
            with self.subTest(case=case):
                plan = _mdns_plan(case, root=root, direction="libcrafter_to_backend")
                self.assertEqual(plan.direction, "libcrafter_to_backend")
                self.assertEqual(plan.stack[-2:], ["udp", "mdns"])
                self.assertIn(plan.stack[0], {"ethernet", "ipv4", "ipv6"})
                self.assertFalse(plan.metadata["malformed"])
                self.assertNotEqual(plan.metadata["comparison_policy"], "non_strict_reencode")

                mdns = _mapping(plan.fields["mdns"], "mdns")
                self.assertLessEqual(set(mdns), _LIBCRAFTER_MDNS_FIELDS)
                self.assertNotEqual(mdns.get("message_kind"), "malformed")
                self.assertNotEqual(mdns.get("file_format"), "pcap")
                fixture = mdns.get("fixture")
                if isinstance(fixture, str):
                    self.assertFalse(fixture.endswith(".pcap"), fixture)

                self._assert_transport_fields(mdns)
                for key in ("questions",):
                    if key in mdns:
                        self._assert_question_list(mdns[key], key)
                for key in ("answers", "authority", "additional"):
                    if key in mdns:
                        self._assert_record_list(mdns[key], key)

    def test_pcap_fixture_cases_are_declared_for_pcap_adapter_not_packet_materializer(self) -> None:
        plan = _mdns_plan("mdns-pcap-ethernet-ipv4", root="link:ethernet")
        mdns = _mapping(plan.fields["mdns"], "mdns")
        self.assertEqual(mdns["file_format"], "pcap")
        self.assertTrue(str(mdns["fixture"]).endswith(".pcap"))
        self.assertIn("roundtrip", self._supported_case_directions("mdns_pcap", "mdns-pcap-ethernet-ipv4"))

    def _assert_transport_fields(self, mdns: Mapping[str, object]) -> None:
        transport = _mapping(mdns["transport"], "transport")
        self.assertLessEqual(set(transport), _LIBCRAFTER_TRANSPORT_FIELDS)
        self.assertEqual(transport["service_port"], _MDNS_PORT)

    def _assert_question_list(self, value: object, name: str) -> None:
        for question in _section(value, name):
            self.assertLessEqual(set(question), _LIBCRAFTER_QUESTION_FIELDS)
            self.assertIn("name", question)
            self.assertIn("type", question)

    def _assert_record_list(self, value: object, name: str) -> None:
        for record in _section(value, name):
            self.assertLessEqual(set(record), _LIBCRAFTER_RECORD_FIELDS)
            self.assertIn("name", record)
            self.assertIn("type", record)

    def _supported_case_directions(self, feature: str, case: str) -> list[str]:
        supported = self._feature(feature).raw["supported_cases"]
        for item in _section(supported, "supported_cases"):
            if item.get("name") == case:
                directions = item.get("directions")
                if not isinstance(directions, list):
                    raise AssertionError("directions must be a list")
                return [str(direction) for direction in directions]
        raise AssertionError(f"missing supported case: {case}")

    def _feature(self, name: str) -> FeatureSpec:
        feature = load_oracle_specs().features.get(name)
        if feature is None:
            raise AssertionError(f"missing feature: {name}")
        return feature


class MdnsScapyMaterializationTest(unittest.TestCase):
    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_scapy_materializes_and_normalizes_cache_flush_record(self) -> None:
        from tools.oracle.engine.backends.scapy import normalize, packets

        plan = _mdns_plan("mdns-cache-flush-record")
        vector = packets.encode_packet_plan(plan)
        decoded = normalize.decode_vector(vector)

        self.assertEqual(vector.root, "l3:ipv4")
        self.assertEqual(decoded.layers, ["ipv4", "udp", "mdns"])
        self.assertNotIn("dns", decoded.layers)
        self.assertEqual(decoded.fields["udp"]["src_port"], _MDNS_PORT)
        self.assertEqual(decoded.fields["udp"]["dst_port"], _MDNS_PORT)

        mdns = decoded.fields["mdns"]
        self.assertEqual(mdns["transaction_id"], 0)
        self.assertTrue(mdns["is_response"])
        self.assertTrue(mdns["authoritative"])
        self.assertTrue(mdns["udp_5353"])
        self.assertEqual(mdns["message_kind"], "multicast_response")
        self.assertEqual(mdns["answer_count"], 1)
        self.assertEqual(mdns["transport"]["service_port"], _MDNS_PORT)

        metadata = decoded.metadata["mdns"]
        answer = metadata["answers"][0]
        self.assertEqual(_presentation_name(answer["name"]), "printer.local.")
        self.assertEqual(answer["record_type"], 1)
        self.assertEqual(answer["raw_class"], 0x8001)
        self.assertEqual(answer["base_class"], 1)
        self.assertTrue(answer["cache_flush"])
        self.assertEqual(answer["ttl"], 120)

    @unittest.skipUnless(_SCAPY_AVAILABLE, "scapy not importable")
    def test_scapy_materializes_dns_sd_browse_query(self) -> None:
        from tools.oracle.engine.backends.scapy import normalize, packets

        plan = _mdns_plan("mdns-dns-sd-browse")
        vector = packets.encode_packet_plan(plan)
        decoded = normalize.decode_vector(vector)

        self.assertEqual(decoded.layers, ["ipv4", "udp", "mdns"])
        mdns = decoded.fields["mdns"]
        self.assertEqual(mdns["message_kind"], "dns_sd_browse")
        self.assertFalse(mdns["is_response"])
        self.assertEqual(mdns["question_count"], 1)

        metadata = decoded.metadata["mdns"]
        question = metadata["questions"][0]
        self.assertEqual(_presentation_name(question["name"]), "_ipp._tcp.local.")
        self.assertEqual(question["record_type"], 12)
        self.assertEqual(question["raw_question_class"], 1)
        self.assertEqual(question["base_question_class"], 1)
        self.assertFalse(question["unicast_response_preferred"])


if __name__ == "__main__":
    unittest.main()
