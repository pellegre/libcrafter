"""Backend-neutral SSDP oracle spec coverage."""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.directions import (
    BACKEND_TO_LIBCRAFTER,
    LIBCRAFTER_TO_BACKEND,
    LIVE_EXCHANGE,
)
from tools.oracle.engine.generator import case_byte_policy_index
from tools.oracle.engine.spec_loader import (
    FeatureSpec,
    LayerSpec,
    ProfileSpec,
    StackSpec,
    load_oracle_specs,
)


OFFLINE_DIRECTIONS = {BACKEND_TO_LIBCRAFTER, LIBCRAFTER_TO_BACKEND}
SSDP_FEATURES = (
    "ssdp_core",
    "ssdp_headers",
    "ssdp_multicast",
    "ssdp_malformed",
    "ssdp_live",
)
SSDP_PROFILES = (
    "ssdp-smoke",
    "ssdp-ci",
    "ssdp-boundary",
    "ssdp-pcap",
    "ssdp-live-dry-run",
)
SSDP_STACKS = {
    "ipv4_udp_ssdp": ("l3:ipv4", ("ipv4", "udp", "ssdp")),
    "ipv6_udp_ssdp": ("l3:ipv6", ("ipv6", "udp", "ssdp")),
    "ethernet_ipv4_udp_ssdp": (
        "link:ethernet",
        ("ethernet", "ipv4", "udp", "ssdp"),
    ),
    "ethernet_ipv6_udp_ssdp": (
        "link:ethernet",
        ("ethernet", "ipv6", "udp", "ssdp"),
    ),
}


def _supported_cases(feature: FeatureSpec) -> dict[str, Mapping[str, object]]:
    raw_cases = feature.raw.get("supported_cases")
    assert isinstance(raw_cases, Sequence) and not isinstance(raw_cases, (str, bytes))
    cases: dict[str, Mapping[str, object]] = {}
    for raw_case in raw_cases:
        assert isinstance(raw_case, Mapping), "supported case entries must be objects"
        name = raw_case.get("name")
        assert isinstance(name, str), "supported case entries must have names"
        cases[name] = raw_case
    return cases


class SsdpOracleSpecTest(unittest.TestCase):
    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def test_ssdp_layer_declares_udp_packet_surface(self) -> None:
        layer = self.specs.layers.get("ssdp")
        self.assertIsInstance(layer, LayerSpec)
        assert layer is not None

        self.assertEqual(layer.roots, ())
        self.assertEqual(layer.parents, ("udp",))
        self.assertEqual(layer.children, ())
        self.assertEqual(layer.raw["live_eligibility"], "provider_gated")
        self.assertFalse(layer.raw["live_defaults"]["developer_host_raw_send"])

        field_names = {field.name for field in layer.fields}
        for expected in (
            "message_kind",
            "method",
            "request_target",
            "version",
            "status_code",
            "headers",
            "body",
        ):
            self.assertIn(expected, field_names)

        coverage = set(layer.coverage_cases)
        for expected in (
            "ssdp-m-search",
            "ssdp-response-ok",
            "ssdp-raw-fallback",
            "ssdp-ipv4-multicast",
            "ssdp-ipv6-multicast",
            "malformed-ssdp-bad-status",
        ):
            self.assertIn(expected, coverage)

        self.assertIn("scapy", layer.backend_support)
        self.assertIn("libcrafter", layer.backend_support)

    def test_ssdp_features_are_registered_with_expected_shapes(self) -> None:
        expected = {
            "ssdp_core": (("udp", "ssdp"), OFFLINE_DIRECTIONS, True, False),
            "ssdp_headers": (("udp", "ssdp"), OFFLINE_DIRECTIONS, True, False),
            "ssdp_multicast": (
                ("ipv4", "ipv6", "udp", "ssdp"),
                OFFLINE_DIRECTIONS,
                True,
                False,
            ),
            "ssdp_malformed": (("udp", "ssdp"), OFFLINE_DIRECTIONS, False, True),
            "ssdp_live": (
                ("ipv4", "ipv6", "udp", "ssdp"),
                {LIVE_EXCHANGE},
                True,
                False,
            ),
        }

        for name, (layers, directions, strict_bytes, malformed) in expected.items():
            with self.subTest(feature=name):
                feature = self.specs.features.get(name)
                self.assertIsInstance(feature, FeatureSpec)
                assert feature is not None
                self.assertEqual(feature.layers, layers)
                self.assertEqual(set(feature.directions), set(directions))
                self.assertIs(feature.strict_bytes, strict_bytes)
                self.assertIs(feature.malformed, malformed)
                self.assertTrue(feature.coverage_cases)
                self.assertIn("scapy", feature.backend_support)
                self.assertIn("libcrafter", feature.backend_support)

    def test_ssdp_stack_fragment_registers_family_stacks_and_constraint(self) -> None:
        family = self.specs.families["ssdp"]
        self.assertEqual(family.default_stack, ("ipv4", "udp", "ssdp"))
        self.assertEqual(family.feature_tags, ("ipv4", "ipv6", "udp", "ssdp"))

        for name, (root, layers) in SSDP_STACKS.items():
            with self.subTest(stack=name):
                stack = self.specs.stacks.get(name)
                self.assertIsInstance(stack, StackSpec)
                assert stack is not None
                self.assertEqual(stack.root, root)
                self.assertEqual(stack.layers, layers)
                self.assertIn("ssdp-m-search", stack.coverage_cases)

        self.assertIn("ssdp_udp_children", self.specs.constraints)
        constraint = self.specs.constraints["ssdp_udp_children"]
        self.assertEqual(constraint.parent, "udp")
        self.assertEqual(constraint.children, ("ssdp",))

    def test_ssdp_profiles_are_offline_or_dry_run_by_default(self) -> None:
        for name in SSDP_PROFILES:
            with self.subTest(profile=name):
                profile = self.specs.profiles.get(name)
                self.assertIsInstance(profile, ProfileSpec)
                assert profile is not None
                self.assertEqual(
                    [(weight.name, weight.weight) for weight in profile.family_weights],
                    [("ssdp", 1)],
                )
                self.assertEqual(profile.payload_length.as_pair(), [0, 0])
                self.assertEqual(profile.feature_weights["live"], 0)

        self.assertEqual(self.specs.profiles["ssdp-smoke"].default_count, 10)
        self.assertEqual(self.specs.profiles["ssdp-ci"].default_count, 200)
        self.assertEqual(self.specs.profiles["ssdp-pcap"].feature_weights["pcap"], 10)

    def test_ssdp_supported_case_directions_match_feature_directions(self) -> None:
        for name in SSDP_FEATURES:
            feature = self.specs.features[name]
            supported = _supported_cases(feature)
            self.assertEqual(set(supported), set(feature.coverage_cases))

            for case_name, raw_case in supported.items():
                with self.subTest(feature=name, case=case_name):
                    directions = raw_case.get("directions")
                    self.assertIsInstance(directions, list)
                    assert isinstance(directions, list)
                    self.assertTrue(directions)
                    self.assertLessEqual(set(directions), set(feature.directions))
                    if name == "ssdp_live":
                        self.assertEqual(set(directions), {LIVE_EXCHANGE})
                    else:
                        self.assertEqual(set(directions), OFFLINE_DIRECTIONS)

    def test_ssdp_case_byte_policies_follow_malformed_contract(self) -> None:
        policy_index = case_byte_policy_index()

        for name in SSDP_FEATURES:
            feature = self.specs.features[name]
            for case_name, raw_case in _supported_cases(feature).items():
                with self.subTest(feature=name, case=case_name):
                    expected_policy = (
                        "structured_error" if feature.malformed else "strict_bytes"
                    )
                    self.assertEqual(raw_case.get("byte_policy"), expected_policy)
                    self.assertEqual(policy_index.get(case_name), expected_policy)

        self.assertEqual(
            policy_index["malformed-ssdp-missing-delimiter"],
            "structured_error",
        )
        self.assertEqual(policy_index["ssdp-raw-fallback"], "strict_bytes")
        self.assertEqual(policy_index["ssdp-live-ipv4-search-exchange"], "strict_bytes")


if __name__ == "__main__":
    unittest.main()
