"""Backend-neutral contracts for the data-driven CoAP oracle specs."""

from __future__ import annotations

import unittest
from collections.abc import Mapping, Sequence

from tools.oracle.engine.directions import BACKEND_TO_LIBCRAFTER, LIBCRAFTER_TO_BACKEND
from tools.oracle.engine.generator import case_byte_policy_index
from tools.oracle.engine.spec_loader import FeatureSpec, LayerSpec, ProfileSpec, StackSpec, load_oracle_specs


COAP_FEATURES = {
    "coap_datagram",
    "coap_reliable",
    "coap_observe",
    "coap_blockwise",
    "coap_extended_token",
    "coap_link_format",
    "coap_oscore",
    "coap_malformed",
    "coap_pcap",
}
COAP_PROFILES = ("coap-smoke", "coap-ci", "coap-live-dry-run")
COAP_STACKS = {
    "ipv4_udp_coap": ("l3:ipv4", ("ipv4", "udp", "coap")),
    "ipv6_udp_coap": ("l3:ipv6", ("ipv6", "udp", "coap")),
    "ipv4_tcp_coap_reliable": ("l3:ipv4", ("ipv4", "tcp", "coap")),
    "ipv6_tcp_coap_reliable": ("l3:ipv6", ("ipv6", "tcp", "coap")),
}


def _objects(value: object) -> Sequence[Mapping[str, object]]:
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes))
    assert all(isinstance(item, Mapping) for item in value)
    return value  # type: ignore[return-value]


class CoapOracleSpecTest(unittest.TestCase):
    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def test_coap_layer_covers_datagram_reliable_and_protected_fields(self) -> None:
        layer = self.specs.layers.get("coap")
        self.assertIsInstance(layer, LayerSpec)
        assert layer is not None
        self.assertEqual(layer.parents, ("udp", "tcp"))
        fields = {field.name for field in layer.fields}
        self.assertTrue({"version", "message_type", "code", "message_id", "token", "token_length", "reliable_length", "options", "payload_marker", "payload", "signaling_options"}.issubset(fields))
        self.assertEqual(layer.raw["live_defaults"]["default_mode"], "dry_run")
        self.assertFalse(layer.raw["live_defaults"]["developer_host_raw_send"])
        self.assertEqual(layer.backend_support["scapy"].status, "planned")
        self.assertFalse(layer.backend_support["scapy"].encode)
        self.assertEqual(layer.backend_support["wireshark"].status, "planned")
        self.assertTrue(layer.backend_support["libcrafter"].encode)
        self.assertTrue(layer.backend_support["libcrafter"].decode)

    def test_focused_feature_specs_cover_every_required_contract(self) -> None:
        self.assertTrue(COAP_FEATURES.issubset(self.specs.features))
        cases = {case for name in COAP_FEATURES for case in self.specs.features[name].coverage_cases}
        required = {
            "coap-datagram-get", "coap-options-payload", "coap-reliable-csm",
            "coap-observe-notification", "coap-block2", "coap-qblock2",
            "coap-extended-token-extended16", "coap-link-format-canonical",
            "coap-oscore-request-vector", "coap-secure-port-raw",
            "malformed-coap-reliable", "coap-pcap-raw-ipv4",
        }
        self.assertTrue(required.issubset(cases))
        for name in COAP_FEATURES:
            self.assertIsInstance(self.specs.features[name], FeatureSpec)
            self.assertTrue(self.specs.features[name].backend_support)

    def test_case_directions_and_byte_policies_are_explicit(self) -> None:
        policy_index = case_byte_policy_index()
        for name in COAP_FEATURES:
            feature = self.specs.features[name]
            supported = _objects(feature.raw["supported_cases"])
            self.assertEqual({case["name"] for case in supported}, set(feature.coverage_cases))
            for case in supported:
                self.assertTrue(case["directions"])
                self.assertIn(case["byte_policy"], {"strict_bytes", "normalized", "structured_error"})
                self.assertEqual(policy_index[case["name"]], case["byte_policy"])
        self.assertEqual(policy_index["coap-link-format-canonical"], "normalized")
        self.assertEqual(policy_index["coap-observe-wrap"], "normalized")
        self.assertEqual(policy_index["malformed-coap-option"], "structured_error")
        self.assertEqual(policy_index["coap-oscore-request-vector"], "strict_bytes")

    def test_stack_fragment_registers_udp_tcp_ipv4_ipv6_and_constraints(self) -> None:
        family = self.specs.families["coap"]
        self.assertEqual(family.default_stack, ("ipv4", "udp", "coap"))
        for name, (root, layers) in COAP_STACKS.items():
            stack = self.specs.stacks.get(name)
            self.assertIsInstance(stack, StackSpec)
            assert stack is not None
            self.assertEqual((stack.root, stack.layers), (root, layers))
            self.assertTrue(stack.coverage_cases)
        self.assertEqual(self.specs.constraints["coap_udp_children"].children, ("coap",))
        self.assertEqual(self.specs.constraints["coap_tcp_children"].children, ("coap",))
        self.assertIn("tools/oracle/specs/stacks.d/coap.yaml", self.specs.source_paths)

    def test_profiles_are_offline_or_dry_run_with_live_weight_zero(self) -> None:
        for name in COAP_PROFILES:
            profile = self.specs.profiles.get(name)
            self.assertIsInstance(profile, ProfileSpec)
            assert profile is not None
            self.assertEqual([(weight.name, weight.weight) for weight in profile.family_weights], [("coap", 1)])
            self.assertEqual(profile.feature_weights["live"], 0)
        self.assertEqual(self.specs.profiles["coap-smoke"].default_count, 12)
        self.assertEqual(self.specs.profiles["coap-ci"].default_count, 240)
        self.assertIn("tools/oracle/specs/profiles.d/coap.yaml", self.specs.source_paths)

    def test_secure_and_reference_backend_gaps_are_explicit(self) -> None:
        feature = self.specs.features["coap_oscore"]
        unsupported = {item["name"]: item["reason"] for item in _objects(feature.raw["unsupported_cases"])}
        self.assertEqual(
            set(unsupported),
            {"coaps-dtls-decryption", "coaps-tls-stream-decryption", "scapy-native-oscore-transform", "wireshark-secret-assisted-oscore", "group-oscore-countersignature"},
        )
        self.assertTrue(all(isinstance(reason, str) and reason for reason in unsupported.values()))
        self.assertEqual(feature.backend_support["scapy"].status, "planned")
        self.assertEqual(feature.backend_support["wireshark"].status, "planned")
        self.assertFalse(feature.backend_support["scapy"].encode)
        self.assertFalse(feature.backend_support["wireshark"].decode)
        secure_raw = next(case for case in _objects(feature.raw["supported_cases"]) if case["name"] == "coap-secure-port-raw")
        self.assertEqual(set(secure_raw["directions"]), {BACKEND_TO_LIBCRAFTER})
        request_vector = next(case for case in _objects(feature.raw["supported_cases"]) if case["name"] == "coap-oscore-request-vector")
        self.assertEqual(set(request_vector["directions"]), {LIBCRAFTER_TO_BACKEND})


if __name__ == "__main__":
    unittest.main()
