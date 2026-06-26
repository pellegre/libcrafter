"""Backend-neutral QUIC oracle spec and generator coverage."""

from __future__ import annotations

import unittest

from tools.oracle.engine.generator import case_byte_policy_index, generate_plans
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import FeatureSpec, LayerSpec, load_oracle_specs


_SEED = 9000


def _quic_plan(case: str):
    plans = generate_plans(
        seed=_SEED,
        profile="quic-smoke",
        count=1,
        backend="scapy",
        root="l3:ipv4",
        family="quic",
        feature="quic_behavior",
        case=case,
        direction="reference_to_libcrafter",
    )
    assert len(plans) == 1
    return plans[0]


def _require_scapy_backend():
    try:
        from tools.oracle.engine.backends.scapy import normalize, packets
        from tools.oracle.engine.backends.scapy.bootstrap import import_scapy
    except Exception as exc:  # pragma: no cover - environment-dependent.
        raise unittest.SkipTest(f"Scapy backend unavailable: {exc}")
    try:
        import_scapy()
    except Exception as exc:  # pragma: no cover - environment-dependent.
        raise unittest.SkipTest(f"Scapy is not importable: {exc}")
    return packets, normalize


class QuicOracleSpecTest(unittest.TestCase):
    def setUp(self) -> None:
        self.specs = load_oracle_specs()

    def test_quic_layer_spec_declares_raw_payload_contract(self) -> None:
        layer = self.specs.layers.get("quic")
        self.assertIsInstance(layer, LayerSpec)
        assert layer is not None
        self.assertIn("udp", layer.parents)
        self.assertIn("raw_hex", {field.name for field in layer.fields})
        self.assertIn("quic-v1-initial", layer.coverage_cases)

    def test_quic_feature_and_profiles_are_registered(self) -> None:
        feature = self.specs.features.get("quic_behavior")
        self.assertIsInstance(feature, FeatureSpec)
        assert feature is not None
        self.assertIn("quic-v1-initial", feature.coverage_cases)
        self.assertIn("quic-smoke", self.specs.profiles)
        self.assertIn("quic-ci", self.specs.profiles)
        self.assertIn("quic", self.specs.families)

    def test_quic_sampler_self_registers(self) -> None:
        sampler = SAMPLER_REGISTRY.require("quic")
        self.assertEqual(sampler.supported_fields, frozenset({"raw_hex"}))


class QuicGeneratorTest(unittest.TestCase):
    def test_v1_initial_generation_pins_udp_4433_and_documentation_ipv4(self) -> None:
        plan = _quic_plan("quic-v1-initial")
        self.assertEqual(plan.stack, ["ipv4", "udp", "quic"])
        self.assertIn("quic", plan.feature_tags)
        self.assertEqual(plan.fields["udp"]["dst_port"], 4433)
        self.assertEqual(plan.fields["ipv4"]["src"], "192.0.2.10")
        self.assertEqual(plan.fields["ipv4"]["dst"], "198.51.100.20")
        self.assertEqual(
            plan.fields["quic"]["raw_hex"],
            "c000000001048394c8f001aa000301beef",
        )

    def test_version_negotiation_generation_uses_invariant_zero_version(self) -> None:
        plan = _quic_plan("quic-version-negotiation")
        raw = plan.fields["quic"]["raw_hex"]
        self.assertTrue(raw.startswith("c000000000"))
        self.assertIn("00000001", raw)
        self.assertIn("6b3343cf", raw)

    def test_coalesced_generation_concatenates_two_long_header_packets(self) -> None:
        plan = _quic_plan("quic-coalesced-initial-handshake")
        raw = plan.fields["quic"]["raw_hex"]
        self.assertGreater(len(bytes.fromhex(raw)), 30)
        self.assertIn("e000000001048394c8f001aa0302cafe", raw)

    def test_quic_profile_does_not_sample_contract_only_cases(self) -> None:
        plans = generate_plans(
            seed=_SEED,
            profile="quic-ci",
            count=30,
            backend="scapy",
            family="quic",
            direction="reference_to_libcrafter",
        )
        cases = {plan.case for plan in plans}
        self.assertTrue(cases)
        self.assertNotIn("quic-grease-bit", cases)
        self.assertNotIn("quic-short-header-raw", cases)
        self.assertNotIn("quic-malformed-exclusions", cases)
        self.assertTrue(all(plan.fields["udp"]["dst_port"] == 4433 for plan in plans))

    def test_quic_case_policies_keep_fixture_only_contracts_out_of_sampling(self) -> None:
        policies = case_byte_policy_index()
        self.assertEqual(policies["quic-v1-initial"], "strict_bytes")
        self.assertEqual(policies["quic-grease-bit"], "normalized")
        self.assertEqual(policies["quic-malformed-exclusions"], "structured_error")


class QuicScapyBackendTest(unittest.TestCase):
    def test_scapy_materializes_quic_as_udp_payload(self) -> None:
        packets, normalize = _require_scapy_backend()
        plan = _quic_plan("quic-v1-initial")
        vector = packets.encode_packet_plan(plan)
        raw = vector.to_bytes()
        self.assertEqual(raw[0] >> 4, 4)
        self.assertIn(plan.fields["quic"]["raw_hex"], vector.raw_hex)

        decoded = normalize.decode_bytes(
            raw,
            root="l3:ipv4",
            source_hex=vector.raw_hex,
            feature_tags=plan.feature_tags,
        )
        self.assertEqual(decoded.layers, ["ipv4", "udp", "quic"])
        self.assertEqual(decoded.fields["quic"]["raw_hex"], plan.fields["quic"]["raw_hex"])
        self.assertEqual(decoded.fields["quic"]["packet_count"], 1)

    def test_scapy_canonicalizes_coalesced_quic_packet_count(self) -> None:
        packets, normalize = _require_scapy_backend()
        plan = _quic_plan("quic-coalesced-initial-handshake")
        vector = packets.encode_packet_plan(plan)
        decoded = normalize.decode_bytes(
            vector.to_bytes(),
            root="l3:ipv4",
            source_hex=vector.raw_hex,
            feature_tags=plan.feature_tags,
        )
        self.assertEqual(decoded.layers, ["ipv4", "udp", "quic"])
        self.assertEqual(decoded.fields["quic"]["packet_count"], 2)


class QuicWiresharkBackendTest(unittest.TestCase):
    def test_wireshark_quic_plugin_self_registers(self) -> None:
        from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY

        plugin = WIRESHARK_REGISTRY.require("quic")
        self.assertIn("version", plugin.tshark_aliases)

    def test_wireshark_canonicalizes_udp_data_payload_as_quic(self) -> None:
        from tools.oracle.engine.backends.wireshark.protocols.quic import (
            canonicalize_quic_payload,
        )

        raw_hex = "c000000001048394c8f001aa000301beef"
        layers = ["ipv4", "udp", "payload"]
        fields = {
            "ipv4": {"protocol": 17},
            "udp": {"src_port": 49152, "dst_port": 4433},
            "payload": {"hex": raw_hex, "length": len(bytes.fromhex(raw_hex))},
        }
        canonicalize_quic_payload(
            layers,
            fields,
            {"data": {"data.data": raw_hex}},
        )
        self.assertEqual(layers, ["ipv4", "udp", "quic"])
        self.assertNotIn("payload", fields)
        self.assertEqual(fields["quic"]["raw_hex"], raw_hex)
        self.assertEqual(fields["quic"]["packet_count"], 1)
