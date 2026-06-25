"""Protocol-level oracle coverage for SNMP specs and backend plugins."""

from __future__ import annotations

import shutil
import unittest
from importlib import import_module

from tools.oracle.engine.backends.scapy import normalize as scapy_normalize
from tools.oracle.engine.backends.scapy import packets as scapy_packets
from tools.oracle.engine.backends.scapy.protocols import SCAPY_REGISTRY
from tools.oracle.engine.backends.scapy.protocols import snmp as snmp_scapy
from tools.oracle.engine.backends.wireshark import normalize as wireshark_normalize
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.generator import generate_plans
from tools.oracle.engine.protocols import SAMPLER_REGISTRY
from tools.oracle.engine.spec_loader import load_oracle_specs

oracle_cli = import_module("tools.oracle.engine.cli.main")


def _scapy_available() -> bool:
    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
        import scapy.all  # type: ignore[import-untyped]  # noqa: F401
    except Exception:
        return False
    return True


def _plan(case: str, feature: str):
    return generate_plans(
        seed=85,
        profile="snmp-smoke",
        count=1,
        backend="scapy",
        root="l3:ipv4",
        family="snmp",
        case=case,
        feature=feature,
        direction="reference_to_libcrafter",
    )[0]


class SnmpOracleSpecTest(unittest.TestCase):
    def test_specs_declare_snmp_layer_features_and_profiles(self) -> None:
        specs = load_oracle_specs()
        self.assertIn("snmp", specs.layers)
        for feature in ("snmp_basic", "snmp_pdu_matrix", "snmp_v3"):
            self.assertIn(feature, specs.features)
        for profile in ("snmp-smoke", "snmp-ci", "snmp-boundary", "snmp-live-dry-run"):
            self.assertIn(profile, specs.profiles)
        self.assertEqual(specs.layers["snmp"].backend_support["scapy"].status, "partial")
        self.assertEqual(specs.layers["snmp"].backend_support["wireshark"].status, "partial")

    def test_supported_fields_are_covered_by_registered_plugins(self) -> None:
        layer_fields = {field.name for field in load_oracle_specs().layers["snmp"].fields}
        sampler = SAMPLER_REGISTRY.require("snmp")
        self.assertLessEqual(sampler.supported_fields, layer_fields)
        self.assertIn("varbinds", sampler.supported_fields)
        self.assertIn("snmp", SCAPY_REGISTRY.names())
        self.assertIn("snmp", WIRESHARK_REGISTRY.names())

    def test_seeded_snmp_generation_stays_on_snmp_stacks(self) -> None:
        plans = generate_plans(seed=85, profile="snmp-smoke", count=8, backend="scapy")
        self.assertEqual(len(plans), 8)
        for plan in plans:
            self.assertEqual(plan.stack[-3:], ["ipv4", "udp", "snmp"])
            self.assertTrue(str(plan.metadata.get("feature")).startswith("snmp_"))
            self.assertIn(plan.fields["udp"]["dst_port"], {161, 162})

    def test_generator_shapes_v2_trap_and_v3_encrypted_cases(self) -> None:
        trap = _plan("snmp-pdu-v2-trap", "snmp_pdu_matrix")
        self.assertEqual(trap.fields["udp"]["dst_port"], 162)
        self.assertEqual(trap.fields["snmp"]["pdu_tag"], "snmpv2_trap")
        self.assertEqual(len(trap.fields["snmp"]["varbinds"]), 2)

        encrypted = _plan("snmp-v3-encrypted-scoped-data", "snmp_v3")
        self.assertEqual(encrypted.fields["udp"]["dst_port"], 161)
        self.assertEqual(encrypted.fields["snmp"]["version"], "v3")
        self.assertEqual(encrypted.fields["snmp"]["scoped_data_kind"], "encrypted_opaque")
        self.assertIn("encrypted_scoped_pdu", encrypted.fields["snmp"])


class SnmpOracleBackendTest(unittest.TestCase):
    def test_scapy_ber_materializer_matches_generated_plan(self) -> None:
        plan = _plan("snmp-basic-v2c-get-request", "snmp_basic")
        payload = snmp_scapy._snmp_message_bytes(plan.fields)
        self.assertEqual(payload[0], 0x30)
        self.assertIn(b"doc-community", payload)
        self.assertTrue(payload.endswith(bytes.fromhex("06082b060102010101000500")))

    def test_pcap_layer_canonicalization_normalizes_snmp(self) -> None:
        self.assertEqual(oracle_cli._canonical_pcap_layers(["Snmp"]), ["snmp"])

    @unittest.skipUnless(_scapy_available(), "scapy not importable")
    def test_scapy_encode_decode_surfaces_snmp_layer(self) -> None:
        plan = _plan("snmp-basic-v2c-get-request", "snmp_basic")
        vector = scapy_packets.encode_packet_plan(plan)
        decoded = scapy_normalize.decode_vector(vector)
        self.assertTrue(vector.to_bytes().endswith(snmp_scapy._snmp_message_bytes(plan.fields)))
        self.assertIn("snmp", decoded.layers)
        self.assertEqual(decoded.fields["snmp"]["version"], "v2c")
        self.assertEqual(decoded.fields["snmp"]["community"], "doc-community")

    @unittest.skipUnless(_scapy_available(), "scapy not importable")
    def test_scapy_decode_canonicalizes_snmp_v3_raw_payload(self) -> None:
        plan = _plan("snmp-v3-encrypted-scoped-data", "snmp_v3")
        vector = scapy_packets.encode_packet_plan(plan)
        decoded = scapy_normalize.decode_vector(vector)
        self.assertIn("snmp", decoded.layers)
        self.assertEqual(decoded.fields["snmp"]["version"], "v3")
        self.assertNotIn("payload", decoded.fields)

    @unittest.skipUnless(_scapy_available(), "scapy not importable")
    def test_scapy_decode_canonicalizes_snmp_v3_raw_payload_without_feature_tags(self) -> None:
        plan = _plan("snmp-v3-encrypted-scoped-data", "snmp_v3")
        vector = scapy_packets.encode_packet_plan(plan)
        decoded = scapy_normalize.decode_bytes(
            vector.to_bytes(),
            root=vector.root or "l3:ipv4",
            source_hex=vector.raw_hex,
        )
        self.assertIn("snmp", decoded.layers)
        self.assertEqual(decoded.fields["snmp"]["version"], "v3")
        self.assertNotIn("payload", decoded.fields)

    @unittest.skipUnless(_scapy_available(), "scapy not importable")
    def test_scapy_decode_canonicalizes_unknown_pdu_raw_payload(self) -> None:
        plan = _plan("snmp-pdu-unknown-preserve", "snmp_pdu_matrix")
        vector = scapy_packets.encode_packet_plan(plan)
        decoded = scapy_normalize.decode_vector(vector)
        self.assertIn("snmp", decoded.layers)
        self.assertEqual(decoded.fields["snmp"]["version"], "v2c")
        self.assertEqual(decoded.fields["snmp"]["community"], "doc-community")
        self.assertNotIn("payload", decoded.fields)

    @unittest.skipUnless(
        _scapy_available() and shutil.which("tshark") is not None,
        "scapy or tshark not available",
    )
    def test_wireshark_decode_surfaces_snmp_when_tshark_is_available(self) -> None:
        plan = _plan("snmp-pdu-v2-trap", "snmp_pdu_matrix")
        vector = scapy_packets.encode_packet_plan(plan)
        decoded = wireshark_normalize.decode_bytes(
            vector.to_bytes(),
            root=vector.root or "l3:ipv4",
            source_hex=vector.raw_hex,
            feature_tags=vector.plan.feature_tags,
        )
        self.assertIn("snmp", decoded.layers)
        self.assertIn("snmp", decoded.fields)


if __name__ == "__main__":
    unittest.main()
