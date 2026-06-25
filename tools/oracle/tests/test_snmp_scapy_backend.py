"""Scapy backend coverage for SNMP oracle materialization."""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.scapy import packets
from tools.oracle.engine.backends.scapy.protocols import SCAPY_REGISTRY
from tools.oracle.engine.backends.scapy.protocols import snmp as snmp_scapy
from tools.oracle.engine.generator import PacketGenerator, load_stack_grammar


def _scapy_available() -> bool:
    try:
        import scapy  # type: ignore[import-untyped]  # noqa: F401
        import scapy.all  # type: ignore[import-untyped]  # noqa: F401
    except Exception:
        return False
    return True


def _plan(case: str, feature: str):
    grammar = load_stack_grammar()
    support = grammar["layers"]["snmp"]["backend_support"]
    support["libcrafter"]["status"] = "partial"
    generator = PacketGenerator(
        seed=83,
        profile="snmp-smoke",
        backend="scapy",
        grammar=grammar,
    )
    return generator.generate(
        index=0,
        root="l3:ipv4",
        family="snmp",
        case=case,
        feature=feature,
        direction="reference_to_libcrafter",
    )


class SnmpScapyBackendTest(unittest.TestCase):
    def test_snmp_layer_is_registered_as_raw_ber_materializer(self) -> None:
        plugin = SCAPY_REGISTRY.require("snmp")
        self.assertEqual(plugin.scapy_class, "Raw")
        self.assertIn("varbinds", plugin.supported_fields)
        self.assertEqual(packets._scapy_layer_name("snmp"), "Raw")
        self.assertIn("snmp_basic", packets._SUPPORTED_FEATURES)
        self.assertIn("snmp_pdu_matrix", packets._SUPPORTED_FEATURES)
        self.assertIn("snmp_v3", packets._SUPPORTED_FEATURES)

    def test_v2c_get_request_materializes_exact_ber_payload(self) -> None:
        plan = _plan("snmp-basic-v2c-get-request", "snmp_basic")
        payload = snmp_scapy._snmp_message_bytes(plan.fields)
        self.assertEqual(
            payload.hex(),
            "302d020101040d646f632d636f6d6d756e697479a019020164020100020100300e300c06082b060102010101000500",
        )

    def test_v3_usm_report_materializes_synthetic_security_bytes(self) -> None:
        plan = _plan("snmp-v3-usm-security-parameters", "snmp_v3")
        payload = snmp_scapy._snmp_message_bytes(plan.fields)
        self.assertTrue(payload.startswith(bytes.fromhex("30")))
        self.assertIn(bytes.fromhex("020103"), payload)
        self.assertIn(b"doc-user", payload)
        self.assertIn(bytes.fromhex("80000000646f632d656e67696e65"), payload)

    @unittest.skipUnless(_scapy_available(), "scapy not importable")
    def test_scapy_packet_encode_embeds_snmp_ber_payload(self) -> None:
        plan = _plan("snmp-pdu-v2-trap", "snmp_pdu_matrix")
        payload = snmp_scapy._snmp_message_bytes(plan.fields)
        vector = packets.encode_packet_plan(plan)
        self.assertEqual(vector.metadata["scapy_stack"][-1], "Raw")
        self.assertTrue(vector.to_bytes().endswith(payload))


if __name__ == "__main__":
    unittest.main()
