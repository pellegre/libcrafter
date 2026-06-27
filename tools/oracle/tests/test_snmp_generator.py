"""SNMP generator-stage oracle planning coverage."""

from __future__ import annotations

from copy import deepcopy
import unittest

from tools.oracle.engine.generator import PacketGenerator, load_stack_grammar


def _snmp_generator() -> PacketGenerator:
    grammar = deepcopy(load_stack_grammar())
    support = grammar["layers"]["snmp"]["backend_support"]
    for backend in ("scapy", "libcrafter"):
        support[backend]["status"] = "supported"
        support[backend]["encode"] = True
        support[backend]["decode"] = True
    return PacketGenerator(
        seed=82,
        profile="snmp-smoke",
        backend="scapy",
        grammar=grammar,
    )


def _plan_for(case: str, feature: str):
    return _snmp_generator().generate(
        index=0,
        root="l3:ipv4",
        family="snmp",
        case=case,
        feature=feature,
        direction="backend_to_libcrafter",
    )


class SnmpGeneratorTest(unittest.TestCase):
    def test_smoke_profile_keeps_cases_on_snmp_features(self) -> None:
        generator = _snmp_generator()
        for index in range(12):
            plan = generator.generate(index=index, family="snmp")
            self.assertEqual(plan.stack[-3:], ["ipv4", "udp", "snmp"])
            self.assertIn("snmp", plan.fields)
            self.assertIsInstance(plan.metadata.get("feature"), str)
            self.assertTrue(str(plan.metadata["feature"]).startswith("snmp_"))
            self.assertNotIn("udp_options", plan.feature_tags)

    def test_v2_trap_plan_uses_trap_port_and_notification_varbinds(self) -> None:
        plan = _plan_for("snmp-pdu-v2-trap", "snmp_pdu_matrix")
        self.assertEqual(plan.fields["udp"]["dst_port"], 162)
        snmp = plan.fields["snmp"]
        self.assertEqual(snmp["version"], "v2c")
        self.assertEqual(snmp["pdu_tag"], "snmpv2_trap")
        self.assertEqual(snmp["message_length"], "derived")
        varbinds = snmp["varbinds"]
        self.assertIsInstance(varbinds, list)
        self.assertEqual(varbinds[0]["name"], "1.3.6.1.2.1.1.3.0")
        self.assertEqual(varbinds[1]["name"], "1.3.6.1.6.3.1.1.4.1.0")

    def test_v3_usm_plan_uses_synthetic_security_bytes(self) -> None:
        plan = _plan_for("snmp-v3-usm-security-parameters", "snmp_v3")
        self.assertEqual(plan.fields["udp"]["dst_port"], 161)
        snmp = plan.fields["snmp"]
        self.assertEqual(snmp["version"], "v3")
        self.assertEqual(snmp["msg_security_model"], "usm")
        security = snmp["msg_security_parameters"]
        self.assertIsInstance(security, dict)
        self.assertEqual(security["kind"], "usm")
        self.assertEqual(security["user_name"], "doc-user")
        self.assertEqual(
            security["engine_id"],
            {"hex": "80000000646f632d656e67696e65"},
        )
        self.assertEqual(snmp["scoped_data_kind"], "plaintext")


if __name__ == "__main__":
    unittest.main()
