"""Wireshark parser-normalization coverage for SNMP oracle fields."""

from __future__ import annotations

import unittest

from tools.oracle.engine.backends.wireshark import normalize
from tools.oracle.engine.backends.wireshark.protocols import WIRESHARK_REGISTRY
from tools.oracle.engine.backends.wireshark.protocols import snmp as snmp_wireshark


class SnmpWiresharkBackendTest(unittest.TestCase):
    def test_snmp_layer_is_registered_and_routed(self) -> None:
        plugin = WIRESHARK_REGISTRY.require("snmp")
        self.assertIn("version", plugin.tshark_aliases)
        self.assertEqual(normalize._PROTOCOL_LAYER_ALIASES["snmp"], "snmp")

    def test_snmp_tshark_fields_normalize_to_oracle_names(self) -> None:
        fields = snmp_wireshark._normalize_snmp(
            {
                "snmp": {
                    "snmp.version": "1",
                    "snmp.community": "doc-community",
                    "snmp.pdu_type": "0xa7",
                    "snmp.request_id": "120",
                    "snmp.error_status": "0",
                    "snmp.error_index": "0",
                    "snmp.name": [
                        {"show": "1.3.6.1.2.1.1.3.0"},
                        {"show": "1.3.6.1.6.3.1.1.4.1.0"},
                    ],
                }
            }
        )
        self.assertEqual(fields["version"], "v2c")
        self.assertEqual(fields["community"], "doc-community")
        self.assertEqual(fields["pdu_tag"], "snmpv2_trap")
        self.assertEqual(fields["request_id"], 120)
        self.assertEqual(
            fields["varbinds"],
            [
                {"name": "1.3.6.1.2.1.1.3.0"},
                {"name": "1.3.6.1.6.3.1.1.4.1.0"},
            ],
        )


if __name__ == "__main__":
    unittest.main()
