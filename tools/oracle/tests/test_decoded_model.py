"""Coverage for backend-neutral decoded model canonicalization."""

from __future__ import annotations

import unittest

from tools.oracle.engine.model import normalized_decoded_model


class DecodedModelCanonicalizationTest(unittest.TestCase):
    def test_ipv4_derived_display_fields_do_not_affect_comparison(self) -> None:
        model = normalized_decoded_model(
            {
                "layers": ["ipv4", "payload"],
                "fields": {
                    "ipv4": {
                        "src": "192.0.2.10",
                        "dst": "198.51.100.20",
                        "flags": "MF",
                        "checksum_status": "valid",
                        "dscp": "0",
                        "ecn": "Not-ECT",
                        "option_count": "0",
                        "options": "",
                        "tos": 0,
                    },
                    "payload": {
                        "hex": "AA",
                        "ascii": ".",
                    },
                },
                "root": "l3:ipv4",
            }
        )

        self.assertEqual(model["fields"]["ipv4"]["flags"], "mf")
        self.assertEqual(model["fields"]["ipv4"]["tos"], 0)
        self.assertEqual(model["fields"]["payload"], {"hex": "aa"})
        self.assertNotIn("checksum_status", model["fields"]["ipv4"])
        self.assertNotIn("dscp", model["fields"]["ipv4"])
        self.assertNotIn("ecn", model["fields"]["ipv4"])
        self.assertNotIn("option_count", model["fields"]["ipv4"])
        self.assertNotIn("options", model["fields"]["ipv4"])


if __name__ == "__main__":
    unittest.main()
