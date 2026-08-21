"""Network-free IPSec cross-implementation validation."""

from __future__ import annotations

import shutil
import unittest

from tools.oracle.engine import ipsec_interop


class InteropMatrixTest(unittest.TestCase):
    def test_matrix_covers_required_protocols_and_modes(self) -> None:
        cases = ipsec_interop.interop_cases()
        suites = {(case.protocol, case.suite) for case in cases}
        self.assertIn(("esp", "aes-gcm"), suites)
        self.assertIn(("esp", "aes-cbc-hmac"), suites)
        self.assertIn(("esp", "chacha20-poly1305"), suites)
        self.assertIn(("ah", "hmac-sha2-256-128"), suites)
        self.assertIn(("sk", "aes-gcm"), suites)
        self.assertEqual(
            {case.mode for case in cases if case.protocol == "esp"},
            {"transport", "tunnel"},
        )


@unittest.skipUnless(
    shutil.which("cargo") and shutil.which("uv"),
    "cross-crypto interop needs cargo and uv",
)
class InteropEndToEndTest(unittest.TestCase):
    def test_all_suites_interoperate_both_directions(self) -> None:
        report = ipsec_interop.run_interop()
        self.assertTrue(report["network_free"])
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["passed_count"], report["case_count"])


if __name__ == "__main__":
    unittest.main()
