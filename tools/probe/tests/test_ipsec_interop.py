"""Coverage for the cross-crypto IPSec behavioral parity (interop) check.

The interop check is the OPEN-direction counterpart of the oracle byte parity:
each implementation must consume the packet the other sealed. The structural
tests (case matrix, operation shape, the CLI dry-run wiring predicate) run with
no external tools. The end-to-end test actually seals/opens ESP/AH/SK both ways
with libcrafter and the oracle-owned reference crypto; it is skipped when
``cargo`` or ``uv`` are unavailable.
"""

from __future__ import annotations

import shutil
import unittest

from tools.oracle.engine import ipsec_interop
from tools.probe.engine import cli
from tools.probe.engine.model import ProbeCase


class InteropMatrixTest(unittest.TestCase):
    def test_matrix_covers_every_required_suite_and_protocol(self) -> None:
        cases = ipsec_interop.interop_cases()
        suites = {(case.protocol, case.suite) for case in cases}
        # ESP MUST/SHOULD suites, AH integrity, and the IKEv2 SK payload.
        self.assertIn(("esp", "aes-gcm"), suites)
        self.assertIn(("esp", "aes-cbc-hmac"), suites)
        self.assertIn(("esp", "chacha20-poly1305"), suites)
        self.assertIn(("ah", "hmac-sha2-256-128"), suites)
        self.assertIn(("sk", "aes-gcm"), suites)
        # Both ESP modes are exercised.
        modes = {case.mode for case in cases if case.protocol == "esp"}
        self.assertEqual(modes, {"transport", "tunnel"})

    def test_cases_use_documentation_addresses_only(self) -> None:
        for case in ipsec_interop.interop_cases():
            self.assertTrue(
                case.source.startswith(("192.0.2.", "2001:db8:"))
                and case.destination.startswith(("198.51.100.", "2001:db8:")),
                f"{case.name} must use documentation address space",
            )

    def test_operation_round_trips_to_open_with_wire_hex(self) -> None:
        case = ipsec_interop.interop_cases()[0]
        seal = case.to_operation(kind="seal")
        self.assertEqual(seal["kind"], "seal")
        self.assertNotIn("wire_hex", seal)
        opened = case.to_operation(kind="open", wire_hex="abcd")
        self.assertEqual(opened["wire_hex"], "abcd")

    def test_flip_last_byte_is_a_one_bit_change(self) -> None:
        flipped = ipsec_interop._flip_last_byte("00ff")
        self.assertEqual(flipped, "00fe")


class InteropWiringTest(unittest.TestCase):
    def _case(self, name: str) -> ProbeCase:
        return ProbeCase(
            name=name,
            description=name,
            stimulus="stimulus",
            expected_response="response",
        )

    def test_non_ipsec_profile_skips_interop(self) -> None:
        self.assertIsNone(
            cli._ipsec_interop_dry_run_metadata([self._case("icmp-echo")])
        )

    def test_ipsec_profile_triggers_interop_predicate(self) -> None:
        # The predicate fires when an IPSec exchange case is selected. The actual
        # run is covered by the end-to-end test; here only the gating is checked.
        cases = [self._case("esp-transport-echo")]
        self.assertTrue(
            any(case.name in cli._IPSEC_PROBE_CASES for case in cases)
        )


@unittest.skipUnless(
    shutil.which("cargo") and shutil.which("uv"),
    "cross-crypto interop needs cargo (libcrafter) and uv (reference crypto)",
)
class InteropEndToEndTest(unittest.TestCase):
    def test_all_suites_interoperate_both_directions_with_tamper(self) -> None:
        report = ipsec_interop.run_interop()
        self.assertEqual(report["check"], "ipsec-cross-crypto-interop")
        self.assertTrue(report["network_free"])
        self.assertTrue(
            report["passed"],
            f"cross-crypto interop did not pass: {report}",
        )
        self.assertEqual(report["passed_count"], report["case_count"])
        for case in report["cases"]:
            self.assertTrue(case["libcrafter_to_reference"], case["name"])
            self.assertTrue(case["reference_to_libcrafter"], case["name"])
            self.assertTrue(case["tamper_detected_by_reference"], case["name"])
            self.assertTrue(case["tamper_detected_by_libcrafter"], case["name"])


if __name__ == "__main__":
    unittest.main()
