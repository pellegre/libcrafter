"""Focused-acceptance harness coverage.

Drives one focused probe case end to end through the probe planner dry-run and
the Rust ``stimulus_endpoint`` dry-run and asserts the stable request/response
shape. The harness lives in :mod:`tools.probe.testing.probe_acceptance`; this
module is the parameterizable unit-test wrapper a per-case step reuses by
pointing :data:`HARNESS_CASE` (or the ``PROBE_HARNESS_CASE`` env override) at
the case under test.

The harness skips rather than fails when the ``uv``/``cargo`` toolchains it
needs to drive both halves of the stack are unavailable, so offline-only
environments do not report a spurious failure.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from tools.probe.testing import probe_acceptance


# The focused case this wrapper drives. ``dns-a-success`` is the first DNS
# behavioral case; per-case steps re-run this wrapper against their own case by
# overriding ``PROBE_HARNESS_CASE`` or importing
# :func:`tools.probe.testing.probe_acceptance.assert_focused_case` directly.
HARNESS_CASE = os.environ.get("PROBE_HARNESS_CASE", "dns-a-success")


class ProbeAcceptanceHarnessTest(unittest.TestCase):
    def test_harness_helpers_report_toolchain_availability(self) -> None:
        # These never raise and gate the live end-to-end test below; assert they
        # return a bool so the harness contract stays inspectable offline.
        self.assertIsInstance(probe_acceptance.cargo_available(), bool)
        self.assertIsInstance(probe_acceptance.probe_run_available(), bool)
        self.assertTrue(probe_acceptance.PROBE_RUN.exists())

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                HARNESS_CASE,
                out_dir=Path(temp_dir) / "harness",
            )

            # Sanity-check the artifacts the harness located/produced exist on
            # disk (still inside the temp directory) and the report agrees with
            # the case under test.
            self.assertTrue(outcome.report_path.is_file())
            self.assertTrue(outcome.request_path.is_file())
            self.assertTrue(outcome.response_path.is_file())
            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn(HARNESS_CASE, planned)


if __name__ == "__main__":
    unittest.main()
