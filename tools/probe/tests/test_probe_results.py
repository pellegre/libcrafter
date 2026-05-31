"""Unit coverage for probe result conversion from endpoint JSON."""

from __future__ import annotations

import unittest

from tools.probe.engine import cli
from tools.probe.engine import results as probe_results
from tools.probe.engine.cases import PROBE_CASE_BY_NAME


class ProbeResultsConversionTest(unittest.TestCase):
    def test_endpoint_response_converts_results_and_observed(self) -> None:
        response = {
            "results": [
                {
                    "case": "icmp-echo",
                    "sequence": 0,
                    "status": "passed",
                    "endpoint_role": "stimulus",
                    "passed": True,
                    "metadata": {"failure_reason": None},
                    "observed_response": {
                        "case": "icmp-echo",
                        "sequence": 0,
                        "endpoint_role": "stimulus",
                        "observed": True,
                        "response_type": "icmp",
                        "raw_hex": "deadbeef",
                        "decoded": {"icmp": {"type": 0}},
                        "metadata": {"peer": "10.77.0.20"},
                    },
                },
                {
                    "case": "tcp-syn-closed",
                    "sequence": 1,
                    "status": "failed",
                    "endpoint_role": "stimulus",
                    "passed": False,
                    "metadata": {"failure_reason": "wrong_flags"},
                },
            ]
        }

        conv_results, observed = probe_results.probe_results_from_endpoint_response(
            response
        )

        self.assertEqual(len(conv_results), 2)
        self.assertEqual(conv_results[0].case, "icmp-echo")
        self.assertTrue(conv_results[0].passed)
        self.assertEqual(conv_results[0].sequence, 0)
        self.assertIsNotNone(conv_results[0].observed_response)
        self.assertEqual(conv_results[1].case, "tcp-syn-closed")
        self.assertFalse(conv_results[1].passed)
        self.assertEqual(conv_results[1].status, "failed")

        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0].observed)
        self.assertEqual(observed[0].response_type, "icmp")
        self.assertEqual(observed[0].raw_hex, "deadbeef")
        self.assertEqual(observed[0].decoded["icmp"]["type"], 0)

    def test_endpoint_response_ignores_non_object_entries(self) -> None:
        response = {"results": ["not-an-object", 7, {"case": "dns-query", "sequence": 3}]}

        conv_results, observed = probe_results.probe_results_from_endpoint_response(
            response
        )

        self.assertEqual(len(conv_results), 1)
        self.assertEqual(conv_results[0].case, "dns-query")
        self.assertIsNone(conv_results[0].passed)
        self.assertEqual(observed, [])

    def test_missing_results_key_yields_empty(self) -> None:
        conv_results, observed = probe_results.probe_results_from_endpoint_response({})

        self.assertEqual(conv_results, [])
        self.assertEqual(observed, [])

    def test_failed_live_probe_results_uses_plan_sequence(self) -> None:
        cases = [
            PROBE_CASE_BY_NAME["icmp-echo"],
            PROBE_CASE_BY_NAME["tcp-syn-closed"],
        ]
        plans = [
            {"case": "icmp-echo", "sequence": 4},
            {"case": "tcp-syn-closed", "sequence": 7},
        ]

        failed, observed = probe_results.failed_live_probe_results(
            planned_cases=cases,
            probe_plans=plans,
            reason=probe_results.FAILURE_DECODE_FAILED,
            errors=["boom"],
        )

        self.assertEqual([result.sequence for result in failed], [4, 7])
        self.assertTrue(all(result.passed is False for result in failed))
        self.assertEqual(
            failed[0].metadata["failure_reason"],
            probe_results.FAILURE_DECODE_FAILED,
        )
        self.assertEqual(failed[0].metadata["errors"], ["boom"])
        self.assertEqual(observed, [])

    def test_failed_live_probe_results_defaults_sequence_to_index(self) -> None:
        cases = [PROBE_CASE_BY_NAME["icmp-echo"]]

        failed, _observed = probe_results.failed_live_probe_results(
            planned_cases=cases,
            probe_plans=[],
            reason=probe_results.FAILURE_DECODE_FAILED,
            errors=[],
        )

        self.assertEqual(failed[0].sequence, 0)

    def test_failed_counts_by_reason_tallies_only_failures(self) -> None:
        failed, _observed = probe_results.failed_live_probe_results(
            planned_cases=[
                PROBE_CASE_BY_NAME["icmp-echo"],
                PROBE_CASE_BY_NAME["tcp-syn-closed"],
            ],
            probe_plans=[
                {"case": "icmp-echo", "sequence": 0},
                {"case": "tcp-syn-closed", "sequence": 1},
            ],
            reason="timeout",
            errors=[],
        )
        passed_results, _ = probe_results.probe_results_from_endpoint_response(
            {
                "results": [
                    {
                        "case": "dns-query",
                        "sequence": 2,
                        "status": "passed",
                        "passed": True,
                    }
                ]
            }
        )

        counts = probe_results.failed_counts_by_reason([*failed, *passed_results])

        self.assertEqual(counts, {"timeout": 2})

    def test_cli_aliases_delegate_to_results_module(self) -> None:
        self.assertIs(
            cli._probe_results_from_endpoint_response,
            probe_results.probe_results_from_endpoint_response,
        )
        self.assertIs(
            cli._failed_live_probe_results,
            probe_results.failed_live_probe_results,
        )
        self.assertIs(
            cli._failed_counts_by_reason,
            probe_results.failed_counts_by_reason,
        )


if __name__ == "__main__":
    unittest.main()
