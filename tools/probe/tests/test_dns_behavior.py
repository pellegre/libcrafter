"""Focused coverage for the DNS behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.tests.probe_acceptance` harness.

``dns-a-success`` is the baseline DNS behavioral check: an A query against the
controlled UDP DNS responder that receives and parses a matching IPv4 answer.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import planning
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.tests import probe_acceptance


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": "behavior",
        "seed": 1010,
        "count": 1,
        "case_names": ["dns-a-success"],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _dns_a_success_plan(*, seed: int = 1010, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=planning.PROBE_CASE_BY_NAME["dns-a-success"],
        sequence=sequence,
    )


class DnsASuccessPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct A query/answer contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-a-success", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-a-success"],
            planning._dns_a_success_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_a_success_plan(), _dns_a_success_plan())

    def test_plan_carries_a_query_contract(self) -> None:
        plan = _dns_a_success_plan()

        self.assertEqual(plan["case"], "dns-a-success")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        # Query id, source port, target port 53, query name, and QTYPE A.
        self.assertIsInstance(plan["query_id"], int)
        self.assertTrue(1 <= plan["query_id"] <= 0xFFFF)
        self.assertIsInstance(plan["source_port"], int)
        self.assertNotEqual(plan["source_port"], 53)
        self.assertEqual(plan["destination_port"], 53)
        self.assertTrue(plan["query_name"].endswith("."))
        self.assertEqual(plan["query_type"], "A")
        self.assertEqual(plan["query_type_value"], 1)
        self.assertEqual(plan["query_class_value"], 1)

        # Expected answer: IPv4 A record in documentation space, NOERROR, a TTL.
        self.assertEqual(plan["expected_answer_type"], "A")
        self.assertEqual(plan["expected_answer_type_value"], 1)
        self.assertEqual(plan["expected_answer_name"], plan["query_name"])
        self.assertTrue(plan["expected_answer_data"].startswith("203.0.113."))
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertIsInstance(plan["answer_ttl"], int)
        self.assertGreater(plan["answer_ttl"], 0)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_question_answer_peer(self) -> None:
        plan = _dns_a_success_plan()
        validation = plan["validation"]

        # Peer addresses and ports (response flows target -> stimulus).
        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"], plan["expected_reply_destination_ipv4"]
        )
        self.assertEqual(validation["source_port"], 53)
        self.assertEqual(validation["destination_port"], plan["source_port"])

        # Transaction id, QR flag, and rcode.
        self.assertEqual(validation["query_id"], plan["query_id"])
        self.assertTrue(validation["qr"])
        self.assertEqual(validation["response_code"], 0)

        # Question name/type/class.
        question = validation["question"]
        self.assertEqual(question["name"], plan["query_name"])
        self.assertEqual(question["type"], "A")
        self.assertEqual(question["class"], "IN")

        # Answer name/type/class/data/ttl.
        answer = validation["answer"]
        self.assertEqual(answer["name"], plan["query_name"])
        self.assertEqual(answer["type"], "A")
        self.assertEqual(answer["class"], "IN")
        self.assertEqual(answer["data"], plan["expected_answer_data"])
        self.assertEqual(answer["ttl"], plan["answer_ttl"])

    def test_target_service_is_controlled_udp_dns_responder(self) -> None:
        target_service = _dns_a_success_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "A")
        self.assertTrue(target_service["answer_data"].startswith("203.0.113."))


class DnsASuccessTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-a-success",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1010,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-a-success", planned)

            # The endpoint produced a result for the focused case and it built
            # the A query (a dry-run plan compiles the outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-a-success"
            ]
            self.assertTrue(results, "endpoint emitted no dns-a-success result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


if __name__ == "__main__":
    unittest.main()
