"""Focused coverage for the DNS behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.tests.probe_acceptance` harness.

``dns-a-success`` is the baseline DNS behavioral check: an A query against the
controlled UDP DNS responder that receives and parses a matching IPv4 answer.
``dns-aaaa-success`` is the IPv6 counterpart: an AAAA query whose response
carries a matching IPv6 (``2001:db8::/32``) address answer over the same
IPv4 lab transport.
"""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import planning
from tools.probe.engine.model import ProbeRunRequest
from tools.probe.tests import probe_acceptance


def _request(
    *,
    case_names: list[str] | None = None,
    **overrides: object,
) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": "behavior",
        "seed": 1010,
        "count": 1,
        "case_names": case_names or ["dns-a-success"],
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


def _dns_aaaa_success_plan(*, seed: int = 1011, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-aaaa-success"]),
        case=planning.PROBE_CASE_BY_NAME["dns-aaaa-success"],
        sequence=sequence,
    )


def _dns_cname_chain_plan(*, seed: int = 1012, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-cname-chain"]),
        case=planning.PROBE_CASE_BY_NAME["dns-cname-chain"],
        sequence=sequence,
    )


def _dns_nxdomain_plan(*, seed: int = 1013, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-nxdomain"]),
        case=planning.PROBE_CASE_BY_NAME["dns-nxdomain"],
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


class DnsAaaaSuccessPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct AAAA query/answer contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-aaaa-success", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-aaaa-success"],
            planning._dns_aaaa_success_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_aaaa_success_plan(), _dns_aaaa_success_plan())

    def test_plan_carries_an_aaaa_query_contract(self) -> None:
        plan = _dns_aaaa_success_plan()

        self.assertEqual(plan["case"], "dns-aaaa-success")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        # Query id, source port, target port 53, query name, and QTYPE AAAA.
        self.assertIsInstance(plan["query_id"], int)
        self.assertTrue(1 <= plan["query_id"] <= 0xFFFF)
        self.assertIsInstance(plan["source_port"], int)
        self.assertNotEqual(plan["source_port"], 53)
        self.assertEqual(plan["destination_port"], 53)
        self.assertTrue(plan["query_name"].endswith("."))
        self.assertEqual(plan["query_type"], "AAAA")
        self.assertEqual(plan["query_type_value"], 28)
        self.assertEqual(plan["query_class_value"], 1)

        # Expected answer: an IPv6 AAAA record in documentation space, NOERROR,
        # a TTL. The lab transport stays IPv4 (endpoint addresses are IPv4).
        self.assertEqual(plan["expected_answer_type"], "AAAA")
        self.assertEqual(plan["expected_answer_type_value"], 28)
        self.assertEqual(plan["expected_answer_name"], plan["query_name"])
        answer = ipaddress.IPv6Address(plan["expected_answer_data"])
        self.assertIn(answer, ipaddress.ip_network("2001:db8::/32"))
        self.assertTrue(ipaddress.ip_address(plan["source_ipv4"]).version == 4)
        self.assertTrue(ipaddress.ip_address(plan["destination_ipv4"]).version == 4)
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertIsInstance(plan["answer_ttl"], int)
        self.assertGreater(plan["answer_ttl"], 0)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_question_answer_peer(self) -> None:
        plan = _dns_aaaa_success_plan()
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
        self.assertEqual(question["type"], "AAAA")
        self.assertEqual(question["class"], "IN")

        # Answer name/type/class/data/ttl.
        answer = validation["answer"]
        self.assertEqual(answer["name"], plan["query_name"])
        self.assertEqual(answer["type"], "AAAA")
        self.assertEqual(answer["class"], "IN")
        self.assertEqual(answer["data"], plan["expected_answer_data"])
        self.assertEqual(answer["ttl"], plan["answer_ttl"])

    def test_target_service_is_controlled_udp_dns_responder(self) -> None:
        target_service = _dns_aaaa_success_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "AAAA")
        answer = ipaddress.IPv6Address(target_service["answer_data"])
        self.assertIn(answer, ipaddress.ip_network("2001:db8::/32"))


class DnsAaaaSuccessTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-aaaa-success",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1011,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-aaaa-success", planned)

            # The endpoint produced a result for the focused case and it built
            # the AAAA query (a dry-run plan compiles the outgoing stimulus
            # packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-aaaa-success"
            ]
            self.assertTrue(results, "endpoint emitted no dns-aaaa-success result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DnsCnameChainPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct CNAME-to-A chain contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-cname-chain", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-cname-chain"],
            planning._dns_cname_chain_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_cname_chain_plan(), _dns_cname_chain_plan())

    def test_plan_carries_original_canonical_terminal_and_count(self) -> None:
        plan = _dns_cname_chain_plan()

        self.assertEqual(plan["case"], "dns-cname-chain")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        # The query is an A query for the original name on port 53.
        self.assertEqual(plan["destination_port"], 53)
        self.assertEqual(plan["query_type"], "A")
        self.assertEqual(plan["query_type_value"], 1)
        self.assertTrue(plan["query_name"].endswith("."))

        # Original name, canonical name, terminal IPv4, and answer count.
        self.assertEqual(plan["original_name"], plan["query_name"])
        self.assertTrue(plan["canonical_name"].endswith("."))
        self.assertNotEqual(plan["canonical_name"], plan["original_name"])
        self.assertTrue(plan["terminal_ipv4"].startswith("203.0.113."))
        # Documentation-space IPv4 terminal answer.
        terminal = ipaddress.IPv4Address(plan["terminal_ipv4"])
        self.assertIn(terminal, ipaddress.ip_network("203.0.113.0/24"))
        self.assertEqual(plan["expected_answer_count"], 2)

        # The terminal A answer is owned by the canonical name.
        self.assertEqual(plan["expected_answer_name"], plan["canonical_name"])
        self.assertEqual(plan["expected_answer_type"], "A")
        self.assertEqual(plan["expected_answer_data"], plan["terminal_ipv4"])
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertIn("qr", plan["expected_response_flags"])

        # The CNAME answer is owned by the original name and points at canonical.
        cname = plan["expected_cname_answer"]
        self.assertEqual(cname["name"], plan["original_name"])
        self.assertEqual(cname["type"], "CNAME")
        self.assertEqual(cname["type_value"], 5)
        self.assertEqual(cname["data"], plan["canonical_name"])

    def test_validation_contract_covers_chain_and_preserved_question(self) -> None:
        plan = _dns_cname_chain_plan()
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

        # The ORIGINAL question is preserved: the queried name, QTYPE A, class IN.
        question = validation["question"]
        self.assertEqual(question["name"], plan["original_name"])
        self.assertEqual(question["type"], "A")
        self.assertEqual(question["class"], "IN")

        # Both answers are part of the contract: a CNAME and the terminal A, and
        # the answer count is exactly two.
        self.assertEqual(validation["answer_count"], 2)
        cname_answer = validation["cname_answer"]
        self.assertEqual(cname_answer["name"], plan["original_name"])
        self.assertEqual(cname_answer["type"], "CNAME")
        self.assertEqual(cname_answer["data"], plan["canonical_name"])
        answer = validation["answer"]
        self.assertEqual(answer["name"], plan["canonical_name"])
        self.assertEqual(answer["type"], "A")
        self.assertEqual(answer["data"], plan["terminal_ipv4"])

    def test_target_service_describes_cname_chain(self) -> None:
        target_service = _dns_cname_chain_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "A")
        chain = target_service["cname_chain"]
        self.assertTrue(chain["canonical_name"].endswith("."))
        self.assertIsInstance(chain["cname_ttl"], int)
        self.assertIsInstance(chain["address_ttl"], int)


class DnsCnameChainTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-cname-chain",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1012,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-cname-chain", planned)

            # The endpoint produced a result for the focused case and it built
            # the A query (a dry-run plan compiles the outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-cname-chain"
            ]
            self.assertTrue(results, "endpoint emitted no dns-cname-chain result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DnsNxdomainPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct NXDOMAIN (negative response) contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-nxdomain", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-nxdomain"],
            planning._dns_nxdomain_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_nxdomain_plan(), _dns_nxdomain_plan())

    def test_plan_carries_an_absent_name_query_contract(self) -> None:
        plan = _dns_nxdomain_plan()

        self.assertEqual(plan["case"], "dns-nxdomain")
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

        # The queried name is the planned absent name; the response is a negative
        # answer: rcode 3 (NXDOMAIN), zero answers, no answer data.
        self.assertEqual(plan["absent_name"], plan["query_name"])
        self.assertEqual(plan["expected_response_code"], 3)
        self.assertEqual(plan["expected_answer_count"], 0)
        self.assertNotIn("expected_answer_data", plan)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_rcode_question_zero_answers(self) -> None:
        plan = _dns_nxdomain_plan()
        validation = plan["validation"]

        # Peer addresses and ports (response flows target -> stimulus).
        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"], plan["expected_reply_destination_ipv4"]
        )
        self.assertEqual(validation["source_port"], 53)
        self.assertEqual(validation["destination_port"], plan["source_port"])

        # Transaction id, QR flag, and rcode NXDOMAIN (3).
        self.assertEqual(validation["query_id"], plan["query_id"])
        self.assertTrue(validation["qr"])
        self.assertEqual(validation["response_code"], 3)

        # The original question is preserved (the absent name, QTYPE A, class IN).
        question = validation["question"]
        self.assertEqual(question["name"], plan["query_name"])
        self.assertEqual(question["type"], "A")
        self.assertEqual(question["class"], "IN")

        # Negative responses carry no answer: the answer count is exactly zero,
        # and the contract does not assert any answer record.
        self.assertEqual(validation["answer_count"], 0)
        self.assertNotIn("answer", validation)

    def test_target_service_marks_the_name_absent(self) -> None:
        target_service = _dns_nxdomain_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "A")
        # The responder leaves the name unregistered and answers NXDOMAIN.
        self.assertTrue(target_service["absent"])
        self.assertEqual(target_service["expected_response_code"], 3)


class DnsNxdomainTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-nxdomain",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1013,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-nxdomain", planned)

            # The endpoint produced a result for the focused case and it built
            # the A query for the absent name (a dry-run plan compiles the
            # outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-nxdomain"
            ]
            self.assertTrue(results, "endpoint emitted no dns-nxdomain result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


if __name__ == "__main__":
    unittest.main()
