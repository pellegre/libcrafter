"""Focused coverage for the DNS behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.testing.probe_acceptance` harness.

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
from tools.probe.testing import probe_acceptance


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


def _dns_nodata_plan(*, seed: int = 1014, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-nodata"]),
        case=planning.PROBE_CASE_BY_NAME["dns-nodata"],
        sequence=sequence,
    )


def _dns_txt_answer_plan(*, seed: int = 1015, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-txt-answer"]),
        case=planning.PROBE_CASE_BY_NAME["dns-txt-answer"],
        sequence=sequence,
    )


def _dns_mx_answer_plan(*, seed: int = 1016, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-mx-answer"]),
        case=planning.PROBE_CASE_BY_NAME["dns-mx-answer"],
        sequence=sequence,
    )


def _dns_srv_answer_plan(*, seed: int = 1017, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-srv-answer"]),
        case=planning.PROBE_CASE_BY_NAME["dns-srv-answer"],
        sequence=sequence,
    )


def _dns_edns_opt_plan(*, seed: int = 1018, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-edns-opt"]),
        case=planning.PROBE_CASE_BY_NAME["dns-edns-opt"],
        sequence=sequence,
    )


def _dns_repeat_transaction_plan(*, seed: int = 1019, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["dns-repeat-transaction"]),
        case=planning.PROBE_CASE_BY_NAME["dns-repeat-transaction"],
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


class DnsNodataPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct NODATA (NOERROR, no answer) contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-nodata", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-nodata"],
            planning._dns_nodata_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_nodata_plan(), _dns_nodata_plan())

    def test_plan_carries_a_present_name_absent_type_contract(self) -> None:
        plan = _dns_nodata_plan()

        self.assertEqual(plan["case"], "dns-nodata")
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

        # The queried name EXISTS, but only under a different type (AAAA); the
        # A query therefore yields NODATA: rcode 0 (NOERROR), zero answers, no
        # answer data. This is behaviorally distinct from NXDOMAIN (rcode 3).
        self.assertEqual(plan["present_name"], plan["query_name"])
        self.assertEqual(plan["present_type"], "AAAA")
        self.assertEqual(plan["present_type_value"], 28)
        self.assertNotEqual(plan["present_type_value"], plan["query_type_value"])
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertEqual(plan["expected_answer_count"], 0)
        self.assertNotIn("expected_answer_data", plan)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_noerror_question_zero_answers(self) -> None:
        plan = _dns_nodata_plan()
        validation = plan["validation"]

        # Peer addresses and ports (response flows target -> stimulus).
        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"], plan["expected_reply_destination_ipv4"]
        )
        self.assertEqual(validation["source_port"], 53)
        self.assertEqual(validation["destination_port"], plan["source_port"])

        # Transaction id, QR flag, and rcode NOERROR (0) — NOT NXDOMAIN.
        self.assertEqual(validation["query_id"], plan["query_id"])
        self.assertTrue(validation["qr"])
        self.assertEqual(validation["response_code"], 0)

        # The original question is preserved (the present name, QTYPE A, class IN).
        question = validation["question"]
        self.assertEqual(question["name"], plan["query_name"])
        self.assertEqual(question["type"], "A")
        self.assertEqual(question["class"], "IN")

        # NODATA carries no answer: the answer count is exactly zero, and the
        # contract does not assert any answer record.
        self.assertEqual(validation["answer_count"], 0)
        self.assertNotIn("answer", validation)

    def test_target_service_marks_the_name_nodata(self) -> None:
        target_service = _dns_nodata_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "A")
        # The responder registers the name under its present type and answers
        # NOERROR/NODATA (rcode 0) for the queried type.
        self.assertTrue(target_service["nodata"])
        self.assertEqual(target_service["present_type"], "AAAA")
        self.assertEqual(target_service["present_type_value"], 28)
        self.assertEqual(target_service["expected_response_code"], 0)


class DnsNodataTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-nodata",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1014,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-nodata", planned)

            # The endpoint produced a result for the focused case and it built
            # the A query for the present name (a dry-run plan compiles the
            # outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-nodata"
            ]
            self.assertTrue(results, "endpoint emitted no dns-nodata result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DnsTxtAnswerPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct TXT query/answer contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-txt-answer", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-txt-answer"],
            planning._dns_txt_answer_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_txt_answer_plan(), _dns_txt_answer_plan())

    def test_plan_carries_a_txt_query_contract(self) -> None:
        plan = _dns_txt_answer_plan()

        self.assertEqual(plan["case"], "dns-txt-answer")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        # Query id, source port, target port 53, query name, and QTYPE TXT.
        self.assertIsInstance(plan["query_id"], int)
        self.assertTrue(1 <= plan["query_id"] <= 0xFFFF)
        self.assertIsInstance(plan["source_port"], int)
        self.assertNotEqual(plan["source_port"], 53)
        self.assertEqual(plan["destination_port"], 53)
        self.assertTrue(plan["query_name"].endswith("."))
        self.assertEqual(plan["query_type"], "TXT")
        self.assertEqual(plan["query_type_value"], 16)
        self.assertEqual(plan["query_class_value"], 1)

        # Expected answer: a TXT record carrying one or more character-strings.
        self.assertEqual(plan["expected_answer_type"], "TXT")
        self.assertEqual(plan["expected_answer_type_value"], 16)
        self.assertEqual(plan["expected_answer_name"], plan["query_name"])
        txt_strings = plan["expected_txt_strings"]
        self.assertIsInstance(txt_strings, list)
        self.assertGreaterEqual(len(txt_strings), 1)
        for value in txt_strings:
            self.assertIsInstance(value, str)
            # Each character-string fits in a single length octet on the wire.
            self.assertLessEqual(len(value.encode("utf-8")), 255)
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertIsInstance(plan["answer_ttl"], int)
        self.assertGreater(plan["answer_ttl"], 0)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_question_txt_answer_peer(self) -> None:
        plan = _dns_txt_answer_plan()
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
        self.assertEqual(question["type"], "TXT")
        self.assertEqual(question["class"], "IN")

        # Answer name/type/class, the full ordered TXT character-string list,
        # and the TTL.
        answer = validation["answer"]
        self.assertEqual(answer["name"], plan["query_name"])
        self.assertEqual(answer["type"], "TXT")
        self.assertEqual(answer["class"], "IN")
        self.assertEqual(answer["txt_strings"], plan["expected_txt_strings"])
        self.assertEqual(answer["ttl"], plan["answer_ttl"])

    def test_target_service_is_controlled_udp_dns_responder(self) -> None:
        target_service = _dns_txt_answer_plan()["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "TXT")
        self.assertEqual(
            target_service["txt_strings"],
            _dns_txt_answer_plan()["expected_txt_strings"],
        )


class DnsTxtAnswerTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-txt-answer",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1015,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-txt-answer", planned)

            # The endpoint produced a result for the focused case and it built
            # the TXT query (a dry-run plan compiles the outgoing stimulus
            # packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-txt-answer"
            ]
            self.assertTrue(results, "endpoint emitted no dns-txt-answer result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DnsMxAnswerPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct MX query/answer contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-mx-answer", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-mx-answer"],
            planning._dns_mx_answer_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_mx_answer_plan(), _dns_mx_answer_plan())

    def test_plan_carries_an_mx_query_contract(self) -> None:
        plan = _dns_mx_answer_plan()

        self.assertEqual(plan["case"], "dns-mx-answer")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        # Query id, source port, target port 53, query name, and QTYPE MX.
        self.assertIsInstance(plan["query_id"], int)
        self.assertTrue(1 <= plan["query_id"] <= 0xFFFF)
        self.assertIsInstance(plan["source_port"], int)
        self.assertNotEqual(plan["source_port"], 53)
        self.assertEqual(plan["destination_port"], 53)
        self.assertTrue(plan["query_name"].endswith("."))
        self.assertEqual(plan["query_type"], "MX")
        self.assertEqual(plan["query_type_value"], 15)
        self.assertEqual(plan["query_class_value"], 1)

        # Expected answer: an MX record carrying a preference + exchange name.
        self.assertEqual(plan["expected_answer_type"], "MX")
        self.assertEqual(plan["expected_answer_type_value"], 15)
        self.assertEqual(plan["expected_answer_name"], plan["query_name"])
        self.assertIsInstance(plan["expected_mx_preference"], int)
        self.assertTrue(1 <= plan["expected_mx_preference"] <= 0xFFFF)
        self.assertTrue(plan["expected_mx_exchange"].endswith("."))
        self.assertNotEqual(plan["expected_mx_exchange"], plan["query_name"])
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertIsInstance(plan["answer_ttl"], int)
        self.assertGreater(plan["answer_ttl"], 0)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_question_mx_answer_peer(self) -> None:
        plan = _dns_mx_answer_plan()
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
        self.assertEqual(question["type"], "MX")
        self.assertEqual(question["class"], "IN")

        # Answer name/type/class, the decoded preference and exchange name, and
        # the TTL.
        answer = validation["answer"]
        self.assertEqual(answer["name"], plan["query_name"])
        self.assertEqual(answer["type"], "MX")
        self.assertEqual(answer["class"], "IN")
        self.assertEqual(answer["preference"], plan["expected_mx_preference"])
        self.assertEqual(answer["exchange"], plan["expected_mx_exchange"])
        self.assertEqual(answer["ttl"], plan["answer_ttl"])

    def test_target_service_is_controlled_udp_dns_responder(self) -> None:
        plan = _dns_mx_answer_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "MX")
        self.assertEqual(target_service["mx_preference"], plan["expected_mx_preference"])
        self.assertEqual(target_service["mx_exchange"], plan["expected_mx_exchange"])


class DnsMxAnswerTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-mx-answer",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1016,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-mx-answer", planned)

            # The endpoint produced a result for the focused case and it built
            # the MX query (a dry-run plan compiles the outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-mx-answer"
            ]
            self.assertTrue(results, "endpoint emitted no dns-mx-answer result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DnsSrvAnswerPlanTest(unittest.TestCase):
    """The plan carries an RFC 2782-correct SRV query/answer contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-srv-answer", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-srv-answer"],
            planning._dns_srv_answer_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_srv_answer_plan(), _dns_srv_answer_plan())

    def test_plan_carries_an_srv_query_contract(self) -> None:
        plan = _dns_srv_answer_plan()

        self.assertEqual(plan["case"], "dns-srv-answer")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        # Query id, source port, target port 53, an SRV owner name, and QTYPE SRV.
        self.assertIsInstance(plan["query_id"], int)
        self.assertTrue(1 <= plan["query_id"] <= 0xFFFF)
        self.assertIsInstance(plan["source_port"], int)
        self.assertNotEqual(plan["source_port"], 53)
        self.assertEqual(plan["destination_port"], 53)
        self.assertTrue(plan["query_name"].endswith("."))
        # SRV owner names are _service._proto.name.
        self.assertTrue(plan["query_name"].startswith("_sip._tcp."))
        self.assertEqual(plan["query_type"], "SRV")
        self.assertEqual(plan["query_type_value"], 33)
        self.assertEqual(plan["query_class_value"], 1)

        # Expected answer: an SRV record carrying priority, weight, service port,
        # and a target host name.
        self.assertEqual(plan["expected_answer_type"], "SRV")
        self.assertEqual(plan["expected_answer_type_value"], 33)
        self.assertEqual(plan["expected_answer_name"], plan["query_name"])
        self.assertIsInstance(plan["expected_srv_priority"], int)
        self.assertTrue(1 <= plan["expected_srv_priority"] <= 0xFFFF)
        self.assertIsInstance(plan["expected_srv_weight"], int)
        self.assertTrue(0 <= plan["expected_srv_weight"] <= 0xFFFF)
        self.assertIsInstance(plan["expected_srv_port"], int)
        self.assertTrue(1 <= plan["expected_srv_port"] <= 0xFFFF)
        self.assertTrue(plan["expected_srv_target"].endswith("."))
        self.assertNotEqual(plan["expected_srv_target"], plan["query_name"])
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertIsInstance(plan["answer_ttl"], int)
        self.assertGreater(plan["answer_ttl"], 0)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_question_srv_answer_peer(self) -> None:
        plan = _dns_srv_answer_plan()
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
        self.assertEqual(question["type"], "SRV")
        self.assertEqual(question["class"], "IN")

        # Answer name/type/class, the decoded priority/weight/port/target, and
        # the TTL.
        answer = validation["answer"]
        self.assertEqual(answer["name"], plan["query_name"])
        self.assertEqual(answer["type"], "SRV")
        self.assertEqual(answer["class"], "IN")
        self.assertEqual(answer["priority"], plan["expected_srv_priority"])
        self.assertEqual(answer["weight"], plan["expected_srv_weight"])
        self.assertEqual(answer["port"], plan["expected_srv_port"])
        self.assertEqual(answer["target"], plan["expected_srv_target"])
        self.assertEqual(answer["ttl"], plan["answer_ttl"])

    def test_target_service_is_controlled_udp_dns_responder(self) -> None:
        plan = _dns_srv_answer_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "SRV")
        self.assertEqual(target_service["srv_priority"], plan["expected_srv_priority"])
        self.assertEqual(target_service["srv_weight"], plan["expected_srv_weight"])
        self.assertEqual(target_service["srv_port"], plan["expected_srv_port"])
        self.assertEqual(target_service["srv_target"], plan["expected_srv_target"])


class DnsSrvAnswerTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-srv-answer",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1017,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-srv-answer", planned)

            # The endpoint produced a result for the focused case and it built
            # the SRV query (a dry-run plan compiles the outgoing stimulus packet).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-srv-answer"
            ]
            self.assertTrue(results, "endpoint emitted no dns-srv-answer result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DnsEdnsOptPlanTest(unittest.TestCase):
    """The plan carries an RFC 6891 EDNS(0) OPT query/response contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-edns-opt", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-edns-opt"],
            planning._dns_edns_opt_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_dns_edns_opt_plan(), _dns_edns_opt_plan())

    def test_plan_carries_an_edns_query_contract(self) -> None:
        plan = _dns_edns_opt_plan()

        self.assertEqual(plan["case"], "dns-edns-opt")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        # Query id, source port, target port 53, a query name, and QTYPE A.
        self.assertIsInstance(plan["query_id"], int)
        self.assertTrue(1 <= plan["query_id"] <= 0xFFFF)
        self.assertIsInstance(plan["source_port"], int)
        self.assertNotEqual(plan["source_port"], 53)
        self.assertEqual(plan["destination_port"], 53)
        self.assertTrue(plan["query_name"].endswith("."))
        self.assertEqual(plan["query_type"], "A")
        self.assertEqual(plan["query_type_value"], 1)
        self.assertEqual(plan["query_class_value"], 1)

        # The stimulus advertises an EDNS(0) OPT record: a requestor UDP payload
        # size, a version, the DO flag, and an NSID option.
        self.assertIsInstance(plan["edns_udp_payload_size"], int)
        self.assertTrue(1 <= plan["edns_udp_payload_size"] <= 0xFFFF)
        self.assertEqual(plan["edns_version"], 0)
        self.assertTrue(plan["edns_do"])
        request_options = plan["edns_request_options"]
        self.assertEqual(len(request_options), 1)
        # NSID option code is 3 (RFC 5001); the data is opaque hex bytes.
        self.assertEqual(request_options[0]["code"], 3)
        bytes.fromhex(request_options[0]["data_hex"])

        # The response's expected OPT metadata: UDP payload size, version,
        # extended rcode, DO flag, and the ordered option list.
        self.assertIsInstance(plan["expected_edns_udp_payload_size"], int)
        self.assertTrue(1 <= plan["expected_edns_udp_payload_size"] <= 0xFFFF)
        self.assertEqual(plan["expected_edns_version"], 0)
        self.assertEqual(plan["expected_edns_extended_rcode"], 0)
        self.assertTrue(plan["expected_edns_do"])
        response_options = plan["expected_edns_options"]
        self.assertEqual(len(response_options), 1)
        self.assertEqual(response_options[0]["code"], 3)
        bytes.fromhex(response_options[0]["data_hex"])
        # The client and server NSID values are recognizably distinct.
        self.assertNotEqual(
            request_options[0]["data_hex"], response_options[0]["data_hex"]
        )
        self.assertEqual(plan["expected_response_code"], 0)
        self.assertIn("qr", plan["expected_response_flags"])

    def test_validation_contract_covers_id_qr_question_answer_and_opt(self) -> None:
        plan = _dns_edns_opt_plan()
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

        # The A answer is preserved alongside the OPT pseudo-record.
        answer = validation["answer"]
        self.assertEqual(answer["name"], plan["query_name"])
        self.assertEqual(answer["type"], "A")
        ipaddress.ip_address(answer["data"])

        # The additional-section OPT contract: UDP payload size, version,
        # extended rcode, DO flag, and the ordered option list.
        edns_opt = validation["edns_opt"]
        self.assertEqual(
            edns_opt["udp_payload_size"], plan["expected_edns_udp_payload_size"]
        )
        self.assertEqual(edns_opt["version"], plan["expected_edns_version"])
        self.assertEqual(
            edns_opt["extended_rcode"], plan["expected_edns_extended_rcode"]
        )
        self.assertEqual(edns_opt["do"], plan["expected_edns_do"])
        self.assertEqual(edns_opt["options"], plan["expected_edns_options"])

    def test_target_service_describes_the_response_opt(self) -> None:
        plan = _dns_edns_opt_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        self.assertEqual(target_service["port"], 53)
        self.assertEqual(target_service["query_type"], "A")
        edns = target_service["edns"]
        self.assertEqual(
            edns["udp_payload_size"], plan["expected_edns_udp_payload_size"]
        )
        self.assertEqual(edns["version"], plan["expected_edns_version"])
        self.assertEqual(edns["extended_rcode"], plan["expected_edns_extended_rcode"])
        self.assertEqual(edns["do"], plan["expected_edns_do"])
        self.assertEqual(edns["options"], plan["expected_edns_options"])


class DnsEdnsOptTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-edns-opt",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1018,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-edns-opt", planned)

            # The endpoint produced a result for the focused case and it built
            # the EDNS query (a dry-run plan compiles the outgoing stimulus
            # packet, which carries the OPT additional record).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-edns-opt"
            ]
            self.assertTrue(results, "endpoint emitted no dns-edns-opt result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus packet bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))


class DnsRepeatTransactionPlanTest(unittest.TestCase):
    """The plan carries two sends reusing one id over separate source ports."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("dns-repeat-transaction", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["dns-repeat-transaction"],
            planning._dns_repeat_transaction_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _dns_repeat_transaction_plan(), _dns_repeat_transaction_plan()
        )

    def test_plan_carries_two_sends_with_one_id_over_separate_ports(self) -> None:
        plan = _dns_repeat_transaction_plan()

        self.assertEqual(plan["case"], "dns-repeat-transaction")
        self.assertEqual(plan["stimulus"], "dns_query")
        self.assertEqual(plan["expected_response"], "dns_response")

        sends = plan["sends"]
        self.assertEqual(plan["send_count"], 2)
        self.assertEqual(len(sends), 2)

        first, second = sends
        # Repeated transaction id: both sends reuse one id and one query name.
        self.assertEqual(first["query_id"], second["query_id"])
        self.assertEqual(first["query_name"], second["query_name"])
        self.assertTrue(first["query_name"].endswith("."))
        # Over separate source ports: the two sends differ only in source port.
        self.assertNotEqual(first["source_port"], second["source_port"])
        self.assertEqual(first["destination_port"], 53)
        self.assertEqual(second["destination_port"], 53)
        # Each send carries its own deterministic A answer so a response can be
        # matched to its send by source port and not confused with the sibling.
        self.assertNotEqual(
            first["expected_answer_data"], second["expected_answer_data"]
        )
        for send in sends:
            self.assertEqual(send["query_type"], "A")
            self.assertEqual(send["query_type_value"], 1)
            ipaddress.ip_address(send["expected_answer_data"])
            self.assertEqual(send["expected_answer_count"], 1)
            self.assertEqual(send["expected_response_code"], 0)

    def test_each_send_validation_matches_its_own_id_port_and_answer(self) -> None:
        plan = _dns_repeat_transaction_plan()
        for send in plan["sends"]:
            validation = send["validation"]
            self.assertEqual(validation["query_id"], send["query_id"])
            self.assertTrue(validation["qr"])
            self.assertEqual(validation["response_code"], 0)
            # The response flows target -> stimulus on this send's source port.
            self.assertEqual(validation["source_port"], send["destination_port"])
            self.assertEqual(validation["destination_port"], send["source_port"])
            self.assertEqual(validation["source_ipv4"], send["expected_reply_source_ipv4"])
            self.assertEqual(
                validation["destination_ipv4"], send["expected_reply_destination_ipv4"]
            )
            self.assertEqual(validation["question"]["name"], send["query_name"])
            self.assertEqual(validation["answer"]["data"], send["expected_answer_data"])

    def test_target_service_describes_per_port_answers(self) -> None:
        plan = _dns_repeat_transaction_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-dns-responder")
        repeat = target_service["repeat_transaction"]
        self.assertEqual(repeat["query_id"], plan["query_id"])
        self.assertEqual(repeat["query_name"], plan["query_name"])
        repeat_sends = repeat["sends"]
        self.assertEqual(len(repeat_sends), 2)
        # The responder gets one answer per source port so each send's response
        # carries its own planned answer.
        ports = {entry["source_port"] for entry in repeat_sends}
        answers = {entry["answer_data"] for entry in repeat_sends}
        self.assertEqual(len(ports), 2)
        self.assertEqual(len(answers), 2)


class DnsRepeatTransactionTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "dns-repeat-transaction",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1019,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("dns-repeat-transaction", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "dns-repeat-transaction"
            ]
            self.assertTrue(
                results, "endpoint emitted no dns-repeat-transaction result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # The dry-run shows TWO planned sends and TWO expected responses.
                self.assertEqual(metadata.get("send_count"), 2)
                planned_sends = metadata.get("planned_sends", [])
                expected_responses = metadata.get("expected_responses", [])
                self.assertEqual(len(planned_sends), 2)
                self.assertEqual(len(expected_responses), 2)
                # Each planned send compiled its own stimulus packet bytes.
                for send in planned_sends:
                    self.assertTrue(send.get("sent_raw_hex"))
                # The two sends reuse one transaction id over separate ports.
                ids = {send.get("query_id") for send in planned_sends}
                ports = {send.get("source_port") for send in planned_sends}
                answers = {send.get("expected_answer_data") for send in planned_sends}
                self.assertEqual(len(ids), 1)
                self.assertEqual(len(ports), 2)
                self.assertEqual(len(answers), 2)


if __name__ == "__main__":
    unittest.main()
