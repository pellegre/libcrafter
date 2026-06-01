"""Focused coverage for the UDP behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.tests.probe_acceptance` harness.

``udp-echo-empty`` is the baseline UDP behavioral check: an IPv4/UDP datagram
with zero payload bytes sent to a controlled target-side UDP echo responder. The
stimulus endpoint decodes the echoed UDP response with libcrafter and validates
the peer addresses, ports, UDP length, checksum status, and empty payload.
"""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

from tools.probe.engine import planning
from tools.probe.engine import target_services
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
        "seed": 1040,
        "count": 1,
        "case_names": case_names or ["udp-echo-empty"],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _udp_echo_empty_plan(*, seed: int = 1040, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=planning.PROBE_CASE_BY_NAME["udp-echo-empty"],
        sequence=sequence,
    )


class UdpEchoEmptyPlanTest(unittest.TestCase):
    """The plan carries an empty UDP stimulus and echo-response contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("udp-echo-empty", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-echo-empty"],
            planning._udp_echo_empty_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_udp_echo_empty_plan(), _udp_echo_empty_plan())

    def test_plan_carries_empty_udp_datagram_stimulus(self) -> None:
        plan = _udp_echo_empty_plan()

        self.assertEqual(plan["case"], "udp-echo-empty")
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")
        ipaddress.IPv4Address(plan["source_ipv4"])
        ipaddress.IPv4Address(plan["destination_ipv4"])
        self.assertNotEqual(plan["source_ipv4"], plan["destination_ipv4"])

        self.assertIsInstance(plan["source_port"], int)
        self.assertIsInstance(plan["destination_port"], int)
        self.assertNotEqual(plan["source_port"], plan["destination_port"])
        self.assertEqual(plan["payload_hex"], "")
        self.assertEqual(plan["payload_length"], 0)
        self.assertEqual(plan["expected_payload_hex"], "")
        self.assertEqual(plan["expected_payload_length"], 0)
        self.assertEqual(plan["expected_udp_length"], 8)
        self.assertTrue(plan["expected_udp_checksum_present"])
        self.assertEqual(
            plan["expected_udp_checksum_statuses"],
            ["valid", "ipv4_no_checksum"],
        )

    def test_capture_filter_matches_echo_direction(self) -> None:
        plan = _udp_echo_empty_plan()

        self.assertIn("udp", plan["capture_filter"])
        self.assertIn(f"src host {plan['expected_reply_source_ipv4']}", plan["capture_filter"])
        self.assertIn(
            f"dst host {plan['expected_reply_destination_ipv4']}",
            plan["capture_filter"],
        )
        self.assertIn(f"src port {plan['destination_port']}", plan["capture_filter"])
        self.assertIn(f"dst port {plan['source_port']}", plan["capture_filter"])

    def test_target_service_is_controlled_udp_echo_responder(self) -> None:
        plan = _udp_echo_empty_plan()
        target_service = plan["target_service"]

        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["port"], plan["destination_port"])
        self.assertEqual(target_service["payload_hex"], "")
        self.assertEqual(target_service["payload_length"], 0)
        self.assertTrue(target_service["deterministic"])

    def test_validation_contract_covers_empty_echo_response(self) -> None:
        plan = _udp_echo_empty_plan()
        validation = plan["validation"]

        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"],
            plan["expected_reply_destination_ipv4"],
        )
        self.assertEqual(validation["source_port"], plan["destination_port"])
        self.assertEqual(validation["destination_port"], plan["source_port"])
        self.assertEqual(validation["payload_hex"], "")
        self.assertEqual(validation["payload_length"], 0)
        self.assertEqual(validation["udp_length"], 8)
        self.assertTrue(validation["checksum_present"])
        self.assertEqual(validation["checksum_statuses"], ["valid", "ipv4_no_checksum"])

    def test_case_is_in_the_udp_responder_target_service_group(self) -> None:
        self.assertIn("udp-echo-empty", target_services._UDP_RESPONDER_CASES)


class UdpEchoEmptyTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-echo-empty",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1040,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-echo-empty", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-echo-empty"
            ]
            self.assertTrue(results, "endpoint emitted no udp-echo-empty result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                # IPv4 header (20 bytes) + UDP header (8 bytes), no payload.
                self.assertEqual(len(sent), 28)
                self.assertEqual(sent[9], 17)
                self.assertEqual(int.from_bytes(sent[2:4], "big"), 28)
                self.assertEqual(int.from_bytes(sent[24:26], "big"), 8)
                self.assertNotEqual(int.from_bytes(sent[26:28], "big"), 0)

                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["length"], 8)
                self.assertEqual(decoded["udp"]["checksum_status"], "valid")
                self.assertEqual(decoded["payload_hex"], "")


if __name__ == "__main__":
    unittest.main()
