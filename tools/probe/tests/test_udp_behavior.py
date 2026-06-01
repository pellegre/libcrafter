"""Focused coverage for the UDP behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.tests.probe_acceptance` harness.

``udp-echo-empty`` is the zero-payload UDP behavioral check. ``udp-echo-short``
is the first service-response check with application bytes: a deterministic
short ASCII payload sent to a controlled target-side UDP echo responder.
``udp-echo-binary`` extends that echo shape with zero and high-bit payload bytes
so JSON artifacts and validation stay byte-oriented. ``udp-echo-large`` uses a
1200-byte deterministic payload that stays below the private-network MTU safety
limit. ``udp-source-port-reflection`` pins a deterministic high stimulus source
port and validates the echoed response is addressed back to that exact port. The
stimulus endpoint decodes the echoed UDP response with libcrafter and validates
the peer addresses, ports, UDP length, checksum status, and exact payload.
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


def _udp_echo_short_plan(*, seed: int = 1041, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-echo-short"]),
        case=planning.PROBE_CASE_BY_NAME["udp-echo-short"],
        sequence=sequence,
    )


def _udp_echo_binary_plan(*, seed: int = 1042, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-echo-binary"]),
        case=planning.PROBE_CASE_BY_NAME["udp-echo-binary"],
        sequence=sequence,
    )


def _udp_echo_large_plan(*, seed: int = 1043, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-echo-large"]),
        case=planning.PROBE_CASE_BY_NAME["udp-echo-large"],
        sequence=sequence,
    )


def _udp_source_port_reflection_plan(*, seed: int = 1044, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-source-port-reflection"]),
        case=planning.PROBE_CASE_BY_NAME["udp-source-port-reflection"],
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


class UdpEchoShortPlanTest(unittest.TestCase):
    """The plan carries a short ASCII UDP stimulus and exact echo contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("udp-echo-short", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-echo-short"],
            planning._udp_echo_short_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_udp_echo_short_plan(), _udp_echo_short_plan())

    def test_plan_carries_short_ascii_udp_datagram_stimulus(self) -> None:
        plan = _udp_echo_short_plan()
        payload = bytes.fromhex(plan["payload_hex"])

        self.assertEqual(plan["case"], "udp-echo-short")
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")
        ipaddress.IPv4Address(plan["source_ipv4"])
        ipaddress.IPv4Address(plan["destination_ipv4"])
        self.assertNotEqual(plan["source_ipv4"], plan["destination_ipv4"])

        self.assertIsInstance(plan["source_port"], int)
        self.assertIsInstance(plan["destination_port"], int)
        self.assertNotEqual(plan["source_port"], plan["destination_port"])
        self.assertGreater(len(payload), 0)
        self.assertLessEqual(len(payload), 32)
        payload_text = payload.decode("ascii")
        self.assertEqual(payload_text.encode("ascii"), payload)
        self.assertTrue(payload.startswith(b"udp-echo:"))
        self.assertEqual(plan["payload_length"], len(payload))
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))
        self.assertTrue(plan["expected_udp_checksum_present"])
        self.assertEqual(
            plan["expected_udp_checksum_statuses"],
            ["valid", "ipv4_no_checksum"],
        )

    def test_capture_filter_matches_echo_direction(self) -> None:
        plan = _udp_echo_short_plan()

        self.assertIn("udp", plan["capture_filter"])
        self.assertIn(f"src host {plan['expected_reply_source_ipv4']}", plan["capture_filter"])
        self.assertIn(
            f"dst host {plan['expected_reply_destination_ipv4']}",
            plan["capture_filter"],
        )
        self.assertIn(f"src port {plan['destination_port']}", plan["capture_filter"])
        self.assertIn(f"dst port {plan['source_port']}", plan["capture_filter"])

    def test_target_service_is_controlled_udp_echo_responder(self) -> None:
        plan = _udp_echo_short_plan()
        target_service = plan["target_service"]

        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["port"], plan["destination_port"])
        self.assertEqual(target_service["payload_hex"], plan["payload_hex"])
        self.assertEqual(target_service["payload_length"], plan["payload_length"])
        self.assertTrue(target_service["deterministic"])

    def test_validation_contract_covers_exact_short_echo_response(self) -> None:
        plan = _udp_echo_short_plan()
        validation = plan["validation"]

        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"],
            plan["expected_reply_destination_ipv4"],
        )
        self.assertEqual(validation["source_port"], plan["destination_port"])
        self.assertEqual(validation["destination_port"], plan["source_port"])
        self.assertEqual(validation["payload_hex"], plan["payload_hex"])
        self.assertEqual(validation["payload_length"], plan["payload_length"])
        self.assertEqual(validation["udp_length"], plan["expected_udp_length"])
        self.assertTrue(validation["checksum_present"])
        self.assertEqual(validation["checksum_statuses"], ["valid", "ipv4_no_checksum"])

    def test_case_is_in_the_udp_responder_target_service_group(self) -> None:
        self.assertIn("udp-echo-short", target_services._UDP_RESPONDER_CASES)


class UdpEchoShortTest(unittest.TestCase):
    """End-to-end focused acceptance for the short ASCII echo case."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-echo-short",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1041,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-echo-short", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-echo-short"
            ]
            self.assertTrue(results, "endpoint emitted no udp-echo-short result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))

                probe_plan = metadata["probe_plan"]
                payload = bytes.fromhex(probe_plan["payload_hex"])
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                # IPv4 header (20 bytes) + UDP header (8 bytes) + exact payload.
                self.assertEqual(len(sent), 28 + len(payload))
                self.assertEqual(sent[9], 17)
                self.assertEqual(int.from_bytes(sent[2:4], "big"), 28 + len(payload))
                self.assertEqual(int.from_bytes(sent[24:26], "big"), 8 + len(payload))
                self.assertEqual(sent[28:], payload)
                self.assertNotEqual(int.from_bytes(sent[26:28], "big"), 0)

                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["length"], 8 + len(payload))
                self.assertEqual(decoded["udp"]["checksum_status"], "valid")
                self.assertEqual(decoded["payload_hex"], probe_plan["payload_hex"])


class UdpEchoBinaryTest(unittest.TestCase):
    """Focused coverage for the deterministic binary UDP echo case."""

    def test_plan_carries_binary_payload_echo_contract(self) -> None:
        plan = _udp_echo_binary_plan()
        payload = bytes.fromhex(plan["payload_hex"])

        self.assertEqual(plan["case"], "udp-echo-binary")
        self.assertIn("udp-echo-binary", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-echo-binary"],
            planning._udp_echo_binary_probe_plan,
        )
        self.assertEqual(_udp_echo_binary_plan(), _udp_echo_binary_plan())
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")
        self.assertGreater(len(payload), 0)
        self.assertIn(0x00, payload)
        self.assertTrue(any(byte >= 0x80 for byte in payload))
        with self.assertRaises(UnicodeDecodeError):
            payload.decode("utf-8")

        self.assertEqual(plan["payload_length"], len(payload))
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))
        self.assertTrue(plan["expected_udp_checksum_present"])
        self.assertEqual(
            plan["expected_udp_checksum_statuses"],
            ["valid", "ipv4_no_checksum"],
        )

        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["payload_hex"], plan["payload_hex"])
        self.assertEqual(target_service["payload_length"], plan["payload_length"])
        self.assertIn("udp-echo-binary", target_services._UDP_RESPONDER_CASES)

        validation = plan["validation"]
        self.assertEqual(validation["payload_hex"], plan["payload_hex"])
        self.assertEqual(validation["payload_length"], plan["payload_length"])
        self.assertEqual(validation["udp_length"], plan["expected_udp_length"])
        self.assertEqual(validation["checksum_statuses"], ["valid", "ipv4_no_checksum"])

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-echo-binary",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1042,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-echo-binary", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-echo-binary"
            ]
            self.assertTrue(results, "endpoint emitted no udp-echo-binary result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))

                probe_plan = metadata["probe_plan"]
                payload = bytes.fromhex(probe_plan["payload_hex"])
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertIn(0x00, payload)
                self.assertTrue(any(byte >= 0x80 for byte in payload))
                # IPv4 header (20 bytes) + UDP header (8 bytes) + exact payload.
                self.assertEqual(len(sent), 28 + len(payload))
                self.assertEqual(sent[9], 17)
                self.assertEqual(int.from_bytes(sent[2:4], "big"), 28 + len(payload))
                self.assertEqual(int.from_bytes(sent[24:26], "big"), 8 + len(payload))
                self.assertEqual(sent[28:], payload)
                self.assertNotEqual(int.from_bytes(sent[26:28], "big"), 0)

                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["length"], 8 + len(payload))
                self.assertEqual(decoded["udp"]["checksum_status"], "valid")
                self.assertEqual(decoded["payload_hex"], probe_plan["payload_hex"])


class UdpEchoLargeTest(unittest.TestCase):
    """Focused coverage for the large non-fragmenting UDP echo case."""

    def test_plan_carries_large_non_fragmenting_payload_echo_contract(self) -> None:
        plan = _udp_echo_large_plan()
        payload = bytes.fromhex(plan["payload_hex"])

        self.assertEqual(plan["case"], "udp-echo-large")
        self.assertIn("udp-echo-large", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-echo-large"],
            planning._udp_echo_large_probe_plan,
        )
        self.assertEqual(_udp_echo_large_plan(), _udp_echo_large_plan())
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")

        self.assertEqual(len(payload), 1200)
        self.assertEqual(plan["payload_length"], len(payload))
        self.assertGreater(plan["payload_length"], 1000)
        self.assertLessEqual(
            plan["payload_length"],
            planning.UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH,
        )
        self.assertLess(
            plan["payload_length"] + plan["payload_mtu_header_overhead"],
            plan["payload_mtu_safety_limit"],
        )
        self.assertEqual(len(set(payload)), 256)
        self.assertEqual(plan["payload_size_policy"], "large_non_fragmenting")
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))
        self.assertTrue(plan["expected_udp_checksum_present"])
        self.assertEqual(
            plan["expected_udp_checksum_statuses"],
            ["valid", "ipv4_no_checksum"],
        )

        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["payload_hex"], plan["payload_hex"])
        self.assertEqual(target_service["payload_length"], plan["payload_length"])
        self.assertEqual(
            target_service["max_non_fragmenting_payload_length"],
            plan["max_non_fragmenting_payload_length"],
        )
        self.assertIn("udp-echo-large", target_services._UDP_RESPONDER_CASES)

        validation = plan["validation"]
        self.assertEqual(validation["payload_hex"], plan["payload_hex"])
        self.assertEqual(validation["payload_length"], plan["payload_length"])
        self.assertEqual(validation["udp_length"], plan["expected_udp_length"])
        self.assertEqual(validation["checksum_statuses"], ["valid", "ipv4_no_checksum"])

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-echo-large",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1043,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-echo-large", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-echo-large"
            ]
            self.assertTrue(results, "endpoint emitted no udp-echo-large result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))

                probe_plan = metadata["probe_plan"]
                payload = bytes.fromhex(probe_plan["payload_hex"])
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertEqual(len(payload), 1200)
                self.assertEqual(len(sent), 28 + len(payload))
                self.assertLess(len(sent), planning.UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT)
                self.assertEqual(sent[9], 17)
                self.assertEqual(int.from_bytes(sent[2:4], "big"), 28 + len(payload))
                self.assertEqual(int.from_bytes(sent[24:26], "big"), 8 + len(payload))
                self.assertEqual(sent[28:], payload)
                self.assertNotEqual(int.from_bytes(sent[26:28], "big"), 0)

                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["length"], 8 + len(payload))
                self.assertEqual(decoded["udp"]["checksum_status"], "valid")
                self.assertEqual(decoded["payload_hex"], probe_plan["payload_hex"])


class UdpSourcePortReflectionTest(unittest.TestCase):
    """Focused coverage for UDP source-port reflection validation."""

    def test_plan_carries_source_port_reflection_contract(self) -> None:
        plan = _udp_source_port_reflection_plan()
        payload = bytes.fromhex(plan["payload_hex"])

        self.assertEqual(plan["case"], "udp-source-port-reflection")
        self.assertIn("udp-source-port-reflection", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-source-port-reflection"],
            planning._udp_source_port_reflection_probe_plan,
        )
        self.assertEqual(_udp_source_port_reflection_plan(), _udp_source_port_reflection_plan())
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")

        ipaddress.IPv4Address(plan["source_ipv4"])
        ipaddress.IPv4Address(plan["destination_ipv4"])
        self.assertGreaterEqual(plan["source_port"], 60000)
        self.assertLess(plan["source_port"], 64000)
        self.assertNotEqual(plan["source_port"], plan["destination_port"])
        self.assertTrue(plan["source_port_reflection"])
        self.assertEqual(plan["source_port_policy"], "deterministic_high")

        self.assertTrue(payload.startswith(b"udp-source-port:"))
        self.assertEqual(plan["payload_length"], len(payload))
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))
        self.assertTrue(plan["expected_udp_checksum_present"])
        self.assertEqual(
            plan["expected_udp_checksum_statuses"],
            ["valid", "ipv4_no_checksum"],
        )

        self.assertIn(f"src port {plan['destination_port']}", plan["capture_filter"])
        self.assertIn(f"dst port {plan['source_port']}", plan["capture_filter"])

        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["port"], plan["destination_port"])
        self.assertEqual(target_service["payload_hex"], plan["payload_hex"])
        self.assertEqual(target_service["payload_length"], plan["payload_length"])
        self.assertTrue(target_service["source_port_reflection"])
        self.assertIn("udp-source-port-reflection", target_services._UDP_RESPONDER_CASES)

        validation = plan["validation"]
        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"],
            plan["expected_reply_destination_ipv4"],
        )
        self.assertEqual(validation["source_port"], plan["destination_port"])
        self.assertEqual(validation["destination_port"], plan["source_port"])
        self.assertEqual(validation["payload_hex"], plan["payload_hex"])
        self.assertEqual(validation["payload_length"], plan["payload_length"])
        self.assertEqual(validation["udp_length"], plan["expected_udp_length"])
        self.assertTrue(validation["source_port_reflection"])
        self.assertEqual(validation["checksum_statuses"], ["valid", "ipv4_no_checksum"])

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-source-port-reflection",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1044,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-source-port-reflection", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-source-port-reflection"
            ]
            self.assertTrue(results, "endpoint emitted no udp-source-port-reflection result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))

                probe_plan = metadata["probe_plan"]
                payload = bytes.fromhex(probe_plan["payload_hex"])
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertEqual(len(sent), 28 + len(payload))
                self.assertEqual(sent[9], 17)
                self.assertEqual(int.from_bytes(sent[2:4], "big"), 28 + len(payload))
                self.assertEqual(int.from_bytes(sent[20:22], "big"), probe_plan["source_port"])
                self.assertEqual(
                    int.from_bytes(sent[22:24], "big"),
                    probe_plan["destination_port"],
                )
                self.assertEqual(int.from_bytes(sent[24:26], "big"), 8 + len(payload))
                self.assertEqual(sent[28:], payload)

                self.assertIn(
                    f"dst port {probe_plan['source_port']}",
                    metadata["capture_filter"],
                )
                self.assertEqual(
                    metadata["target_service"]["port"],
                    probe_plan["destination_port"],
                )

                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["sport"], probe_plan["source_port"])
                self.assertEqual(decoded["udp"]["dport"], probe_plan["destination_port"])
                self.assertEqual(decoded["udp"]["length"], 8 + len(payload))
                self.assertEqual(decoded["udp"]["checksum_status"], "valid")
                self.assertEqual(decoded["payload_hex"], probe_plan["payload_hex"])


if __name__ == "__main__":
    unittest.main()
