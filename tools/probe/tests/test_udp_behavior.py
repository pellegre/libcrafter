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
port and validates the echoed response is addressed back to that exact port.
``udp-multi-shot-order`` sends three ordered payload markers through the same
echo responder. ``udp-closed-port-icmp`` sends a UDP datagram to an unbound
target port and validates the decoded ICMP destination-unreachable /
port-unreachable response plus its embedded original IPv4/UDP prefix.
``udp-zero-checksum-ipv4`` sends a controlled echo stimulus whose IPv4 UDP
checksum is explicitly overridden to zero, then keeps the ordinary payload and
peer tuple validation for responses accepted by the provider kernel.
``udp-options-surplus-echo`` sends the same controlled echo payload shape with
deterministic UDP surplus/options after the UDP payload length and records the
sent raw bytes, UDP length, surplus length, and option summary.
``udp-length-boundary-echo`` sends a deterministic payload one byte below the
configured no-fragment safety limit so the raw UDP length field and decoded
response contract are checked near the boundary. The stimulus endpoint decodes
each response with libcrafter and validates the peer addresses, ports, UDP
length, checksum status, exact payload, or ICMP embedded prefix depending on the
case.
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


def _udp_multi_shot_order_plan(*, seed: int = 1045, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-multi-shot-order"]),
        case=planning.PROBE_CASE_BY_NAME["udp-multi-shot-order"],
        sequence=sequence,
    )


def _udp_closed_port_icmp_plan(*, seed: int = 1046, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-closed-port-icmp"]),
        case=planning.PROBE_CASE_BY_NAME["udp-closed-port-icmp"],
        sequence=sequence,
    )


def _udp_zero_checksum_ipv4_plan(*, seed: int = 1047, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-zero-checksum-ipv4"]),
        case=planning.PROBE_CASE_BY_NAME["udp-zero-checksum-ipv4"],
        sequence=sequence,
    )


def _udp_options_surplus_echo_plan(*, seed: int = 1048, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-options-surplus-echo"]),
        case=planning.PROBE_CASE_BY_NAME["udp-options-surplus-echo"],
        sequence=sequence,
    )


def _udp_length_boundary_echo_plan(*, seed: int = 1049, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["udp-length-boundary-echo"]),
        case=planning.PROBE_CASE_BY_NAME["udp-length-boundary-echo"],
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


class UdpMultiShotOrderTest(unittest.TestCase):
    """Focused coverage for ordered multi-shot UDP echo validation."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("udp-multi-shot-order", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-multi-shot-order"],
            planning._udp_multi_shot_order_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_udp_multi_shot_order_plan(), _udp_multi_shot_order_plan())

    def test_plan_carries_three_ordered_payload_markers(self) -> None:
        plan = _udp_multi_shot_order_plan()

        self.assertEqual(plan["case"], "udp-multi-shot-order")
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")
        self.assertTrue(plan["multi_shot_order"])
        self.assertEqual(plan["send_count"], 3)

        sends = plan["udp_sends"]
        self.assertEqual(len(sends), 3)
        self.assertEqual(plan["sequence_markers"], ["shot-00", "shot-01", "shot-02"])
        self.assertEqual(plan["sequence_marker"], "shot-00")
        self.assertEqual(plan["payload_hex"], sends[0]["payload_hex"])

        payloads = []
        for index, send in enumerate(sends):
            marker = f"shot-{index:02d}"
            payload = bytes.fromhex(send["payload_hex"])
            payloads.append(payload)

            self.assertEqual(send["index"], index)
            self.assertEqual(send["sequence_marker"], marker)
            self.assertIn(marker.encode("ascii"), payload)
            self.assertTrue(payload.startswith(b"udp-multi-shot-order:"))
            self.assertEqual(send["payload_length"], len(payload))
            self.assertEqual(send["expected_payload_hex"], send["payload_hex"])
            self.assertEqual(send["expected_payload_length"], len(payload))
            self.assertEqual(send["expected_udp_length"], 8 + len(payload))
            self.assertEqual(send["source_port"], plan["source_port"])
            self.assertEqual(send["destination_port"], plan["destination_port"])

            validation = send["validation"]
            self.assertEqual(validation["sequence_marker"], marker)
            self.assertEqual(validation["payload_hex"], send["payload_hex"])
            self.assertEqual(validation["payload_length"], len(payload))
            self.assertEqual(validation["udp_length"], 8 + len(payload))
            self.assertEqual(validation["source_port"], send["destination_port"])
            self.assertEqual(validation["destination_port"], send["source_port"])
            self.assertEqual(validation["checksum_statuses"], ["valid", "ipv4_no_checksum"])

        self.assertEqual(len({payload.hex() for payload in payloads}), 3)

    def test_target_service_describes_ordered_payloads(self) -> None:
        plan = _udp_multi_shot_order_plan()
        target_service = plan["target_service"]

        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["port"], plan["destination_port"])
        self.assertTrue(target_service["multi_shot_order"])
        self.assertEqual(target_service["send_count"], 3)
        self.assertEqual(target_service["sequence_markers"], plan["sequence_markers"])
        self.assertEqual(len(target_service["ordered_payloads"]), 3)
        self.assertIn("udp-multi-shot-order", target_services._UDP_RESPONDER_CASES)

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-multi-shot-order",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1045,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-multi-shot-order", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-multi-shot-order"
            ]
            self.assertTrue(results, "endpoint emitted no udp-multi-shot-order result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertEqual(metadata.get("send_count"), 3)
                planned_sends = metadata.get("planned_sends", [])
                expected_responses = metadata.get("expected_responses", [])
                self.assertEqual(len(planned_sends), 3)
                self.assertEqual(len(expected_responses), 3)

                markers = [send["sequence_marker"] for send in planned_sends]
                self.assertEqual(markers, ["shot-00", "shot-01", "shot-02"])
                payloads = []
                for send in planned_sends:
                    payload = bytes.fromhex(send["payload_hex"])
                    payloads.append(payload)
                    sent = bytes.fromhex(send["sent_raw_hex"])
                    self.assertEqual(len(sent), 28 + len(payload))
                    self.assertEqual(sent[9], 17)
                    self.assertEqual(int.from_bytes(sent[2:4], "big"), 28 + len(payload))
                    self.assertEqual(int.from_bytes(sent[24:26], "big"), 8 + len(payload))
                    self.assertEqual(sent[28:], payload)
                    self.assertIn(send["sequence_marker"].encode("ascii"), payload)

                self.assertEqual(len({payload.hex() for payload in payloads}), 3)
                self.assertEqual(
                    [response["sequence_marker"] for response in expected_responses],
                    markers,
                )


class UdpClosedPortIcmpTest(unittest.TestCase):
    """Focused coverage for UDP closed-port ICMP behavior."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("udp-closed-port-icmp", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-closed-port-icmp"],
            planning._udp_closed_port_icmp_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_udp_closed_port_icmp_plan(), _udp_closed_port_icmp_plan())

    def test_plan_carries_udp_stimulus_and_icmp_port_unreachable_contract(self) -> None:
        plan = _udp_closed_port_icmp_plan()
        payload = bytes.fromhex(plan["payload_hex"])

        self.assertEqual(plan["case"], "udp-closed-port-icmp")
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "icmp_port_unreachable")
        ipaddress.IPv4Address(plan["source_ipv4"])
        ipaddress.IPv4Address(plan["destination_ipv4"])
        self.assertNotEqual(plan["source_ipv4"], plan["destination_ipv4"])
        self.assertIsInstance(plan["source_port"], int)
        self.assertIsInstance(plan["destination_port"], int)
        self.assertNotEqual(plan["source_port"], plan["destination_port"])

        self.assertTrue(payload.startswith(b"udp-closed-port-icmp:"))
        self.assertEqual(plan["payload_length"], len(payload))
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))
        self.assertEqual(plan["expected_icmp_type"], 3)
        self.assertEqual(plan["expected_icmp_code"], 3)
        self.assertEqual(plan["expected_embedded_prefix_length"], 28)

    def test_capture_filter_matches_icmp_reply_direction(self) -> None:
        plan = _udp_closed_port_icmp_plan()

        self.assertIn("icmp", plan["capture_filter"])
        self.assertIn(f"src host {plan['expected_reply_source_ipv4']}", plan["capture_filter"])
        self.assertIn(
            f"dst host {plan['expected_reply_destination_ipv4']}",
            plan["capture_filter"],
        )
        self.assertNotIn("udp", plan["capture_filter"])

    def test_target_setup_verifies_udp_port_is_unbound(self) -> None:
        plan = _udp_closed_port_icmp_plan()
        target_service = plan["target_service"]

        self.assertFalse(target_service["required"])
        self.assertEqual(target_service["kind"], "closed-udp-port")
        self.assertEqual(target_service["port"], plan["destination_port"])
        self.assertEqual(target_service["state"], "planned-unbound")
        self.assertEqual(target_service["expects"], "icmp_port_unreachable")
        self.assertIn("udp-closed-port-icmp", target_services._UDP_CLOSED_PORT_CASES)

        setup = target_services.target_service_setup_plan(
            probe_plans=[plan],
            dry_run=True,
        )
        self.assertFalse(setup["starts_services"])
        self.assertEqual(setup["services"], [])
        self.assertEqual(len(setup["closed_udp_ports"]), 1)
        closed = setup["closed_udp_ports"][0]
        self.assertEqual(closed["port"], plan["destination_port"])
        self.assertEqual(closed["state"], "planned-unbound")
        self.assertEqual(closed["purpose"], "udp-closed-port-icmp")
        self.assertEqual(closed["expects"], "icmp_port_unreachable")

        script = target_services.target_service_setup_script(
            artifact_root="/root/libcrafter/artifacts/probe/target-services",
            bind_ipv4=plan["destination_ipv4"],
            open_ports=[],
            closed_ports=[],
            dns_plans=[],
            closed_udp_ports=[plan["destination_port"]],
        )
        self.assertIn(
            f'check_udp_port_free "$udp_bind_ipv4" {plan["destination_port"]}',
            script,
        )
        self.assertIn(f'echo closed_udp_port_{plan["destination_port"]}=free', script)
        self.assertNotIn("udp_responder", script)

    def test_validation_contract_covers_icmp_and_embedded_udp_prefix(self) -> None:
        plan = _udp_closed_port_icmp_plan()
        validation = plan["validation"]

        self.assertEqual(validation["source_ipv4"], plan["expected_reply_source_ipv4"])
        self.assertEqual(
            validation["destination_ipv4"],
            plan["expected_reply_destination_ipv4"],
        )
        self.assertEqual(validation["icmp_type"], 3)
        self.assertEqual(validation["icmp_code"], 3)
        self.assertEqual(validation["embedded_prefix"]["source"], "stimulus_sent_bytes")
        self.assertEqual(validation["embedded_prefix"]["length"], 28)
        self.assertEqual(validation["embedded_udp"]["source_port"], plan["source_port"])
        self.assertEqual(
            validation["embedded_udp"]["destination_port"],
            plan["destination_port"],
        )
        self.assertEqual(validation["embedded_udp"]["udp_length"], plan["expected_udp_length"])

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-closed-port-icmp",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1046,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-closed-port-icmp", planned)
            target_setup = outcome.report.get("metadata", {}).get("target_service_setup", {})
            closed_udp_ports = target_setup.get("closed_udp_ports", [])
            self.assertTrue(closed_udp_ports)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-closed-port-icmp"
            ]
            self.assertTrue(results, "endpoint emitted no udp-closed-port-icmp result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))
                self.assertTrue(metadata.get("expected_embedded_prefix_hex"))

                probe_plan = metadata["probe_plan"]
                payload = bytes.fromhex(probe_plan["payload_hex"])
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                embedded_prefix = bytes.fromhex(metadata["expected_embedded_prefix_hex"])

                self.assertEqual(embedded_prefix, sent[:28])
                self.assertEqual(sent[9], 17)
                self.assertEqual(int.from_bytes(sent[2:4], "big"), 28 + len(payload))
                self.assertEqual(int.from_bytes(sent[20:22], "big"), probe_plan["source_port"])
                self.assertEqual(
                    int.from_bytes(sent[22:24], "big"),
                    probe_plan["destination_port"],
                )
                self.assertEqual(int.from_bytes(sent[24:26], "big"), 8 + len(payload))
                self.assertEqual(sent[28:], payload)

                self.assertIn("icmp", metadata["capture_filter"])
                self.assertEqual(metadata["target_service"]["kind"], "closed-udp-port")
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


class UdpZeroChecksumIpv4Test(unittest.TestCase):
    """Focused coverage for IPv4 UDP zero-checksum override behavior."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("udp-zero-checksum-ipv4", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-zero-checksum-ipv4"],
            planning._udp_zero_checksum_ipv4_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_udp_zero_checksum_ipv4_plan(), _udp_zero_checksum_ipv4_plan())

    def test_plan_carries_zero_checksum_override_and_echo_contract(self) -> None:
        plan = _udp_zero_checksum_ipv4_plan()
        payload = bytes.fromhex(plan["payload_hex"])

        self.assertEqual(plan["case"], "udp-zero-checksum-ipv4")
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")
        self.assertTrue(payload.startswith(b"udp-zero-checksum-ipv4:"))
        self.assertEqual(plan["payload_length"], len(payload))
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))
        self.assertEqual(plan["stimulus_udp_checksum"], 0)
        self.assertTrue(plan["stimulus_udp_checksum_override"])
        self.assertEqual(
            plan["stimulus_udp_checksum_policy"],
            "ipv4_zero_checksum_override",
        )
        self.assertEqual(
            plan["expected_udp_checksum_statuses"],
            ["valid", "ipv4_no_checksum"],
        )

        self.assertIn("udp-zero-checksum-ipv4", target_services._UDP_RESPONDER_CASES)
        self.assertIn(
            "udp_ipv4_zero_checksum",
            planning.PROBE_CASE_BY_NAME["udp-zero-checksum-ipv4"].required_capabilities,
        )

    def test_target_service_and_validation_surface_kernel_dependent_acceptance(self) -> None:
        plan = _udp_zero_checksum_ipv4_plan()
        target_service = plan["target_service"]

        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["port"], plan["destination_port"])
        self.assertEqual(target_service["payload_hex"], plan["payload_hex"])
        self.assertEqual(target_service["stimulus_udp_checksum"], 0)
        self.assertTrue(target_service["stimulus_udp_checksum_override"])
        self.assertEqual(target_service["kernel_acceptance"], "provider_dependent")

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
        self.assertEqual(validation["checksum_statuses"], ["valid", "ipv4_no_checksum"])
        self.assertEqual(validation["stimulus_udp_checksum"], 0)
        self.assertTrue(plan["wire_requirements"]["requires_udp_ipv4_zero_checksum"])

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-zero-checksum-ipv4",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1047,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-zero-checksum-ipv4", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-zero-checksum-ipv4"
            ]
            self.assertTrue(results, "endpoint emitted no udp-zero-checksum-ipv4 result")
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
                self.assertEqual(int.from_bytes(sent[26:28], "big"), 0)
                self.assertEqual(sent[28:], payload)
                self.assertEqual(probe_plan["stimulus_udp_checksum"], 0)
                self.assertTrue(probe_plan["stimulus_udp_checksum_override"])

                self.assertEqual(
                    metadata["target_service"]["stimulus_udp_checksum"],
                    0,
                )
                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["sport"], probe_plan["source_port"])
                self.assertEqual(decoded["udp"]["dport"], probe_plan["destination_port"])
                self.assertEqual(decoded["udp"]["length"], 8 + len(payload))
                self.assertEqual(decoded["udp"]["checksum"], 0)
                self.assertEqual(decoded["udp"]["checksum_status"], "ipv4_no_checksum")
                self.assertEqual(decoded["payload_hex"], probe_plan["payload_hex"])


class UdpOptionsSurplusEchoTest(unittest.TestCase):
    """Focused coverage for UDP options surplus echo behavior."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("udp-options-surplus-echo", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-options-surplus-echo"],
            planning._udp_options_surplus_echo_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _udp_options_surplus_echo_plan(),
            _udp_options_surplus_echo_plan(),
        )

    def test_plan_carries_udp_surplus_options_and_echo_contract(self) -> None:
        plan = _udp_options_surplus_echo_plan()
        payload = bytes.fromhex(plan["payload_hex"])
        option_bytes = bytes.fromhex(plan["stimulus_udp_options_hex"])

        self.assertEqual(plan["case"], "udp-options-surplus-echo")
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")
        self.assertTrue(payload.startswith(b"udp-options-surplus-echo:"))
        self.assertEqual(plan["payload_length"], len(payload))
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))

        self.assertTrue(plan["udp_options_surplus"])
        self.assertEqual(plan["expected_udp_options_hex"], plan["stimulus_udp_options_hex"])
        self.assertEqual(plan["stimulus_udp_options_policy"], "deterministic_valid_surplus_options")
        self.assertEqual(plan["expected_udp_options_status"], "valid")
        self.assertEqual(option_bytes[0], 1)
        self.assertEqual(option_bytes[1], 4)
        self.assertEqual(option_bytes[5], 6)
        self.assertEqual(option_bytes[-1], 0)
        self.assertEqual(plan["expected_udp_option_count"], 4)
        self.assertEqual(len(plan["expected_udp_options_summary"]), 4)
        self.assertEqual(plan["expected_udp_options_summary"][0], "NOP")
        self.assertTrue(plan["expected_udp_options_summary"][1].startswith("MDS(size="))
        self.assertTrue(plan["expected_udp_options_summary"][2].startswith("REQ(token=0x"))
        self.assertEqual(plan["expected_udp_options_summary"][3], "EOL")
        self.assertEqual(
            plan["expected_udp_surplus_length"],
            plan["expected_udp_surplus_alignment_length"] + 2 + len(option_bytes),
        )
        self.assertEqual(
            plan["expected_ipv4_total_length"],
            20 + plan["expected_udp_length"] + plan["expected_udp_surplus_length"],
        )

        self.assertIn("udp-options-surplus-echo", target_services._UDP_RESPONDER_CASES)
        self.assertIn(
            "udp_options_surplus",
            planning.PROBE_CASE_BY_NAME["udp-options-surplus-echo"].required_capabilities,
        )

    def test_target_service_and_validation_surface_surplus_contract(self) -> None:
        plan = _udp_options_surplus_echo_plan()
        target_service = plan["target_service"]

        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "udp-responder")
        self.assertEqual(target_service["mode"], "echo")
        self.assertEqual(target_service["port"], plan["destination_port"])
        self.assertEqual(target_service["payload_hex"], plan["payload_hex"])
        self.assertTrue(target_service["udp_options_surplus"])
        self.assertEqual(
            target_service["stimulus_udp_options_hex"],
            plan["stimulus_udp_options_hex"],
        )
        self.assertEqual(target_service["expected_udp_surplus_length"], plan["expected_udp_surplus_length"])
        self.assertEqual(target_service["expected_udp_options_summary"], plan["expected_udp_options_summary"])
        self.assertEqual(target_service["kernel_acceptance"], "provider_dependent")

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
        self.assertEqual(validation["expected_udp_options_status"], "valid")
        self.assertEqual(validation["expected_udp_options_summary"], plan["expected_udp_options_summary"])
        self.assertTrue(plan["wire_requirements"]["requires_udp_options_surplus"])

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-options-surplus-echo",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1048,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-options-surplus-echo", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-options-surplus-echo"
            ]
            self.assertTrue(results, "endpoint emitted no udp-options-surplus-echo result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))

                probe_plan = metadata["probe_plan"]
                payload = bytes.fromhex(probe_plan["payload_hex"])
                option_bytes = bytes.fromhex(probe_plan["stimulus_udp_options_hex"])
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                udp_length = 8 + len(payload)
                surplus_start = 20 + udp_length
                surplus = sent[surplus_start:]

                self.assertEqual(len(sent), probe_plan["expected_ipv4_total_length"])
                self.assertEqual(sent[9], 17)
                self.assertEqual(
                    int.from_bytes(sent[2:4], "big"),
                    probe_plan["expected_ipv4_total_length"],
                )
                self.assertEqual(int.from_bytes(sent[20:22], "big"), probe_plan["source_port"])
                self.assertEqual(
                    int.from_bytes(sent[22:24], "big"),
                    probe_plan["destination_port"],
                )
                self.assertEqual(int.from_bytes(sent[24:26], "big"), udp_length)
                self.assertEqual(sent[28:surplus_start], payload)
                self.assertEqual(len(surplus), probe_plan["expected_udp_surplus_length"])
                self.assertEqual(
                    len(surplus) - len(option_bytes) - 2,
                    probe_plan["expected_udp_surplus_alignment_length"],
                )
                self.assertEqual(surplus[-len(option_bytes):], option_bytes)

                self.assertEqual(metadata["sent_udp_surplus_length"], len(surplus))
                sent_options = metadata["sent_udp_options"]
                self.assertEqual(sent_options["status"], "valid")
                self.assertEqual(sent_options["surplus_length"], len(surplus))
                self.assertEqual(sent_options["option_bytes_hex"], probe_plan["stimulus_udp_options_hex"])
                self.assertEqual(sent_options["option_count"], probe_plan["expected_udp_option_count"])
                self.assertEqual(sent_options["summary"], probe_plan["expected_udp_options_summary"])

                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["sport"], probe_plan["source_port"])
                self.assertEqual(decoded["udp"]["dport"], probe_plan["destination_port"])
                self.assertEqual(decoded["udp"]["length"], udp_length)
                self.assertEqual(decoded["udp"]["checksum_status"], "valid")
                self.assertEqual(decoded["payload_hex"], probe_plan["payload_hex"])
                self.assertEqual(decoded["udp_options"]["surplus_length"], len(surplus))
                self.assertEqual(
                    decoded["udp_options"]["summary"],
                    probe_plan["expected_udp_options_summary"],
                )


class UdpLengthBoundaryEchoTest(unittest.TestCase):
    """Focused coverage for the near-boundary non-fragmenting UDP echo case."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("udp-length-boundary-echo", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["udp-length-boundary-echo"],
            planning._udp_length_boundary_echo_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _udp_length_boundary_echo_plan(),
            _udp_length_boundary_echo_plan(),
        )

    def test_plan_carries_near_boundary_payload_echo_contract(self) -> None:
        plan = _udp_length_boundary_echo_plan()
        payload = bytes.fromhex(plan["payload_hex"])
        header_overhead = (
            planning.UDP_ECHO_LARGE_IPV4_HEADER_LENGTH
            + planning.UDP_ECHO_LARGE_UDP_HEADER_LENGTH
        )

        self.assertEqual(plan["case"], "udp-length-boundary-echo")
        self.assertEqual(plan["stimulus"], "udp_datagram")
        self.assertEqual(plan["expected_response"], "udp_response")
        self.assertEqual(len(payload), planning.UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH)
        self.assertEqual(
            plan["payload_length"],
            planning.UDP_ECHO_LARGE_MAX_PAYLOAD_LENGTH - 1,
        )
        self.assertEqual(plan["payload_boundary_margin"], 1)
        self.assertEqual(plan["expected_payload_hex"], plan["payload_hex"])
        self.assertEqual(plan["expected_payload_length"], len(payload))
        self.assertEqual(plan["expected_udp_length"], 8 + len(payload))
        self.assertEqual(
            plan["expected_ipv4_total_length"],
            planning.UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT - 1,
        )
        self.assertEqual(
            plan["expected_ipv4_total_length"],
            plan["payload_length"] + header_overhead,
        )
        self.assertLess(
            plan["expected_ipv4_total_length"],
            planning.UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT,
        )
        self.assertEqual(plan["payload_size_policy"], "near_boundary_non_fragmenting")
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
            target_service["expected_ipv4_total_length"],
            plan["expected_ipv4_total_length"],
        )
        self.assertIn("udp-length-boundary-echo", target_services._UDP_RESPONDER_CASES)
        self.assertIn(
            "udp_large_payload",
            planning.PROBE_CASE_BY_NAME["udp-length-boundary-echo"].required_capabilities,
        )

        validation = plan["validation"]
        self.assertEqual(validation["payload_hex"], plan["payload_hex"])
        self.assertEqual(validation["payload_length"], plan["payload_length"])
        self.assertEqual(validation["udp_length"], plan["expected_udp_length"])
        self.assertEqual(
            validation["expected_ipv4_total_length"],
            plan["expected_ipv4_total_length"],
        )
        self.assertTrue(plan["wire_requirements"]["requires_udp_large_payload"])

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "udp-length-boundary-echo",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1049,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("udp-length-boundary-echo", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "udp-length-boundary-echo"
            ]
            self.assertTrue(results, "endpoint emitted no udp-length-boundary-echo result")
            for result in results:
                self.assertEqual(result.get("status"), "planned")
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))

                probe_plan = metadata["probe_plan"]
                payload = bytes.fromhex(probe_plan["payload_hex"])
                sent = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertEqual(len(payload), planning.UDP_LENGTH_BOUNDARY_PAYLOAD_LENGTH)
                self.assertEqual(len(sent), probe_plan["expected_ipv4_total_length"])
                self.assertEqual(
                    len(sent),
                    planning.UDP_ECHO_LARGE_IPV4_PACKET_SAFETY_LIMIT - 1,
                )
                self.assertEqual(sent[9], 17)
                self.assertEqual(
                    int.from_bytes(sent[2:4], "big"),
                    probe_plan["expected_ipv4_total_length"],
                )
                self.assertEqual(
                    int.from_bytes(sent[20:22], "big"),
                    probe_plan["source_port"],
                )
                self.assertEqual(
                    int.from_bytes(sent[22:24], "big"),
                    probe_plan["destination_port"],
                )
                self.assertEqual(
                    int.from_bytes(sent[24:26], "big"),
                    probe_plan["expected_udp_length"],
                )
                self.assertEqual(sent[28:], payload)
                self.assertNotEqual(int.from_bytes(sent[26:28], "big"), 0)

                decoded = metadata["sent_decoded"]
                self.assertEqual(decoded["udp"]["sport"], probe_plan["source_port"])
                self.assertEqual(decoded["udp"]["dport"], probe_plan["destination_port"])
                self.assertEqual(decoded["udp"]["length"], probe_plan["expected_udp_length"])
                self.assertEqual(decoded["udp"]["checksum_status"], "valid")
                self.assertEqual(decoded["payload_hex"], probe_plan["payload_hex"])


if __name__ == "__main__":
    unittest.main()
