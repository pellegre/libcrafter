"""Focused coverage for the ARP behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.tests.probe_acceptance` harness.

``arp-basic-who-has`` is the baseline ARP behavioral check: an Ethernet-broadcast
ARP who-has request (operation 1) resolving the target endpoint's IPv4 address,
answered by the target kernel with a unicast is-at reply (operation 2). ARP rides
Ethernet directly (no IP/UDP); the stimulus endpoint sends at the link layer,
captures the is-at reply, decodes the Ethernet/ARP frame with libcrafter, and
validates the operation, the sender/target hardware/protocol addresses, and the
Ethernet source/destination. Providers without link-layer send, link-layer
capture, or broadcast support skip the case.
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
        "seed": 1030,
        "count": 1,
        "case_names": case_names or ["arp-basic-who-has"],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _arp_basic_who_has_plan(*, seed: int = 1030, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed),
        case=planning.PROBE_CASE_BY_NAME["arp-basic-who-has"],
        sequence=sequence,
    )


def _is_documentation_mac(mac: str) -> bool:
    # RFC 7042 reserves 00:00:5e:00:53:00-ff for documentation unicast MACs.
    return mac.startswith("00:00:5e:00:53:")


class ArpBasicWhoHasPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct who-has stimulus and is-at contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("arp-basic-who-has", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["arp-basic-who-has"],
            planning._arp_basic_who_has_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_arp_basic_who_has_plan(), _arp_basic_who_has_plan())

    def test_plan_carries_a_broadcast_who_has_stimulus(self) -> None:
        plan = _arp_basic_who_has_plan()

        self.assertEqual(plan["case"], "arp-basic-who-has")
        self.assertEqual(plan["stimulus"], "arp_who_has")
        self.assertEqual(plan["expected_response"], "arp_is_at")

        # ARP rides Ethernet directly (no IP/UDP): ethertype 0x0806, IPv4/Ethernet
        # hardware/protocol parameters, and the request operation (1).
        self.assertEqual(plan["ethertype"], 0x0806)
        self.assertEqual(plan["hardware_type"], 1)
        self.assertEqual(plan["protocol_type"], 0x0800)
        self.assertEqual(plan["hardware_length"], 6)
        self.assertEqual(plan["protocol_length"], 4)
        self.assertEqual(plan["operation"], 1)
        self.assertEqual(plan["operation_label"], "request")

        # The sender hardware address is a documentation MAC; the who-has leaves
        # the target hardware address all-zero. The request is broadcast.
        self.assertTrue(_is_documentation_mac(plan["sender_hardware_addr"]))
        self.assertEqual(plan["target_hardware_addr"], "00:00:00:00:00:00")
        self.assertEqual(plan["ethernet_source"], plan["sender_hardware_addr"])
        self.assertEqual(plan["ethernet_destination"], "ff:ff:ff:ff:ff:ff")

        # The sender resolves the target endpoint's protocol address.
        self.assertEqual(plan["sender_protocol_addr"], plan["source_ipv4"])
        self.assertEqual(plan["target_protocol_addr"], plan["destination_ipv4"])

    def test_validation_contract_covers_is_at_fields(self) -> None:
        plan = _arp_basic_who_has_plan()
        validation = plan["validation"]

        # The expected reply is an ARP is-at (operation 2).
        self.assertEqual(validation["ethertype"], 0x0806)
        self.assertEqual(validation["operation"], 2)
        self.assertEqual(validation["operation_label"], "reply")

        # The reply resolves the target: its sender hardware/protocol address is
        # the target MAC/IPv4 the who-has asked for.
        self.assertTrue(_is_documentation_mac(validation["sender_hardware_addr"]))
        self.assertEqual(validation["sender_protocol_addr"], plan["target_protocol_addr"])

        # The reply is addressed back to the original sender (target hardware /
        # protocol address are the querier's MAC/IPv4).
        self.assertEqual(
            validation["target_hardware_addr"], plan["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["target_protocol_addr"], plan["sender_protocol_addr"]
        )

        # The unicast reply's Ethernet framing: resolved target MAC -> querier MAC.
        self.assertEqual(validation["ethernet_source"], validation["sender_hardware_addr"])
        self.assertEqual(validation["ethernet_destination"], plan["sender_hardware_addr"])

        # The resolved MAC is distinct from the querier MAC.
        self.assertNotEqual(
            validation["sender_hardware_addr"], plan["sender_hardware_addr"]
        )

    def test_capture_filter_is_link_layer_arp_reply(self) -> None:
        plan = _arp_basic_who_has_plan()
        # ARP cannot be selected by host/IP BPF: match on the protocol and the
        # reply opcode (ARP byte 6:2 == 2).
        self.assertEqual(plan["capture_filter"], "arp and arp[6:2] = 2")

    def test_target_service_is_the_arp_answering_kernel(self) -> None:
        plan = _arp_basic_who_has_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "arp-kernel")
        self.assertEqual(target_service["layer"], "link")
        # The kernel answers ARP for its own configured address; setup tunes ARP
        # sysctls and flushes the neighbor cache.
        self.assertEqual(
            target_service["target_protocol_addr"], plan["target_protocol_addr"]
        )
        self.assertTrue(target_service["arp_sysctls"])
        self.assertTrue(target_service["neighbor_cache_flush"])

    def test_wire_requirements_gate_on_link_layer(self) -> None:
        plan = _arp_basic_who_has_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_broadcast"])


class ArpBasicWhoHasTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "arp-basic-who-has",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1030,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("arp-basic-who-has", planned)

            # The endpoint produced a result for the focused case and it built the
            # Ethernet/ARP who-has (a dry-run plan compiles the outgoing stimulus
            # frame at the link layer).
            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "arp-basic-who-has"
            ]
            self.assertTrue(results, "endpoint emitted no arp-basic-who-has result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus frame bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))
                # The compiled who-has frame is an Ethernet/ARP broadcast: the
                # Ethernet destination is the broadcast address and the ethertype
                # is ARP (0x0806). The first 14 octets are the Ethernet header.
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertGreaterEqual(len(frame), 14 + 28)
                self.assertEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
                self.assertEqual(frame[12:14], (0x0806).to_bytes(2, "big"))
                # ARP opcode (bytes 6:2 of the ARP payload, i.e. frame[20:22]) is
                # the who-has request (1).
                self.assertEqual(frame[20:22], (1).to_bytes(2, "big"))

    def test_provider_without_link_layer_skips(self) -> None:
        # Hetzner cannot provide L2/broadcast/provider-MAC, so the case skips with
        # a stable capability reason rather than planning a stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "arp-basic-who-has",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1030,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            arp_skips = [skip for skip in skips if skip.get("case") == "arp-basic-who-has"]
            self.assertTrue(arp_skips, "expected arp-basic-who-has to skip on hetzner")


def _arp_repeat_two_replies_plan(*, seed: int = 1031, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["arp-repeat-two-replies"]),
        case=planning.PROBE_CASE_BY_NAME["arp-repeat-two-replies"],
        sequence=sequence,
    )


class ArpRepeatTwoRepliesPlanTest(unittest.TestCase):
    """The repeat case plans two who-has sends for one target and two contracts."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("arp-repeat-two-replies", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["arp-repeat-two-replies"],
            planning._arp_repeat_two_replies_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _arp_repeat_two_replies_plan(), _arp_repeat_two_replies_plan()
        )

    def test_plan_carries_two_who_has_sends_for_one_target(self) -> None:
        plan = _arp_repeat_two_replies_plan()

        self.assertEqual(plan["case"], "arp-repeat-two-replies")
        self.assertEqual(plan["stimulus"], "arp_who_has")
        self.assertEqual(plan["expected_response"], "arp_is_at")

        # The repeat contract is a per-send array of two who-has -> is-at sends.
        sends = plan["arp_sends"]
        self.assertEqual(plan["send_count"], 2)
        self.assertEqual(len(sends), 2)

        # Both sends resolve the SAME target (the case point is a repeated who-has
        # for one target) and share the sender hardware/protocol address.
        for index, send in enumerate(sends):
            self.assertEqual(send["index"], index)
            self.assertEqual(send["operation"], 1)
            self.assertEqual(send["operation_label"], "request")
            self.assertEqual(send["ethertype"], 0x0806)
            self.assertEqual(send["target_protocol_addr"], plan["target_protocol_addr"])
            self.assertEqual(send["sender_protocol_addr"], plan["sender_protocol_addr"])
            self.assertTrue(_is_documentation_mac(send["sender_hardware_addr"]))
            self.assertEqual(send["target_hardware_addr"], "00:00:00:00:00:00")
            self.assertEqual(send["ethernet_destination"], "ff:ff:ff:ff:ff:ff")
            self.assertEqual(send["capture_filter"], "arp and arp[6:2] = 2")

        self.assertEqual(
            sends[0]["target_protocol_addr"], sends[1]["target_protocol_addr"]
        )

    def test_each_send_carries_an_is_at_validation_contract(self) -> None:
        plan = _arp_repeat_two_replies_plan()
        for send in plan["arp_sends"]:
            validation = send["validation"]
            # Each expected reply is an ARP is-at (operation 2) resolving the
            # target MAC/IPv4 back to the original querier.
            self.assertEqual(validation["operation"], 2)
            self.assertTrue(_is_documentation_mac(validation["sender_hardware_addr"]))
            self.assertEqual(
                validation["sender_protocol_addr"], send["target_protocol_addr"]
            )
            self.assertEqual(
                validation["target_hardware_addr"], send["sender_hardware_addr"]
            )
            self.assertEqual(
                validation["target_protocol_addr"], send["sender_protocol_addr"]
            )
            self.assertEqual(
                validation["ethernet_source"], validation["sender_hardware_addr"]
            )
            self.assertEqual(
                validation["ethernet_destination"], send["sender_hardware_addr"]
            )
            # The resolved MAC is distinct from the querier MAC.
            self.assertNotEqual(
                validation["sender_hardware_addr"], send["sender_hardware_addr"]
            )

    def test_target_service_repeat_descriptor_covers_both_sends(self) -> None:
        plan = _arp_repeat_two_replies_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "arp-kernel")
        self.assertEqual(target_service["layer"], "link")
        self.assertTrue(target_service["arp_sysctls"])
        # A neighbor-cache flush keeps the kernel re-answering each repeated
        # who-has rather than the client short-circuiting on a cached reply.
        self.assertTrue(target_service["neighbor_cache_flush"])
        repeat_sends = target_service["repeat"]["sends"]
        self.assertEqual(len(repeat_sends), 2)
        for repeat_send in repeat_sends:
            self.assertEqual(
                repeat_send["target_protocol_addr"], plan["target_protocol_addr"]
            )

    def test_wire_requirements_gate_on_link_layer(self) -> None:
        plan = _arp_repeat_two_replies_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_broadcast"])


class ArpRepeatTwoRepliesTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_plans_two_sends_and_two_expected_replies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "arp-repeat-two-replies",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1031,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("arp-repeat-two-replies", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "arp-repeat-two-replies"
            ]
            self.assertTrue(
                results, "endpoint emitted no arp-repeat-two-replies result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # The multi-send dry-run plans two who-has sends and two expected
                # is-at replies.
                self.assertEqual(metadata.get("send_count"), 2)
                planned_sends = metadata.get("planned_sends", [])
                expected_responses = metadata.get("expected_responses", [])
                self.assertEqual(len(planned_sends), 2)
                self.assertEqual(len(expected_responses), 2)

                targets = set()
                for send in planned_sends:
                    # Each planned send carries the compiled Ethernet/ARP who-has
                    # broadcast frame bytes.
                    frame = bytes.fromhex(send["sent_raw_hex"])
                    self.assertGreaterEqual(len(frame), 14 + 28)
                    self.assertEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
                    self.assertEqual(frame[12:14], (0x0806).to_bytes(2, "big"))
                    # ARP opcode (frame[20:22]) is the who-has request (1).
                    self.assertEqual(frame[20:22], (1).to_bytes(2, "big"))
                    targets.add(send["target_protocol_addr"])

                # Both who-has sends resolve the same target address.
                self.assertEqual(len(targets), 1)

                # Each expected reply is an ARP is-at (operation 2).
                for expected in expected_responses:
                    self.assertEqual(expected["operation"], 2)

    def test_provider_without_link_layer_skips(self) -> None:
        # Hetzner cannot provide L2/broadcast/provider-MAC, so the case skips with
        # a stable capability reason rather than planning a stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "arp-repeat-two-replies",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1031,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            arp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "arp-repeat-two-replies"
            ]
            self.assertTrue(
                arp_skips, "expected arp-repeat-two-replies to skip on hetzner"
            )


def _arp_source_address_preserved_plan(*, seed: int = 1032, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["arp-source-address-preserved"]),
        case=planning.PROBE_CASE_BY_NAME["arp-source-address-preserved"],
        sequence=sequence,
    )


class ArpSourceAddressPreservedPlanTest(unittest.TestCase):
    """The reply must be addressed back to the request's sender HW/proto."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("arp-source-address-preserved", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["arp-source-address-preserved"],
            planning._arp_source_address_preserved_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _arp_source_address_preserved_plan(),
            _arp_source_address_preserved_plan(),
        )

    def test_request_uses_deterministic_sender_hw_and_proto(self) -> None:
        plan = _arp_source_address_preserved_plan()

        self.assertEqual(plan["case"], "arp-source-address-preserved")
        self.assertEqual(plan["stimulus"], "arp_who_has")
        self.assertEqual(plan["expected_response"], "arp_is_at")
        self.assertEqual(plan["operation"], 1)

        # The request carries deterministic sender hardware AND protocol
        # addresses (the stimulus endpoint's own); the who-has leaves the target
        # hardware address all-zero and is broadcast.
        self.assertTrue(_is_documentation_mac(plan["sender_hardware_addr"]))
        self.assertEqual(plan["sender_protocol_addr"], plan["source_ipv4"])
        self.assertEqual(plan["target_hardware_addr"], "00:00:00:00:00:00")
        self.assertEqual(plan["ethernet_source"], plan["sender_hardware_addr"])
        self.assertEqual(plan["ethernet_destination"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(plan["target_protocol_addr"], plan["destination_ipv4"])

    def test_validation_preserves_request_sender_into_reply_target(self) -> None:
        plan = _arp_source_address_preserved_plan()
        validation = plan["validation"]

        self.assertEqual(validation["operation"], 2)

        # Preservation: the reply's TARGET hardware/protocol address equals the
        # request's SENDER hardware/protocol address (the reply is addressed back
        # to the requester).
        self.assertEqual(
            validation["target_hardware_addr"], plan["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["target_protocol_addr"], plan["sender_protocol_addr"]
        )

        # The reply's SENDER hardware/protocol address is the target endpoint's
        # own MAC/IPv4 (the resolved address), distinct from the querier.
        self.assertTrue(_is_documentation_mac(validation["sender_hardware_addr"]))
        self.assertEqual(
            validation["sender_protocol_addr"], plan["target_protocol_addr"]
        )
        self.assertNotEqual(
            validation["sender_hardware_addr"], plan["sender_hardware_addr"]
        )

        # The unicast reply's Ethernet framing mirrors the swap: resolved target
        # MAC -> the original querier MAC.
        self.assertEqual(
            validation["ethernet_source"], validation["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["ethernet_destination"], plan["sender_hardware_addr"]
        )

    def test_target_service_is_the_arp_answering_kernel(self) -> None:
        plan = _arp_source_address_preserved_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "arp-kernel")
        self.assertEqual(target_service["layer"], "link")
        self.assertEqual(
            target_service["target_protocol_addr"], plan["target_protocol_addr"]
        )
        self.assertTrue(target_service["arp_sysctls"])
        self.assertTrue(target_service["neighbor_cache_flush"])

    def test_wire_requirements_gate_on_link_layer(self) -> None:
        plan = _arp_source_address_preserved_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_broadcast"])


class ArpSourceAddressPreservedTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "arp-source-address-preserved",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1032,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("arp-source-address-preserved", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "arp-source-address-preserved"
            ]
            self.assertTrue(
                results, "endpoint emitted no arp-source-address-preserved result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus frame bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))
                # The compiled who-has frame is an Ethernet/ARP broadcast request
                # carrying the deterministic sender hardware/protocol address.
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertGreaterEqual(len(frame), 14 + 28)
                self.assertEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
                self.assertEqual(frame[12:14], (0x0806).to_bytes(2, "big"))
                # ARP opcode (frame[20:22]) is the who-has request (1).
                self.assertEqual(frame[20:22], (1).to_bytes(2, "big"))

                # The probe plan echoed back carries the preservation contract:
                # the expected reply's TARGET HW/proto equal the request's SENDER
                # HW/proto, and its SENDER HW/proto are the target endpoint's own.
                plan = metadata.get("probe_plan", {})
                validation = plan.get("validation", {})
                self.assertEqual(
                    validation.get("target_hardware_addr"),
                    plan.get("sender_hardware_addr"),
                )
                self.assertEqual(
                    validation.get("target_protocol_addr"),
                    plan.get("sender_protocol_addr"),
                )
                self.assertEqual(
                    validation.get("sender_protocol_addr"),
                    plan.get("target_protocol_addr"),
                )
                self.assertNotEqual(
                    validation.get("sender_hardware_addr"),
                    plan.get("sender_hardware_addr"),
                )

    def test_provider_without_link_layer_skips(self) -> None:
        # Hetzner cannot provide L2/broadcast/provider-MAC, so the case skips with
        # a stable capability reason rather than planning a stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "arp-source-address-preserved",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1032,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            arp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "arp-source-address-preserved"
            ]
            self.assertTrue(
                arp_skips,
                "expected arp-source-address-preserved to skip on hetzner",
            )


if __name__ == "__main__":
    unittest.main()
