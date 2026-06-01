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


def _arp_alias_address_reply_plan(*, seed: int = 1033, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["arp-alias-address-reply"]),
        case=planning.PROBE_CASE_BY_NAME["arp-alias-address-reply"],
        sequence=sequence,
    )


class ArpAliasAddressReplyPlanTest(unittest.TestCase):
    """The target answers ARP for a configured secondary IPv4 alias."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("arp-alias-address-reply", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["arp-alias-address-reply"],
            planning._arp_alias_address_reply_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _arp_alias_address_reply_plan(),
            _arp_alias_address_reply_plan(),
        )

    def test_who_has_resolves_the_alias_not_the_primary(self) -> None:
        plan = _arp_alias_address_reply_plan()

        self.assertEqual(plan["case"], "arp-alias-address-reply")
        self.assertEqual(plan["stimulus"], "arp_who_has")
        self.assertEqual(plan["expected_response"], "arp_is_at")
        self.assertEqual(plan["operation"], 1)

        # The who-has resolves the configured alias address, which is a distinct
        # host from the endpoint's primary IPv4 but rides the same /24 segment.
        alias = plan["alias_ipv4"]
        endpoint_pair = planning.deterministic_ipv4_pair("behavior", 1033, 0)
        primary_target = endpoint_pair[1]
        self.assertEqual(plan["target_protocol_addr"], alias)
        self.assertEqual(plan["destination_ipv4"], alias)
        self.assertNotEqual(alias, primary_target)
        self.assertNotEqual(alias, plan["source_ipv4"])
        # Same /24 lab segment as the endpoint pair.
        self.assertEqual(
            ipaddress.ip_network(f"{alias}/24", strict=False),
            ipaddress.ip_network(f"{primary_target}/24", strict=False),
        )

        # The who-has is a broadcast request carrying a documentation sender MAC.
        self.assertTrue(_is_documentation_mac(plan["sender_hardware_addr"]))
        self.assertEqual(plan["target_hardware_addr"], "00:00:00:00:00:00")
        self.assertEqual(plan["ethernet_destination"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(plan["sender_protocol_addr"], plan["source_ipv4"])

    def test_validation_pins_reply_sender_to_alias_and_target_mac(self) -> None:
        plan = _arp_alias_address_reply_plan()
        validation = plan["validation"]

        self.assertEqual(validation["operation"], 2)
        # The reply's SENDER protocol address is the alias (the resolved address).
        self.assertEqual(validation["sender_protocol_addr"], plan["alias_ipv4"])
        # The reply's SENDER hardware address is the target endpoint's own MAC.
        self.assertTrue(_is_documentation_mac(validation["sender_hardware_addr"]))
        self.assertEqual(
            validation["sender_hardware_addr"],
            plan["target_service"]["target_hardware_addr"],
        )
        # The reply is addressed back to the original querier.
        self.assertEqual(
            validation["target_hardware_addr"], plan["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["target_protocol_addr"], plan["sender_protocol_addr"]
        )
        # The resolved MAC is distinct from the querier MAC.
        self.assertNotEqual(
            validation["sender_hardware_addr"], plan["sender_hardware_addr"]
        )

    def test_target_service_adds_and_removes_the_alias(self) -> None:
        plan = _arp_alias_address_reply_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "arp-kernel")
        self.assertEqual(target_service["layer"], "link")
        self.assertTrue(target_service["alias_address"])
        self.assertEqual(target_service["alias_ipv4"], plan["alias_ipv4"])
        self.assertEqual(
            target_service["target_protocol_addr"], plan["alias_ipv4"]
        )
        self.assertTrue(target_service["arp_sysctls"])
        self.assertTrue(target_service["neighbor_cache_flush"])

        # The typed kernel-state descriptor renders the alias add/del setup and
        # cleanup commands so target preparation is reversible.
        descriptor = target_services.arp_alias_descriptor(
            bind_ipv4=plan["source_ipv4"],
            source_ipv4=plan["source_ipv4"],
            alias_ipv4=plan["alias_ipv4"],
            interface="eth0",
        )
        self.assertTrue(
            any(
                command.startswith(f"ip addr add {plan['alias_ipv4']}/")
                for command in descriptor.setup_commands
            ),
            f"expected an alias add command, got {descriptor.setup_commands}",
        )
        self.assertTrue(
            any(
                command.startswith(f"ip addr del {plan['alias_ipv4']}/")
                for command in descriptor.cleanup_commands
            ),
            f"expected an alias del command, got {descriptor.cleanup_commands}",
        )

    def test_wire_requirements_gate_on_link_layer(self) -> None:
        plan = _arp_alias_address_reply_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_broadcast"])


class ArpAliasAddressReplyTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "arp-alias-address-reply",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1033,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("arp-alias-address-reply", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "arp-alias-address-reply"
            ]
            self.assertTrue(
                results, "endpoint emitted no arp-alias-address-reply result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus frame bytes: an
                # Ethernet/ARP broadcast who-has request (opcode 1).
                self.assertTrue(metadata.get("sent_raw_hex"))
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertGreaterEqual(len(frame), 14 + 28)
                self.assertEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
                self.assertEqual(frame[12:14], (0x0806).to_bytes(2, "big"))
                self.assertEqual(frame[20:22], (1).to_bytes(2, "big"))

                # The probe plan echoed back resolves the alias and pins the
                # expected reply sender-proto to the alias.
                plan = metadata.get("probe_plan", {})
                alias = plan.get("alias_ipv4")
                self.assertTrue(alias)
                self.assertEqual(plan.get("target_protocol_addr"), alias)
                validation = plan.get("validation", {})
                self.assertEqual(validation.get("sender_protocol_addr"), alias)

                # The target service adds the alias (alias_address marker + the
                # alias IPv4 the kernel answers for).
                target_service = metadata.get("target_service", {})
                self.assertTrue(target_service.get("alias_address"))
                self.assertEqual(target_service.get("alias_ipv4"), alias)

    def test_provider_without_link_layer_skips(self) -> None:
        # Hetzner cannot provide L2/broadcast/provider-MAC, so the case skips with
        # a stable capability reason rather than planning a stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "arp-alias-address-reply",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1033,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            arp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "arp-alias-address-reply"
            ]
            self.assertTrue(
                arp_skips,
                "expected arp-alias-address-reply to skip on hetzner",
            )


def _arp_unicast_request_reply_plan(*, seed: int = 1034, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["arp-unicast-request-reply"]),
        case=planning.PROBE_CASE_BY_NAME["arp-unicast-request-reply"],
        sequence=sequence,
    )


class ArpUnicastRequestReplyPlanTest(unittest.TestCase):
    """The request is sent unicast to the known target MAC, not broadcast."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("arp-unicast-request-reply", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["arp-unicast-request-reply"],
            planning._arp_unicast_request_reply_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _arp_unicast_request_reply_plan(),
            _arp_unicast_request_reply_plan(),
        )

    def test_request_is_addressed_unicast_to_the_target_mac(self) -> None:
        plan = _arp_unicast_request_reply_plan()

        self.assertEqual(plan["case"], "arp-unicast-request-reply")
        self.assertEqual(plan["stimulus"], "arp_who_has")
        self.assertEqual(plan["expected_response"], "arp_is_at")
        self.assertEqual(plan["operation"], 1)
        self.assertEqual(plan["operation_label"], "request")

        # The whole point of the case: the request's Ethernet destination is the
        # KNOWN target MAC, NOT the broadcast address.
        target_mac = plan["target_service"]["target_hardware_addr"]
        self.assertTrue(_is_documentation_mac(target_mac))
        self.assertEqual(plan["ethernet_destination"], target_mac)
        self.assertNotEqual(plan["ethernet_destination"], "ff:ff:ff:ff:ff:ff")
        self.assertTrue(plan["request_is_unicast"])

        # The Ethernet destination is the same target MAC the reply resolves to.
        self.assertEqual(
            plan["ethernet_destination"],
            plan["validation"]["sender_hardware_addr"],
        )

        # The ARP layer is otherwise an ordinary who-has: documentation sender
        # MAC, all-zero target hardware, target protocol = the target IPv4.
        self.assertTrue(_is_documentation_mac(plan["sender_hardware_addr"]))
        self.assertEqual(plan["ethernet_source"], plan["sender_hardware_addr"])
        self.assertEqual(plan["target_hardware_addr"], "00:00:00:00:00:00")
        self.assertEqual(plan["sender_protocol_addr"], plan["source_ipv4"])
        self.assertEqual(plan["target_protocol_addr"], plan["destination_ipv4"])

    def test_validation_contract_covers_is_at_fields(self) -> None:
        plan = _arp_unicast_request_reply_plan()
        validation = plan["validation"]

        self.assertEqual(validation["ethertype"], 0x0806)
        self.assertEqual(validation["operation"], 2)
        self.assertEqual(validation["operation_label"], "reply")

        # The reply resolves the target: sender HW/proto = the target MAC/IPv4.
        self.assertTrue(_is_documentation_mac(validation["sender_hardware_addr"]))
        self.assertEqual(
            validation["sender_protocol_addr"], plan["target_protocol_addr"]
        )

        # The reply is addressed back to the original querier.
        self.assertEqual(
            validation["target_hardware_addr"], plan["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["target_protocol_addr"], plan["sender_protocol_addr"]
        )

        # The unicast reply's Ethernet framing: resolved target MAC -> querier MAC.
        self.assertEqual(
            validation["ethernet_source"], validation["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["ethernet_destination"], plan["sender_hardware_addr"]
        )

        # The resolved MAC is distinct from the querier MAC.
        self.assertNotEqual(
            validation["sender_hardware_addr"], plan["sender_hardware_addr"]
        )

    def test_plan_requires_provider_mac_knowledge(self) -> None:
        # A unicast request cannot be addressed without the target's MAC, so the
        # case requires provider-MAC knowledge: the wire requirements flag it and
        # the catalog case lists the provider_mac capability so MAC-less providers
        # skip with the stable requires_provider_mac reason.
        plan = _arp_unicast_request_reply_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_provider_mac"])
        self.assertIn(
            "provider_mac",
            planning.PROBE_CASE_BY_NAME["arp-unicast-request-reply"].required_capabilities,
        )

    def test_target_service_is_the_arp_answering_kernel(self) -> None:
        plan = _arp_unicast_request_reply_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "arp-kernel")
        self.assertEqual(target_service["layer"], "link")
        self.assertEqual(
            target_service["target_protocol_addr"], plan["target_protocol_addr"]
        )
        self.assertTrue(target_service["arp_sysctls"])
        self.assertTrue(target_service["neighbor_cache_flush"])


class ArpUnicastRequestReplyTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "arp-unicast-request-reply",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1034,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("arp-unicast-request-reply", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "arp-unicast-request-reply"
            ]
            self.assertTrue(
                results, "endpoint emitted no arp-unicast-request-reply result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus frame bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))
                # The compiled who-has frame is an Ethernet/ARP UNICAST request:
                # the Ethernet destination is the target MAC (NOT broadcast) and
                # the ethertype is ARP (0x0806). The first 14 octets are the
                # Ethernet header.
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertGreaterEqual(len(frame), 14 + 28)
                self.assertNotEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
                self.assertEqual(frame[12:14], (0x0806).to_bytes(2, "big"))
                # ARP opcode (frame[20:22]) is the who-has request (1).
                self.assertEqual(frame[20:22], (1).to_bytes(2, "big"))

                # The Ethernet destination of the request is exactly the target
                # MAC the reply also resolves to.
                plan = metadata.get("probe_plan", {})
                target_mac = (
                    plan.get("target_service", {}).get("target_hardware_addr")
                )
                self.assertTrue(target_mac)
                expected_dst = bytes(
                    int(octet, 16) for octet in target_mac.split(":")
                )
                self.assertEqual(frame[0:6], expected_dst)
                self.assertEqual(plan.get("ethernet_destination"), target_mac)
                self.assertEqual(
                    plan.get("validation", {}).get("sender_hardware_addr"),
                    target_mac,
                )

    def test_provider_without_provider_mac_skips(self) -> None:
        # Hetzner cannot provide L2/broadcast/provider-MAC, so the case skips with
        # a stable capability reason rather than planning a unicast stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "arp-unicast-request-reply",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1034,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            arp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "arp-unicast-request-reply"
            ]
            self.assertTrue(
                arp_skips,
                "expected arp-unicast-request-reply to skip on hetzner",
            )


def _arp_padding_reply_plan(*, seed: int = 1035, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["arp-padding-reply"]),
        case=planning.PROBE_CASE_BY_NAME["arp-padding-reply"],
        sequence=sequence,
    )


class ArpPaddingReplyPlanTest(unittest.TestCase):
    """The who-has frame is padded up to the Ethernet minimum frame length."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("arp-padding-reply", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["arp-padding-reply"],
            planning._arp_padding_reply_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_arp_padding_reply_plan(), _arp_padding_reply_plan())

    def test_plan_carries_a_broadcast_who_has_with_padding_metadata(self) -> None:
        plan = _arp_padding_reply_plan()

        self.assertEqual(plan["case"], "arp-padding-reply")
        self.assertEqual(plan["stimulus"], "arp_who_has")
        self.assertEqual(plan["expected_response"], "arp_is_at")
        self.assertEqual(plan["operation"], 1)
        self.assertEqual(plan["operation_label"], "request")

        # The request is an ordinary broadcast who-has carrying a documentation
        # sender MAC; the who-has leaves the target hardware address all-zero.
        self.assertTrue(_is_documentation_mac(plan["sender_hardware_addr"]))
        self.assertEqual(plan["target_hardware_addr"], "00:00:00:00:00:00")
        self.assertEqual(plan["ethernet_source"], plan["sender_hardware_addr"])
        self.assertEqual(plan["ethernet_destination"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(plan["sender_protocol_addr"], plan["source_ipv4"])
        self.assertEqual(plan["target_protocol_addr"], plan["destination_ipv4"])

        # The padding metadata: the frame is padded up to the 60-byte (sans FCS)
        # Ethernet minimum, and the endpoint records the resulting frame length.
        self.assertEqual(plan["ethernet_min_frame_len"], 60)
        self.assertEqual(plan["expected_request_frame_len"], 60)

    def test_validation_contract_covers_is_at_fields(self) -> None:
        plan = _arp_padding_reply_plan()
        validation = plan["validation"]

        self.assertEqual(validation["ethertype"], 0x0806)
        self.assertEqual(validation["operation"], 2)
        self.assertEqual(validation["operation_label"], "reply")

        # The reply resolves the target: sender HW/proto = the target MAC/IPv4.
        self.assertTrue(_is_documentation_mac(validation["sender_hardware_addr"]))
        self.assertEqual(
            validation["sender_protocol_addr"], plan["target_protocol_addr"]
        )
        # The reply is addressed back to the original querier.
        self.assertEqual(
            validation["target_hardware_addr"], plan["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["target_protocol_addr"], plan["sender_protocol_addr"]
        )
        # The resolved MAC is distinct from the querier MAC.
        self.assertNotEqual(
            validation["sender_hardware_addr"], plan["sender_hardware_addr"]
        )

    def test_target_service_is_the_arp_answering_kernel(self) -> None:
        plan = _arp_padding_reply_plan()
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
        plan = _arp_padding_reply_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_broadcast"])


class ArpPaddingReplyTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "arp-padding-reply",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1035,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("arp-padding-reply", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "arp-padding-reply"
            ]
            self.assertTrue(results, "endpoint emitted no arp-padding-reply result")
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus frame bytes.
                self.assertTrue(metadata.get("sent_raw_hex"))

                # The endpoint records the sent frame length and the expected
                # request frame length (the padded minimum) in metadata.
                self.assertEqual(metadata.get("ethernet_min_frame_len"), 60)
                self.assertEqual(metadata.get("expected_request_frame_len"), 60)
                self.assertEqual(metadata.get("sent_frame_len"), 60)

                # The compiled who-has frame is an Ethernet/ARP broadcast request
                # PADDED up to the 60-byte minimum: 14-byte Ethernet header +
                # 28-byte ARP payload + 18 trailing zero pad bytes.
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertEqual(len(frame), 60)
                self.assertEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
                self.assertEqual(frame[12:14], (0x0806).to_bytes(2, "big"))
                # ARP opcode (frame[20:22]) is the who-has request (1).
                self.assertEqual(frame[20:22], (1).to_bytes(2, "big"))
                # The trailing bytes after the 42-byte Ethernet/ARP frame are the
                # zero padding the agent set (an honored override compile()
                # preserved).
                self.assertEqual(frame[42:], b"\x00" * 18)

                # The plan echoed back carries the padding metadata.
                plan = metadata.get("probe_plan", {})
                self.assertEqual(plan.get("ethernet_min_frame_len"), 60)
                self.assertEqual(plan.get("expected_request_frame_len"), 60)

    def test_provider_without_link_layer_skips(self) -> None:
        # Hetzner cannot provide L2/broadcast/provider-MAC, so the case skips with
        # a stable capability reason rather than planning a stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "arp-padding-reply",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1035,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            arp_skips = [
                skip for skip in skips if skip.get("case") == "arp-padding-reply"
            ]
            self.assertTrue(arp_skips, "expected arp-padding-reply to skip on hetzner")


def _arp_cache_flush_reply_plan(*, seed: int = 1036, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=["arp-cache-flush-reply"]),
        case=planning.PROBE_CASE_BY_NAME["arp-cache-flush-reply"],
        sequence=sequence,
    )


class ArpCacheFlushReplyPlanTest(unittest.TestCase):
    """The target setup flushes the neighbor cache before the stimulus who-has."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("arp-cache-flush-reply", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["arp-cache-flush-reply"],
            planning._arp_cache_flush_reply_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _arp_cache_flush_reply_plan(), _arp_cache_flush_reply_plan()
        )

    def test_plan_carries_a_broadcast_who_has_stimulus(self) -> None:
        plan = _arp_cache_flush_reply_plan()

        self.assertEqual(plan["case"], "arp-cache-flush-reply")
        self.assertEqual(plan["stimulus"], "arp_who_has")
        self.assertEqual(plan["expected_response"], "arp_is_at")

        # ARP rides Ethernet directly (no IP/UDP): ethertype 0x0806, IPv4/Ethernet
        # hardware/protocol parameters, and the request operation (1).
        self.assertEqual(plan["ethertype"], 0x0806)
        self.assertEqual(plan["operation"], 1)
        self.assertEqual(plan["operation_label"], "request")

        # The request is a broadcast who-has carrying a documentation sender MAC.
        self.assertTrue(_is_documentation_mac(plan["sender_hardware_addr"]))
        self.assertEqual(plan["target_hardware_addr"], "00:00:00:00:00:00")
        self.assertEqual(plan["ethernet_source"], plan["sender_hardware_addr"])
        self.assertEqual(plan["ethernet_destination"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(plan["sender_protocol_addr"], plan["source_ipv4"])
        self.assertEqual(plan["target_protocol_addr"], plan["destination_ipv4"])

    def test_validation_contract_covers_is_at_fields(self) -> None:
        plan = _arp_cache_flush_reply_plan()
        validation = plan["validation"]

        # Same is-at contract as the basic case: a reply (operation 2) resolving
        # the target MAC/IPv4 back to the original querier.
        self.assertEqual(validation["ethertype"], 0x0806)
        self.assertEqual(validation["operation"], 2)
        self.assertEqual(validation["operation_label"], "reply")
        self.assertTrue(_is_documentation_mac(validation["sender_hardware_addr"]))
        self.assertEqual(
            validation["sender_protocol_addr"], plan["target_protocol_addr"]
        )
        self.assertEqual(
            validation["target_hardware_addr"], plan["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["target_protocol_addr"], plan["sender_protocol_addr"]
        )
        self.assertEqual(
            validation["ethernet_source"], validation["sender_hardware_addr"]
        )
        self.assertEqual(
            validation["ethernet_destination"], plan["sender_hardware_addr"]
        )
        self.assertNotEqual(
            validation["sender_hardware_addr"], plan["sender_hardware_addr"]
        )

    def test_target_service_flushes_neighbor_cache_before_stimulus(self) -> None:
        plan = _arp_cache_flush_reply_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "arp-kernel")
        self.assertEqual(target_service["layer"], "link")
        self.assertEqual(
            target_service["target_protocol_addr"], plan["target_protocol_addr"]
        )
        self.assertTrue(target_service["arp_sysctls"])
        self.assertTrue(target_service["neighbor_cache_flush"])

        # The behavioral distinction: an explicit pre-stimulus neighbor flush
        # marker plus the setup flush commands (run BEFORE the stimulus) and the
        # cleanup commands (leaving neighbor state in a normal flushed state).
        self.assertTrue(target_service["flush_neighbor"])
        setup = target_service["neighbor_flush_commands"]
        cleanup = target_service["neighbor_flush_cleanup_commands"]
        self.assertTrue(setup, "expected pre-stimulus neighbor flush setup commands")
        self.assertTrue(cleanup, "expected neighbor flush cleanup commands")
        # The setup flushes the neighbor cache before the who-has is sent.
        self.assertTrue(
            any(command.startswith("ip neigh flush") for command in setup),
            f"expected an `ip neigh flush` setup command, got {setup}",
        )
        # The cleanup leaves neighbor state in a normal (flushed) state.
        self.assertTrue(
            any(command.startswith("ip neigh flush") for command in cleanup),
            f"expected an `ip neigh flush` cleanup command, got {cleanup}",
        )

        # The same flush contract is surfaced at the top level so the stimulus
        # endpoint reads it through the flattened plan.
        self.assertTrue(plan["flush_neighbor"])
        self.assertEqual(plan["neighbor_flush_commands"], setup)
        self.assertEqual(plan["neighbor_flush_cleanup_commands"], cleanup)

    def test_wire_requirements_gate_on_link_layer(self) -> None:
        plan = _arp_cache_flush_reply_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_broadcast"])


class ArpCacheFlushReplyTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "arp-cache-flush-reply",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1036,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("arp-cache-flush-reply", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "arp-cache-flush-reply"
            ]
            self.assertTrue(
                results, "endpoint emitted no arp-cache-flush-reply result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus frame bytes: an
                # Ethernet/ARP broadcast who-has request (opcode 1).
                self.assertTrue(metadata.get("sent_raw_hex"))
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertGreaterEqual(len(frame), 14 + 28)
                self.assertEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
                self.assertEqual(frame[12:14], (0x0806).to_bytes(2, "big"))
                # ARP opcode (frame[20:22]) is the who-has request (1).
                self.assertEqual(frame[20:22], (1).to_bytes(2, "big"))

                # The probe plan echoed back validates a fresh is-at reply
                # (operation 2) the same way the basic case does.
                plan = metadata.get("probe_plan", {})
                validation = plan.get("validation", {})
                self.assertEqual(validation.get("operation"), 2)

                # The endpoint's target service surfaces the explicit pre-stimulus
                # neighbor flush (setup) and the cleanup that leaves neighbor state
                # in a normal flushed state.
                target_service = metadata.get("target_service", {})
                self.assertEqual(target_service.get("kind"), "arp-kernel")
                self.assertTrue(target_service.get("flush_neighbor"))
                setup = target_service.get("neighbor_flush_commands") or []
                cleanup = target_service.get("neighbor_flush_cleanup_commands") or []
                self.assertTrue(
                    any(str(c).startswith("ip neigh flush") for c in setup),
                    f"expected a flush setup command in target service, got {setup}",
                )
                self.assertTrue(
                    any(str(c).startswith("ip neigh flush") for c in cleanup),
                    f"expected a flush cleanup command in target service, got {cleanup}",
                )

    def test_provider_without_link_layer_skips(self) -> None:
        # Hetzner cannot provide L2/broadcast/provider-MAC, so the case skips with
        # a stable capability reason rather than planning a stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "arp-cache-flush-reply",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1036,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            arp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "arp-cache-flush-reply"
            ]
            self.assertTrue(
                arp_skips, "expected arp-cache-flush-reply to skip on hetzner"
            )


if __name__ == "__main__":
    unittest.main()
