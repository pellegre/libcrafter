"""Focused coverage for the NDP (IPv6 Neighbor Discovery) behavioral probe cases.

Each test asserts the deterministic plan shape its case produces and, when the
``uv``/``cargo`` toolchains are available, drives the case end to end through the
probe planner dry-run and the Rust ``stimulus_endpoint`` dry-run via the shared
:mod:`tools.probe.testing.probe_acceptance` harness.

NDP is the IPv6 analog of ARP. ``ndp-neighbor-solicitation`` is the baseline NDP
behavioral check (the direct analog of ARP who-has/is-at): a Neighbor
Solicitation (ICMPv6 type 135) resolving the target endpoint's link-local
address, addressed to its solicited-node multicast group, answered by the target
kernel with a solicited Neighbor Advertisement (type 136). NDP rides ICMPv6 over
IPv6 (not Ethernet directly like ARP); the stimulus endpoint builds an
Ethernet/IPv6/ICMPv6 stack, captures the advertisement, decodes it with
libcrafter, and validates the type, the R/S/O flags, the resolved target address,
and the Target Link-Layer Address option. ``ndp-router-solicitation`` solicits a
Router Advertisement (type 134, which needs an RA-emitting router target), and
``ndp-duplicate-address-detection`` sends a DAD probe from the unspecified source
(``::``). Providers without an IPv6 multicast link-layer substrate skip the
cases.
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
        "seed": 1050,
        "count": 1,
        "case_names": case_names or ["ndp-neighbor-solicitation"],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _is_documentation_mac(mac: str) -> bool:
    # RFC 7042 reserves 00:00:5e:00:53:00-ff for documentation unicast MACs.
    return mac.startswith("00:00:5e:00:53:")


def _is_link_local(address: str) -> bool:
    # RFC 4291 link-local prefix fe80::/10.
    return ipaddress.ip_address(address) in ipaddress.ip_network("fe80::/10")


def _ndp_plan(case_name: str, *, seed: int, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=[case_name]),
        case=planning.PROBE_CASE_BY_NAME[case_name],
        sequence=sequence,
    )


# --- ndp-neighbor-solicitation (the primary, ARP who-has/is-at analog) ---------


def _ndp_neighbor_solicitation_plan(*, seed: int = 1050, sequence: int = 0) -> dict:
    return _ndp_plan("ndp-neighbor-solicitation", seed=seed, sequence=sequence)


class NdpNeighborSolicitationPlanTest(unittest.TestCase):
    """The plan carries an RFC-correct NS stimulus and NA validation contract."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("ndp-neighbor-solicitation", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["ndp-neighbor-solicitation"],
            planning._ndp_neighbor_solicitation_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _ndp_neighbor_solicitation_plan(), _ndp_neighbor_solicitation_plan()
        )

    def test_plan_carries_a_solicited_node_neighbor_solicitation(self) -> None:
        plan = _ndp_neighbor_solicitation_plan()

        self.assertEqual(plan["case"], "ndp-neighbor-solicitation")
        self.assertEqual(plan["stimulus"], "ndp_neighbor_solicitation")
        self.assertEqual(plan["expected_response"], "ndp_neighbor_advertisement")

        # NDP rides ICMPv6 over IPv6: the solicitation is a Neighbor Solicitation
        # (type 135) from the stimulus link-local address to the target's
        # solicited-node multicast group, carrying a Source Link-Layer Address
        # option.
        self.assertEqual(plan["ip_version"], 6)
        self.assertEqual(plan["icmpv6_type"], 135)
        self.assertEqual(plan["icmpv6_code"], 0)
        self.assertTrue(_is_link_local(plan["source_ipv6"]))
        self.assertTrue(_is_link_local(plan["target_ipv6"]))
        self.assertTrue(_is_documentation_mac(plan["source_link_layer_addr"]))
        self.assertEqual(plan["ethernet_source"], plan["source_link_layer_addr"])

        # The destination is the solicited-node multicast address derived from the
        # target's low 24 bits (RFC 4291 section 2.7.1: ff02::1:ffXX:XXXX).
        expected_solicited = _solicited_node(plan["target_ipv6"])
        self.assertEqual(plan["destination_ipv6"], expected_solicited)
        self.assertEqual(plan["solicited_node_multicast"], expected_solicited)
        self.assertTrue(plan["destination_ipv6"].startswith("ff02::1:ff"))

        # The reply is expected from the target back to the stimulus.
        self.assertEqual(plan["expected_reply_source_ipv6"], plan["target_ipv6"])
        self.assertEqual(plan["expected_reply_destination_ipv6"], plan["source_ipv6"])

    def test_validation_contract_covers_neighbor_advertisement(self) -> None:
        plan = _ndp_neighbor_solicitation_plan()
        validation = plan["validation"]

        # The expected reply is a solicited Neighbor Advertisement (type 136) with
        # R=0, S=1, O=1 — the IPv6 is-at analog.
        self.assertEqual(validation["icmpv6_type"], 136)
        self.assertFalse(validation["router_flag"])
        self.assertTrue(validation["solicited_flag"])
        self.assertTrue(validation["override_flag"])

        # The advertisement resolves the target: its target address is the
        # solicited address, and the Target Link-Layer Address option carries the
        # target endpoint's documentation MAC.
        self.assertEqual(validation["target_ipv6"], plan["target_ipv6"])
        self.assertTrue(_is_documentation_mac(validation["target_link_layer_addr"]))
        self.assertEqual(
            validation["target_link_layer_addr"],
            plan["target_service"]["target_hardware_addr"],
        )
        self.assertEqual(validation["source_ipv6"], plan["target_ipv6"])
        self.assertEqual(validation["destination_ipv6"], plan["source_ipv6"])

        # The typed key the Rust ``ndp`` module reads mirrors ``validation``.
        self.assertEqual(plan["ndp_validation"], validation)

    def test_capture_filter_is_icmpv6_neighbor_advertisement(self) -> None:
        plan = _ndp_neighbor_solicitation_plan()
        # NDP cannot be selected by host/IP BPF on the multicast group alone:
        # match ICMPv6 plus the Neighbor Advertisement type (ip6[40] == 136).
        self.assertEqual(plan["capture_filter"], "icmp6 and ip6[40] = 136")

    def test_target_service_is_the_ndp_answering_kernel(self) -> None:
        plan = _ndp_neighbor_solicitation_plan()
        target_service = plan["target_service"]
        self.assertTrue(target_service["required"])
        self.assertEqual(target_service["kind"], "ndp-kernel")
        self.assertEqual(target_service["layer"], "network")
        # The kernel answers a Neighbor Solicitation for its own configured
        # address; setup configures the link-local address and flushes the
        # neighbor cache.
        self.assertEqual(target_service["target_ipv6"], plan["target_ipv6"])
        self.assertTrue(target_service["ndp_sysctls"])
        self.assertTrue(target_service["neighbor_cache_flush"])

    def test_wire_requirements_gate_on_ipv6_multicast(self) -> None:
        plan = _ndp_neighbor_solicitation_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_ipv6_multicast"])

    def test_case_gates_on_ipv6_multicast_capability(self) -> None:
        case = planning.PROBE_CASE_BY_NAME["ndp-neighbor-solicitation"]
        self.assertIn("link_layer_send", case.required_capabilities)
        self.assertIn("link_layer_capture", case.required_capabilities)
        self.assertIn("ipv6_multicast", case.required_capabilities)


class NdpNeighborSolicitationTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "ndp-neighbor-solicitation",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1050,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("ndp-neighbor-solicitation", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "ndp-neighbor-solicitation"
            ]
            self.assertTrue(
                results, "endpoint emitted no ndp-neighbor-solicitation result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                # A planned dry-run carries the compiled stimulus frame bytes: an
                # Ethernet/IPv6/ICMPv6 Neighbor Solicitation. The ethertype is IPv6
                # (0x86dd), the IPv6 next header is ICMPv6 (58), and the ICMPv6 type
                # byte (ip6[40], i.e. frame offset 54) is the NS type (135).
                self.assertTrue(metadata.get("sent_raw_hex"))
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertGreaterEqual(len(frame), 14 + 40 + 24)
                self.assertEqual(frame[12:14], (0x86DD).to_bytes(2, "big"))
                self.assertEqual(frame[14 + 6], 58)
                self.assertEqual(frame[14 + 40], 135)
                # The Ethernet destination is the IPv6-multicast 33:33 mapping
                # (RFC 2464).
                self.assertEqual(frame[0:2], b"\x33\x33")

    def test_provider_without_link_layer_skips(self) -> None:
        # Hetzner cannot provide an L2/IPv6-multicast segment, so the case skips
        # with a stable capability reason rather than planning a stimulus.
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "ndp-neighbor-solicitation",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1050,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            ndp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "ndp-neighbor-solicitation"
            ]
            self.assertTrue(
                ndp_skips, "expected ndp-neighbor-solicitation to skip on hetzner"
            )


# --- ndp-router-solicitation (needs an RA-emitting router target) --------------


def _ndp_router_solicitation_plan(*, seed: int = 1051, sequence: int = 0) -> dict:
    return _ndp_plan("ndp-router-solicitation", seed=seed, sequence=sequence)


class NdpRouterSolicitationPlanTest(unittest.TestCase):
    """The plan solicits a Router Advertisement from an RA-emitting router."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("ndp-router-solicitation", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["ndp-router-solicitation"],
            planning._ndp_router_solicitation_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(
            _ndp_router_solicitation_plan(), _ndp_router_solicitation_plan()
        )

    def test_plan_carries_an_all_routers_router_solicitation(self) -> None:
        plan = _ndp_router_solicitation_plan()

        self.assertEqual(plan["case"], "ndp-router-solicitation")
        self.assertEqual(plan["stimulus"], "ndp_router_solicitation")
        self.assertEqual(plan["expected_response"], "ndp_router_advertisement")

        # A Router Solicitation (type 133) from the stimulus link-local address to
        # the all-routers multicast group (ff02::2).
        self.assertEqual(plan["icmpv6_type"], 133)
        self.assertTrue(_is_link_local(plan["source_ipv6"]))
        self.assertEqual(plan["destination_ipv6"], "ff02::2")
        self.assertEqual(plan["all_routers_multicast"], "ff02::2")
        self.assertTrue(_is_documentation_mac(plan["source_link_layer_addr"]))

    def test_plan_records_router_target_requirement(self) -> None:
        plan = _ndp_router_solicitation_plan()
        # A bare kernel does not answer a Router Solicitation; the case needs the
        # target to act as an RA-emitting router. The plan and the target service
        # record this so live runners configure a router or skip the case.
        self.assertTrue(plan["requires_router_target"])
        target_service = plan["target_service"]
        self.assertEqual(target_service["kind"], "ndp-router")
        self.assertTrue(target_service["router_advertisements"])
        self.assertTrue(target_service["requires_router_target"])

        # The catalog case carries the notes/metadata documenting the router
        # requirement.
        case = planning.PROBE_CASE_BY_NAME["ndp-router-solicitation"]
        self.assertTrue(case.metadata.get("requires_router_target"))
        self.assertIn("router", str(case.metadata.get("notes", "")).lower())

    def test_validation_contract_covers_router_advertisement(self) -> None:
        plan = _ndp_router_solicitation_plan()
        validation = plan["validation"]
        self.assertEqual(validation["icmpv6_type"], 134)
        self.assertEqual(validation["source_ipv6"], plan["expected_reply_source_ipv6"])
        self.assertEqual(plan["ndp_validation"], validation)

    def test_capture_filter_is_icmpv6_router_advertisement(self) -> None:
        plan = _ndp_router_solicitation_plan()
        self.assertEqual(plan["capture_filter"], "icmp6 and ip6[40] = 134")

    def test_wire_requirements_gate_on_ipv6_multicast(self) -> None:
        plan = _ndp_router_solicitation_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_ipv6_multicast"])


class NdpRouterSolicitationTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "ndp-router-solicitation",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1051,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("ndp-router-solicitation", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "ndp-router-solicitation"
            ]
            self.assertTrue(
                results, "endpoint emitted no ndp-router-solicitation result"
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))
                # An Ethernet/IPv6/ICMPv6 Router Solicitation (type 133) to the
                # all-routers multicast group.
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertEqual(frame[12:14], (0x86DD).to_bytes(2, "big"))
                self.assertEqual(frame[14 + 6], 58)
                self.assertEqual(frame[14 + 40], 133)
                # The plan echoed back records the router-target requirement.
                plan = metadata.get("probe_plan", {})
                self.assertTrue(plan.get("requires_router_target"))

    def test_provider_without_link_layer_skips(self) -> None:
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "ndp-router-solicitation",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1051,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            ndp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "ndp-router-solicitation"
            ]
            self.assertTrue(
                ndp_skips, "expected ndp-router-solicitation to skip on hetzner"
            )


# --- ndp-duplicate-address-detection (unspecified-source DAD probe) ------------


def _ndp_dad_plan(*, seed: int = 1052, sequence: int = 0) -> dict:
    return _ndp_plan("ndp-duplicate-address-detection", seed=seed, sequence=sequence)


class NdpDuplicateAddressDetectionPlanTest(unittest.TestCase):
    """The DAD probe is sourced from :: and validates a defending NA."""

    def test_plan_uses_dedicated_builder(self) -> None:
        self.assertIn("ndp-duplicate-address-detection", planning.PLAN_BUILDERS)
        self.assertIs(
            planning.PLAN_BUILDERS["ndp-duplicate-address-detection"],
            planning._ndp_duplicate_address_detection_probe_plan,
        )

    def test_plan_is_deterministic(self) -> None:
        self.assertEqual(_ndp_dad_plan(), _ndp_dad_plan())

    def test_plan_carries_an_unspecified_source_dad_solicitation(self) -> None:
        plan = _ndp_dad_plan()

        self.assertEqual(plan["case"], "ndp-duplicate-address-detection")
        self.assertEqual(plan["stimulus"], "ndp_duplicate_address_detection")
        self.assertEqual(plan["expected_response"], "ndp_neighbor_advertisement")

        # DAD: a Neighbor Solicitation (type 135) for an owned address, sourced
        # from the unspecified address (::) with NO Source Link-Layer Address
        # option (RFC 4861 section 4.3), addressed to the solicited-node group.
        self.assertEqual(plan["icmpv6_type"], 135)
        self.assertEqual(plan["source_ipv6"], "::")
        self.assertTrue(plan["dad"])
        self.assertTrue(plan["omit_source_link_layer_addr"])
        self.assertNotIn("source_link_layer_addr", plan)
        self.assertTrue(_is_link_local(plan["target_ipv6"]))
        self.assertEqual(
            plan["destination_ipv6"], _solicited_node(plan["target_ipv6"])
        )

    def test_validation_contract_covers_defending_advertisement(self) -> None:
        plan = _ndp_dad_plan()
        validation = plan["validation"]
        # A DAD defense Neighbor Advertisement is sent to all-nodes (ff02::1) with
        # O set and S clear (RFC 4862 section 5.4.3).
        self.assertEqual(validation["icmpv6_type"], 136)
        self.assertFalse(validation["solicited_flag"])
        self.assertTrue(validation["override_flag"])
        self.assertEqual(validation["target_ipv6"], plan["target_ipv6"])
        self.assertEqual(validation["destination_ipv6"], "ff02::1")
        self.assertEqual(plan["expected_reply_destination_ipv6"], "ff02::1")
        self.assertEqual(plan["ndp_validation"], validation)

    def test_target_service_defends_the_owned_address(self) -> None:
        plan = _ndp_dad_plan()
        target_service = plan["target_service"]
        self.assertEqual(target_service["kind"], "ndp-kernel")
        self.assertTrue(target_service["defends_address"])
        self.assertEqual(target_service["target_ipv6"], plan["target_ipv6"])

    def test_wire_requirements_gate_on_ipv6_multicast(self) -> None:
        plan = _ndp_dad_plan()
        requirements = plan["wire_requirements"]
        self.assertTrue(requirements["requires_link_layer_send"])
        self.assertTrue(requirements["requires_link_layer_capture"])
        self.assertTrue(requirements["requires_ipv6_multicast"])


class NdpDuplicateAddressDetectionTest(unittest.TestCase):
    """End-to-end focused acceptance through planner and stimulus endpoint."""

    def test_focused_case_drives_planner_and_stimulus_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            outcome = probe_acceptance.assert_focused_case(
                self,
                "ndp-duplicate-address-detection",
                out_dir=Path(temp_dir) / "harness",
                provider="qemu",
                profile="behavior",
                seed=1052,
            )

            self.assertEqual(outcome.report.get("status"), "dry-run")
            planned = outcome.report.get("metadata", {}).get("planned_case_names", [])
            self.assertIn("ndp-duplicate-address-detection", planned)

            results = [
                result
                for result in outcome.response.get("results", [])
                if result.get("case") == "ndp-duplicate-address-detection"
            ]
            self.assertTrue(
                results,
                "endpoint emitted no ndp-duplicate-address-detection result",
            )
            for result in results:
                metadata = result.get("metadata", {})
                self.assertTrue(metadata.get("dry_run"))
                self.assertTrue(metadata.get("sent_raw_hex"))
                # The DAD solicitation is an Ethernet/IPv6/ICMPv6 Neighbor
                # Solicitation (type 135) with the IPv6 source set to the
                # unspecified address (::, all-zero in the IPv6 source field at
                # frame offset 14 + 8 .. 14 + 24).
                frame = bytes.fromhex(metadata["sent_raw_hex"])
                self.assertEqual(frame[12:14], (0x86DD).to_bytes(2, "big"))
                self.assertEqual(frame[14 + 40], 135)
                self.assertEqual(frame[14 + 8 : 14 + 24], b"\x00" * 16)
                plan = metadata.get("probe_plan", {})
                self.assertTrue(plan.get("dad"))

    def test_provider_without_link_layer_skips(self) -> None:
        if not probe_acceptance.probe_run_available():
            self.skipTest("probe runner requires uv on PATH")
        with tempfile.TemporaryDirectory() as temp_dir:
            out_dir = Path(temp_dir) / "hetzner"
            report_path = probe_acceptance._run_probe_dry_run(
                "ndp-duplicate-address-detection",
                out_dir=out_dir,
                provider="hetzner",
                profile="behavior",
                seed=1052,
                count=1,
                timeout_seconds=600,
            )
            report = probe_acceptance._load_json(report_path)
            skips = report.get("skips", [])
            ndp_skips = [
                skip
                for skip in skips
                if skip.get("case") == "ndp-duplicate-address-detection"
            ]
            self.assertTrue(
                ndp_skips,
                "expected ndp-duplicate-address-detection to skip on hetzner",
            )


def _solicited_node(unicast_ipv6: str) -> str:
    """Reference solicited-node multicast for an IPv6 address (RFC 4291 2.7.1)."""

    packed = ipaddress.ip_address(unicast_ipv6).packed
    prefix = bytes.fromhex("ff0200000000000000000001ff000000")
    solicited = bytearray(prefix)
    solicited[13:16] = packed[13:16]
    return str(ipaddress.IPv6Address(bytes(solicited)))


if __name__ == "__main__":
    unittest.main()
