"""Guarded live behavior-suite coverage.

The full DNS/DHCP/ARP/UDP behavior suite must stay dry-run safe by default, but
when a live provider is explicitly selected it must route through the protected
lab-backed execution path. These tests pin that command contract and the target
setup pieces required by the supported live cases.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.probe.engine import cli, target_services
from tools.probe.engine.model import JSONObject, ProbeReport, ProbeRunRequest
from tools.probe.engine.report import REPO_ROOT


SEED = 1051
COUNT = 40


def _behavior_request(*, dry_run: bool) -> ProbeRunRequest:
    return ProbeRunRequest(
        provider="qemu",
        profile="behavior",
        seed=SEED,
        count=COUNT,
        case_names=[],
        dry_run=dry_run,
        confirm_live_run=not dry_run,
    )


def _planned_behavior(
    *,
    dry_run: bool,
) -> tuple[ProbeRunRequest, list[object], list[object], list[JSONObject]]:
    request = _behavior_request(dry_run=dry_run)
    selected = cli._profile_selected_cases(request.profile, request.case_names)
    planned = cli._planned_cases(selected, seed=request.seed, count=request.count)
    probe_plans = cli._probe_plans_for_cases(request, planned)
    return request, selected, planned, probe_plans


def _dry_run_report_and_request() -> tuple[ProbeReport, JSONObject]:
    request, selected, planned, probe_plans = _planned_behavior(dry_run=True)
    with tempfile.TemporaryDirectory() as temp_dir:
        report_path = Path(temp_dir) / "report.json"
        report = cli._dry_run_report(
            request=request,
            selected_cases=selected,
            planned_cases=planned,
            probe_plans=probe_plans,
            report_path=report_path,
        )
        request_artifact = Path(str(report.artifacts[1]))
        endpoint_request = json.loads(request_artifact.read_text(encoding="utf-8"))
    return report, endpoint_request


class GuardedBehaviorCommandDocsTest(unittest.TestCase):
    def test_docs_show_env_guarded_behavior_suite_command(self) -> None:
        docs = (REPO_ROOT / "docs" / "probe.md").read_text(encoding="utf-8")
        self.assertIn("LIBCRAFTER_PROBE_LIVE_PROVIDER", docs)
        self.assertIn('--provider "$LIBCRAFTER_PROBE_LIVE_PROVIDER"', docs)
        self.assertIn("--confirm-live-run --profile behavior --seed 1051 --count 40", docs)
        self.assertIn("--provider qemu --dry-run --profile behavior --seed 1051 --count 40", docs)


class BehaviorDryRunSetupTest(unittest.TestCase):
    def test_full_behavior_dry_run_advertises_dhcp_and_arp_setup(self) -> None:
        report, endpoint_request = _dry_run_report_and_request()
        setup = report.metadata["target_service_setup"]

        self.assertEqual(report.metadata["planned_count"], COUNT)
        self.assertEqual(len(endpoint_request["probe_plans"]), COUNT)
        self.assertFalse(setup["starts_services"])
        self.assertFalse(setup["dry_run_starts_services"])

        services = setup["services"]
        self.assertTrue(any(service["name"] == "dns-responder" for service in services))
        self.assertTrue(any(service["name"] == "dhcp-responder" for service in services))
        self.assertTrue(any(service["name"] == "udp-responder" for service in services))

        dhcp_services = [
            service for service in services if service["name"] == "dhcp-responder"
        ]
        self.assertEqual(len(dhcp_services), 1)
        self.assertEqual(dhcp_services[0]["port"], 67)
        self.assertEqual(dhcp_services[0]["request_count"], 11)

        arp_state = setup["arp_kernel_state"]
        self.assertTrue(arp_state["planned"])
        self.assertEqual(arp_state["case_count"], 10)
        self.assertIn("arp-padding-reply", arp_state["cases"])
        self.assertIn("arp-alias-address-reply", arp_state["cases"])
        self.assertIn("arp-broadcast-filtered-capture", arp_state["cases"])
        self.assertTrue(arp_state["alias_addresses"])
        self.assertTrue(arp_state["alt_sender_addresses"])
        self.assertEqual(len(arp_state["decoy_events"]), 1)

    def test_live_setup_script_renders_dhcp_and_arp_blocks(self) -> None:
        _request, _selected, _planned, probe_plans = _planned_behavior(dry_run=True)
        script = target_services.target_service_setup_script(
            artifact_root="/root/libcrafter/artifacts/probe/target-services",
            bind_ipv4="10.77.0.20",
            open_ports=[],
            closed_ports=[],
            dns_plans=target_services.dns_probe_plans(probe_plans),
            dhcp_plans=target_services.dhcp_probe_plans(probe_plans),
            arp_plans=target_services.arp_probe_plans(probe_plans),
            udp_plans=target_services.udp_probe_plans(probe_plans),
            closed_udp_ports=[43217],
            target_interface="eth1",
        )

        self.assertIn("dhcp-responder.py", script)
        self.assertIn("echo dhcp_responder_67=running", script)
        self.assertIn("arp_kernel_state=configured", script)
        self.assertIn("target_interface=eth1", script)
        self.assertIn("arp-decoy-emitter.py", script)
        self.assertIn("check_udp_port_free \"$udp_bind_ipv4\" 43217", script)


class BehaviorLiveRoutingTest(unittest.TestCase):
    def test_confirmed_behavior_suite_routes_to_lab_live_helper(self) -> None:
        request, selected, planned, probe_plans = _planned_behavior(dry_run=False)
        sentinel = object()

        with mock.patch.object(
            cli,
            "_lab_endpoint_live_report",
            return_value=sentinel,
        ) as live_report:
            report = cli._guarded_live_report(
                request=request,
                selected_cases=selected,
                planned_cases=planned,
                probe_plans=probe_plans,
                report_path=Path("/tmp/probe-report.json"),
                status=cli.STATUS_UNSUPPORTED,
            )

        self.assertIs(report, sentinel)
        live_report.assert_called_once()
        self.assertEqual(live_report.call_args.kwargs["request"].profile, "behavior")
        self.assertEqual(len(live_report.call_args.kwargs["planned_cases"]), COUNT)

    def test_arp_live_rewrite_uses_provider_macs_when_available(self) -> None:
        _request, _selected, _planned, probe_plans = _planned_behavior(dry_run=False)
        arp_plan = next(
            plan for plan in probe_plans if plan["case"] == "arp-unicast-request-reply"
        )
        rewritten = cli._probe_plan_with_endpoint_addresses(
            arp_plan,
            source_ipv4="10.77.0.10",
            target_ipv4="10.77.0.20",
            source_mac="02:00:00:00:00:10",
            target_mac="02:00:00:00:00:20",
            target_interface="eth1",
            rewrite_source="lab_session",
        )

        self.assertEqual(rewritten["sender_hardware_addr"], "02:00:00:00:00:10")
        self.assertEqual(rewritten["ethernet_source"], "02:00:00:00:00:10")
        self.assertEqual(rewritten["ethernet_destination"], "02:00:00:00:00:20")
        self.assertEqual(
            rewritten["target_service"]["target_hardware_addr"],
            "02:00:00:00:00:20",
        )
        self.assertEqual(rewritten["target_service"]["interface"], "eth1")
        validation = rewritten["validation"]
        self.assertEqual(validation["sender_hardware_addr"], "02:00:00:00:00:20")
        self.assertEqual(validation["target_hardware_addr"], "02:00:00:00:00:10")
        self.assertEqual(validation["ethernet_source"], "02:00:00:00:00:20")
        self.assertEqual(validation["ethernet_destination"], "02:00:00:00:00:10")


if __name__ == "__main__":
    unittest.main()
