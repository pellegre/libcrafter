"""Unit coverage for deterministic probe selection and plan generation."""

from __future__ import annotations

import unittest

from tools.probe.engine import cases as probe_cases
from tools.probe.engine import capabilities
from tools.probe.engine import cli
from tools.probe.engine import planning
from tools.probe.engine.lab import probe_capabilities_from_lab_capabilities
from tools.probe.engine.model import ProbeRunRequest


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": "smoke",
        "seed": 2,
        "count": 6,
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


_IGMP_LINK_LAYER_SUBSTRATE = {
    "provider": "qemu",
    "ipv4_unicast": True,
    "controlled_services": True,
    "link_layer_send": True,
    "link_layer_capture": True,
    "broadcast": True,
    "provider_mac_known": True,
    "controlled_router": False,
    "live_packet_exchange": True,
}

_IGMP_L3_ONLY_SUBSTRATE = {
    "provider": "hetzner",
    "ipv4_unicast": True,
    "controlled_services": True,
    "link_layer_send": False,
    "link_layer_capture": False,
    "broadcast": False,
    "provider_mac_known": False,
    "controlled_router": False,
    "live_packet_exchange": True,
}


class ProbePlanningSelectionTest(unittest.TestCase):
    def test_planned_cases_empty_selection_returns_empty(self) -> None:
        self.assertEqual(planning.planned_cases([], seed=1, count=5), [])

    def test_planned_cases_cycles_to_requested_count(self) -> None:
        selected = list(probe_cases.PROBE_CASES[:2])
        planned = planning.planned_cases(selected, seed=0, count=5)

        self.assertEqual(len(planned), 5)
        self.assertEqual(
            [case.name for case in planned],
            [selected[index % 2].name for index in range(5)],
        )

    def test_planned_cases_seed_rotates_starting_offset(self) -> None:
        selected = list(probe_cases.PROBE_CASES)
        zero = planning.planned_cases(selected, seed=0, count=len(selected))
        offset = len(selected) // 2 if len(selected) > 1 else 0
        shifted = planning.planned_cases(selected, seed=offset, count=len(selected))

        self.assertEqual(zero[0].name, selected[0].name)
        self.assertEqual(shifted[0].name, selected[offset % len(selected)].name)

    def test_planned_cases_matches_legacy_cli_alias(self) -> None:
        selected = list(probe_cases.PROBE_CASES)
        self.assertIs(cli._planned_cases, planning.planned_cases)
        self.assertEqual(
            cli._planned_cases(selected, seed=2, count=6),
            planning.planned_cases(selected, seed=2, count=6),
        )


class ProbePlanningDispatchTest(unittest.TestCase):
    def test_probe_plans_for_cases_is_deterministic(self) -> None:
        request = _request()
        selected = probe_cases.selected_cases(request.case_names)
        planned = planning.planned_cases(
            selected,
            seed=request.seed,
            count=request.count,
        )

        first = planning.probe_plans_for_cases(request, planned)
        second = planning.probe_plans_for_cases(request, planned)

        self.assertEqual(first, second)
        self.assertEqual(len(first), request.count)
        for sequence, plan in enumerate(first):
            self.assertEqual(plan["sequence"], sequence)
            self.assertEqual(plan["index"], sequence)
            self.assertEqual(plan["profile"], request.profile)
            self.assertEqual(plan["seed"], request.seed)

    def test_dispatch_routes_each_registered_case_to_its_builder(self) -> None:
        request = _request()
        for name in planning.PLAN_BUILDERS:
            case = probe_cases.PROBE_CASE_BY_NAME[name]
            plan = planning.probe_plan_for_case(request=request, case=case, sequence=0)
            self.assertEqual(plan["case"], case.name)
            # The IPSec cases are registered but intentionally planned-only until
            # their crate stimulus builders land (later probe steps); every other
            # registered builder produces a fully materialized plan.
            if name in planning.PLANNED_ONLY_REGISTERED_CASES:
                self.assertIs(plan["planned_only"], True, name)
            else:
                self.assertNotIn("planned_only", plan)

    def test_dispatch_falls_back_to_planned_only_for_unregistered_case(self) -> None:
        request = _request()
        for case in probe_cases.PROBE_CASES:
            plan = planning.probe_plan_for_case(request=request, case=case, sequence=0)
            self.assertEqual(plan["case"], case.name)
            if (
                case.name in planning.PLAN_BUILDERS
                and case.name not in planning.PLANNED_ONLY_REGISTERED_CASES
            ):
                self.assertNotIn("planned_only", plan)
            else:
                # Unregistered cases use the planned-only fallback; the IPSec
                # cases are registered but deliberately planned-only.
                self.assertIs(plan["planned_only"], True)

    def test_icmp_plan_shape_is_stable(self) -> None:
        plan = planning.probe_plan_for_case(
            request=_request(),
            case=probe_cases.PROBE_CASE_BY_NAME["icmp-echo"],
            sequence=0,
        )

        self.assertEqual(plan["stimulus"], "icmp_echo_request")
        self.assertEqual(plan["expected_response"], "icmp_echo_reply")
        self.assertEqual(plan["validation"]["icmp_type"], 0)
        self.assertEqual(plan["validation"]["icmp_code"], 0)
        self.assertEqual(plan["payload_hex"], plan["validation"]["payload_hex"])
        self.assertEqual(
            plan["capture_filter"],
            f"icmp and src host {plan['destination_ipv4']} "
            f"and dst host {plan['source_ipv4']}",
        )

    def test_tcp_open_and_closed_plans_diverge(self) -> None:
        open_plan = planning.probe_plan_for_case(
            request=_request(),
            case=probe_cases.PROBE_CASE_BY_NAME["tcp-syn-open"],
            sequence=0,
        )
        closed_plan = planning.probe_plan_for_case(
            request=_request(),
            case=probe_cases.PROBE_CASE_BY_NAME["tcp-syn-closed"],
            sequence=0,
        )

        self.assertEqual(open_plan["expected_response"], "tcp_syn_ack")
        self.assertEqual(open_plan["validation"]["flags"], ["syn", "ack"])
        self.assertTrue(open_plan["target_service"]["required"])
        self.assertEqual(closed_plan["expected_response"], "tcp_rst")
        self.assertEqual(closed_plan["validation"]["flags"], ["rst"])
        self.assertTrue(closed_plan["validation"]["allow_rst_ack"])

    def test_dns_plan_carries_question_and_answer(self) -> None:
        plan = planning.probe_plan_for_case(
            request=_request(),
            case=probe_cases.PROBE_CASE_BY_NAME["dns-query"],
            sequence=0,
        )

        self.assertEqual(plan["destination_port"], 53)
        self.assertEqual(plan["query_name"], plan["validation"]["question"]["name"])
        self.assertEqual(plan["expected_answer_data"], plan["validation"]["answer"]["data"])
        self.assertTrue(plan["validation"]["qr"])

    def test_ttl_plan_targets_controlled_router(self) -> None:
        plan = planning.probe_plan_for_case(
            request=_request(),
            case=probe_cases.PROBE_CASE_BY_NAME["ttl-expired"],
            sequence=0,
        )

        self.assertEqual(plan["ttl"], 1)
        self.assertEqual(plan["expected_icmp_type"], 11)
        self.assertEqual(plan["validation"]["source_ipv4"], plan["controlled_router_ipv4"])

    def test_arp_plan_records_link_layer_requirements(self) -> None:
        plan = planning.probe_plan_for_case(
            request=_request(),
            case=probe_cases.PROBE_CASE_BY_NAME["arp-resolution"],
            sequence=0,
        )

        self.assertEqual(plan["ethertype"], 0x0806)
        self.assertEqual(plan["validation"]["operation"], 2)
        self.assertTrue(plan["wire_requirements"]["requires_link_layer_send"])
        self.assertTrue(plan["wire_requirements"]["requires_broadcast"])


class ProbePlanningRegistryTest(unittest.TestCase):
    def test_register_plan_builder_rejects_unknown_case(self) -> None:
        with self.assertRaises(ValueError):
            planning.register_plan_builder("not-a-real-case", lambda **_: {})

    def test_registered_cases_resolve_through_dispatch_not_fallback(self) -> None:
        request = _request()
        for name in planning.PLAN_BUILDERS:
            case = probe_cases.PROBE_CASE_BY_NAME[name]
            plan = planning.probe_plan_for_case(
                request=request,
                case=case,
                sequence=1,
            )
            if name in planning.PLANNED_ONLY_REGISTERED_CASES:
                # Planned-only builders route through the dispatcher (not the
                # bare fallback): they still emit builder-specific shape.
                self.assertIs(plan["planned_only"], True, name)
                if name == "bgp-session-smoke":
                    self.assertEqual(plan["stimulus"], "bgp_session", name)
                    self.assertEqual(
                        plan["target_service"]["kind"],
                        "frr-bgp-peer",
                        name,
                    )
                    self.assertEqual(
                        plan["target_service"]["provision_script"],
                        "tools/probe/target_services/bgp/provision-peer.sh",
                        name,
                    )
                elif name == "rip-update-v2":
                    self.assertEqual(plan["stimulus"], "rip_request", name)
                    self.assertEqual(plan["destination_port"], 520, name)
                    self.assertEqual(plan["multicast_group"], "224.0.0.9", name)
                    self.assertEqual(
                        plan["target_service"]["kind"],
                        "frr-ripd",
                        name,
                    )
                    self.assertEqual(
                        plan["target_service"]["rib_command"],
                        "vtysh -c 'show ip rip'",
                        name,
                    )
                elif name == "ripng-update":
                    self.assertEqual(plan["stimulus"], "ripng_request", name)
                    self.assertEqual(plan["destination_port"], 521, name)
                    self.assertEqual(plan["multicast_group"], "ff02::9", name)
                    self.assertEqual(
                        plan["target_service"]["kind"],
                        "frr-ripngd",
                        name,
                    )
                    self.assertEqual(
                        plan["target_service"]["rib_command"],
                        "vtysh -c 'show ipv6 ripng'",
                        name,
                    )
                else:
                    self.assertIn("ipsec_protocol", plan, name)
                    self.assertIn("stimulus_packet_shape", plan, name)
            else:
                self.assertNotIn("planned_only", plan, name)

    def test_cli_reexports_planning_for_backward_compatibility(self) -> None:
        self.assertIs(cli._planned_cases, planning.planned_cases)
        self.assertIs(cli._probe_plans_for_cases, planning.probe_plans_for_cases)
        self.assertIs(cli._probe_plan_for_case, planning.probe_plan_for_case)
        self.assertIs(cli._deterministic_bytes, planning.deterministic_bytes)
        self.assertIs(cli._deterministic_ipv4_pair, planning.deterministic_ipv4_pair)
        self.assertIs(cli._deterministic_router_ipv4, planning.deterministic_router_ipv4)
        self.assertIs(cli._dns_label, planning.dns_label)
        self.assertIs(cli._dns_query_name, planning.dns_query_name)
        self.assertIs(
            cli._deterministic_documentation_mac,
            planning.deterministic_documentation_mac,
        )


class IgmpProbePlanningTest(unittest.TestCase):
    def _igmp_plan(self, case_name: str, *, sequence: int = 0) -> dict:
        return planning.probe_plan_for_case(
            request=_request(profile="igmp", count=len(probe_cases.IGMP_PROFILE_CASE_NAMES)),
            case=probe_cases.PROBE_CASE_BY_NAME[case_name],
            sequence=sequence,
        )

    def test_igmp_membership_query_observation_plan_is_dry_run_only(self) -> None:
        plan = self._igmp_plan("igmp-membership-query-observation")

        self.assertEqual(plan["protocol"], "igmp")
        self.assertEqual(plan["ip_protocol"], 2)
        self.assertEqual(plan["ttl"], 1)
        self.assertTrue(plan["router_alert_required"])
        self.assertIs(plan["planned_only"], True)
        self.assertEqual(plan["destination_ipv4"], "224.0.0.1")
        self.assertEqual(plan["stimulus_packet_shape"]["igmp"]["igmp_type"], 0x11)
        self.assertEqual(
            plan["target_service"]["provision_script"],
            "tools/probe/target_services/igmp/provision-router.sh",
        )
        self.assertIn("igmp and src host", plan["capture_filter"])
        self.assertNotIn("payload_hex", plan)
        self.assertNotIn("packet_hex", plan)

    def test_igmp_report_leave_and_v3_source_list_plans(self) -> None:
        report = self._igmp_plan("igmp-v2-membership-report-emission")
        leave = self._igmp_plan("igmp-v2-leave-group-emission")
        v3 = self._igmp_plan("igmp-v3-source-list-report")

        self.assertEqual(report["stimulus_packet_shape"]["igmp"]["igmp_type"], 0x16)
        self.assertEqual(report["destination_ipv4"], report["group_address"])
        self.assertEqual(leave["stimulus_packet_shape"]["igmp"]["igmp_type"], 0x17)
        self.assertEqual(leave["destination_ipv4"], "224.0.0.2")
        self.assertEqual(v3["stimulus_packet_shape"]["igmp"]["igmp_type"], 0x22)
        self.assertEqual(v3["destination_ipv4"], "224.0.0.22")
        self.assertEqual(v3["validation"]["record_type"], "mode_is_include")
        self.assertEqual(v3["validation"]["record_count"], 1)
        self.assertEqual(len(v3["validation"]["source_addresses"]), 2)
        for plan in (report, leave, v3):
            self.assertEqual(
                plan["target_service"]["provision_script"],
                "tools/probe/target_services/igmp/provision-listener.sh",
            )
            self.assertTrue(plan["wire_requirements"]["requires_provider_backing"])
            self.assertTrue(plan["wire_requirements"]["requires_confirm_live_run"])
            self.assertNotIn("payload_hex", plan)
            self.assertNotIn("packet_hex", plan)

    def test_igmp_planning_is_deterministic(self) -> None:
        first = self._igmp_plan("igmp-v3-source-list-report", sequence=3)
        second = self._igmp_plan("igmp-v3-source-list-report", sequence=3)

        self.assertEqual(first, second)
        self.assertEqual(first["group_address"].split(".")[:3], ["233", "252", "0"])

    def test_igmp_unsupported_provider_skips_with_stable_reason(self) -> None:
        case = probe_cases.PROBE_CASE_BY_NAME["igmp-v2-membership-report-emission"]
        derived = probe_capabilities_from_lab_capabilities(
            "hetzner",
            _IGMP_L3_ONLY_SUBSTRATE,
            dry_run=True,
        )

        self.assertEqual(capabilities.missing_capabilities(case, derived)[0], "ipv4_multicast")
        self.assertEqual(
            capabilities.skip_reason_for_missing_capability(case, "ipv4_multicast"),
            capabilities.SKIP_REQUIRES_IPV4_MULTICAST,
        )

    def test_igmp_link_layer_provider_grants_required_capabilities(self) -> None:
        case = probe_cases.PROBE_CASE_BY_NAME["igmp-v3-source-list-report"]
        derived = probe_capabilities_from_lab_capabilities(
            "qemu",
            _IGMP_LINK_LAYER_SUBSTRATE,
            dry_run=True,
        )

        self.assertTrue(derived["ipv4_multicast"])
        self.assertTrue(derived["igmp_peer"])
        self.assertEqual(capabilities.missing_capabilities(case, derived), [])

    def test_igmp_failure_reasons_are_reported(self) -> None:
        reasons = cli._failure_reasons_for_case("igmp-v3-source-list-report")

        self.assertIn("timeout", reasons)
        self.assertIn("wrong_peer", reasons)
        self.assertIn("wrong_payload", reasons)
        self.assertIn("decode_failed", reasons)
        self.assertIn("target_setup_failed", reasons)


if __name__ == "__main__":
    unittest.main()
