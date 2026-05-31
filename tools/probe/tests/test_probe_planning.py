"""Unit coverage for deterministic probe selection and plan generation."""

from __future__ import annotations

import unittest

from tools.probe.engine import cases as probe_cases
from tools.probe.engine import cli
from tools.probe.engine import planning
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
            self.assertNotIn("planned_only", plan)

    def test_dispatch_falls_back_to_planned_only_for_unregistered_case(self) -> None:
        request = _request()
        for case in probe_cases.PROBE_CASES:
            plan = planning.probe_plan_for_case(request=request, case=case, sequence=0)
            self.assertEqual(plan["case"], case.name)
            if case.name in planning.PLAN_BUILDERS:
                self.assertNotIn("planned_only", plan)
            else:
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


if __name__ == "__main__":
    unittest.main()
