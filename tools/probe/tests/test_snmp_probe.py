"""Offline unit coverage for the SNMP probe profile and dry-run plans."""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import cases as probe_cases
from tools.probe.engine import planning
from tools.probe.engine.model import ProbeRunRequest


SNMP_SMOKE_PROFILE = "snmp-smoke"
SNMP_GET_CASE = "snmp-get-response"
SNMP_TRAP_CASE = "snmp-notification-trap"


def _request(**overrides: object) -> ProbeRunRequest:
    base = {
        "provider": "local-dry-run",
        "profile": SNMP_SMOKE_PROFILE,
        "seed": 1,
        "count": 4,
        "case_names": [],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _snmp_plan(case_name: str = SNMP_GET_CASE, *, sequence: int = 0) -> dict:
    case = probe_cases.PROBE_CASE_BY_NAME[case_name]
    return planning.probe_plan_for_case(
        request=_request(),
        case=case,
        sequence=sequence,
    )


class SnmpProbeProfileTest(unittest.TestCase):
    def test_snmp_smoke_profile_is_registered(self) -> None:
        self.assertIn(SNMP_SMOKE_PROFILE, probe_cases.known_profiles())

    def test_snmp_cases_require_snmp_peer_capability(self) -> None:
        names = probe_cases.profile_case_names(SNMP_SMOKE_PROFILE)
        assert names is not None
        for name in names:
            case = probe_cases.PROBE_CASE_BY_NAME[name]
            with self.subTest(case=name):
                self.assertEqual(case.metadata["protocol"], "snmp")
                self.assertIn("snmp_peer", case.required_capabilities)


class SnmpProbePlanTest(unittest.TestCase):
    def test_get_plan_carries_agent_service_and_wire_shape(self) -> None:
        plan = _snmp_plan()

        self.assertEqual(plan["case"], SNMP_GET_CASE)
        self.assertEqual(plan["stimulus"], "snmp_get_request")
        self.assertEqual(plan["protocol"], "snmp")
        self.assertEqual(plan["destination_port"], 161)
        self.assertEqual(plan["snmp_request"]["pdu"], "get_request")
        self.assertEqual(plan["expected_snmp_response"]["pdu"], "response")
        self.assertEqual(plan["target_service"]["kind"], "snmp-controlled-peer")
        self.assertEqual(plan["target_service"]["service_mode"], "agent")

    def test_trap_plan_uses_notification_port(self) -> None:
        plan = _snmp_plan(SNMP_TRAP_CASE)

        self.assertEqual(plan["destination_port"], 162)
        self.assertEqual(plan["target_service"]["service_mode"], "notification_sink")
        self.assertEqual(plan["validation"]["response_pdu"], "notification_observed")

    def test_snmp_plans_are_planned_only_and_send_nothing(self) -> None:
        names = probe_cases.profile_case_names(SNMP_SMOKE_PROFILE)
        assert names is not None
        for name in names:
            with self.subTest(case=name):
                plan = _snmp_plan(name)
                self.assertIs(plan["planned_only"], True)
                self.assertIs(plan["stimulus_driver"]["planned_only"], True)
                self.assertIs(plan["validation"]["planned_only"], True)
                self.assertNotIn("payload_hex", plan)
                self.assertNotIn("packet_hex", plan)

    def test_snmp_plan_uses_documentation_addresses(self) -> None:
        plan = _snmp_plan()
        documentation = ipaddress.ip_network("198.51.100.0/24")

        self.assertEqual(plan["documentation_prefixes"], ["198.51.100.0/24"])
        for key in ("source_ipv4", "destination_ipv4"):
            self.assertIn(ipaddress.ip_address(plan[key]), documentation)


if __name__ == "__main__":
    unittest.main()
