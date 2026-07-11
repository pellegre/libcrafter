"""Focused coverage for QUIC probe planning cases."""

from __future__ import annotations

import ipaddress
import unittest

from tools.probe.engine import cases, cli, planning, target_services
from tools.probe.engine.model import ProbeRunRequest


def _request(
    *,
    case_names: list[str] | None = None,
    **overrides: object,
) -> ProbeRunRequest:
    base = {
        "provider": "qemu",
        "profile": "quic-smoke",
        "seed": 9800,
        "count": 1,
        "case_names": case_names or ["quic-initial-udp-observation"],
        "dry_run": True,
    }
    base.update(overrides)
    return ProbeRunRequest(**base)  # type: ignore[arg-type]


def _plan(case_name: str, *, seed: int = 9800, sequence: int = 0) -> dict:
    return planning.probe_plan_for_case(
        request=_request(seed=seed, case_names=[case_name]),
        case=planning.PROBE_CASE_BY_NAME[case_name],
        sequence=sequence,
    )


class QuicProbeCatalogTest(unittest.TestCase):
    def test_quic_cases_are_registered_in_focused_profile(self) -> None:
        self.assertEqual(
            cases.QUIC_SMOKE_PROFILE_CASE_NAMES,
            (
                "quic-initial-udp-observation",
                "quic-version-negotiation-observation",
                "quic-retry-observation",
                "quic-stateless-reset-observation",
                "quic-protected-flow-plan",
            ),
        )
        self.assertEqual(cases.profile_default_count("quic-smoke"), 5)
        for case_name in cases.QUIC_SMOKE_PROFILE_CASE_NAMES:
            self.assertIn(case_name, cases.PROBE_CASE_BY_NAME)
            self.assertEqual(
                cases.PROBE_CASE_BY_NAME[case_name].metadata["protocol"],
                "quic",
            )


class QuicProbePlanTest(unittest.TestCase):
    def test_plan_builders_are_registered_with_identity(self) -> None:
        expected = {
            "quic-initial-udp-observation": planning._quic_initial_udp_observation_probe_plan,
            "quic-version-negotiation-observation": (
                planning._quic_version_negotiation_observation_probe_plan
            ),
            "quic-retry-observation": planning._quic_retry_observation_probe_plan,
            "quic-stateless-reset-observation": (
                planning._quic_stateless_reset_observation_probe_plan
            ),
            "quic-protected-flow-plan": planning._quic_protected_flow_plan_probe_plan,
        }
        for case_name, builder in expected.items():
            with self.subTest(case=case_name):
                self.assertIn(case_name, planning.PLAN_BUILDERS)
                self.assertIs(planning.PLAN_BUILDERS[case_name], builder)

    def test_initial_observation_plan_carries_quic_udp_payload(self) -> None:
        plan = _plan("quic-initial-udp-observation")

        self.assertEqual(plan["case"], "quic-initial-udp-observation")
        self.assertNotIn("planned_only", plan)
        ipaddress.IPv4Address(plan["source_ipv4"])
        ipaddress.IPv4Address(plan["destination_ipv4"])
        self.assertEqual(plan["destination_port"], 4433)
        self.assertEqual(plan["quic"]["packet_type"], "initial")
        self.assertEqual(plan["quic"]["version"], 1)
        self.assertEqual(
            plan["quic_payload_hex"],
            "c000000001048394c8f001aa000301beef",
        )
        self.assertEqual(plan["udp_payload_hex"], plan["quic_payload_hex"])
        self.assertEqual(plan["payload_hex"], plan["quic_payload_hex"])
        self.assertEqual(plan["expected_payload_hex"], plan["quic_payload_hex"])
        self.assertEqual(plan["quic_payload_length"], 17)
        self.assertEqual(plan["expected_udp_length"], 25)
        self.assertEqual(plan["target_service"]["kind"], "quic-controlled-udp")
        self.assertEqual(plan["target_service"]["behavior"], "echo_udp_payload")
        self.assertEqual(
            plan["stimulus_driver"]["adapter_module"],
            "tools/probe/adapters/src/quic.rs",
        )
        self.assertIn("udp", plan["capture_filter"])
        self.assertIn("quic-initial-udp-observation", cli._STIMULUS_ENDPOINT_CASES)

    def test_planned_only_cases_record_controlled_target_requirements(self) -> None:
        for case_name in cases.QUIC_SMOKE_PROFILE_CASE_NAMES[1:]:
            with self.subTest(case=case_name):
                plan = _plan(case_name)

                self.assertTrue(plan["planned_only"])
                self.assertTrue(plan["target_service"]["planned_only"])
                self.assertTrue(plan["stimulus_driver"]["planned_only"])
                self.assertEqual(plan["destination_port"], 4433)
                self.assertGreater(plan["quic_payload_length"], 0)
                self.assertTrue(plan["wire_requirements"]["requires_udp_service"])
                self.assertNotIn(case_name, cli._STIMULUS_ENDPOINT_CASES)

    def test_version_negotiation_plan_uses_zero_version_payload(self) -> None:
        plan = _plan("quic-version-negotiation-observation")

        self.assertEqual(plan["quic"]["packet_type"], "version_negotiation")
        self.assertEqual(plan["quic"]["version"], 0)
        self.assertTrue(plan["quic_payload_hex"].startswith("c000000000"))
        self.assertEqual(
            plan["target_service"]["behavior"],
            "observe_version_negotiation",
        )

    def test_protected_flow_plan_keeps_payload_opaque(self) -> None:
        plan = _plan("quic-protected-flow-plan")

        self.assertTrue(plan["planned_only"])
        self.assertTrue(plan["quic"]["encrypted_payload_opaque"])
        self.assertEqual(
            plan["target_service"]["kind"], "quic-controlled-endpoint"
        )
        self.assertEqual(
            plan["target_service"]["behavior"],
            "run_authenticated_client_server_flow",
        )
        self.assertEqual(
            plan["conversation"]["kind"],
            "stateful_authenticated_quic_endpoint_flow",
        )
        self.assertEqual(
            plan["conversation"]["distinct_from"],
            "quic-initial-udp-observation",
        )
        self.assertEqual(plan["conversation"]["version"], 1)
        self.assertEqual(plan["conversation"]["alpn"], "crafter-flow")
        self.assertEqual(
            plan["conversation"]["roles"],
            {
                "stimulus": "authenticated_quic_client",
                "target": "controlled_quic_server",
            },
        )
        self.assertEqual(
            plan["conversation"]["identity"],
            {
                "kind": "synthetic_test_identity",
                "provisioned_by": "controlled_target_service",
                "trust_installed_on": "stimulus_client",
                "secrets_in_plan": False,
            },
        )
        stream = plan["conversation"]["stream_exchange"]
        self.assertEqual(stream["bidirectional_streams"], 1)
        self.assertGreater(stream["request_length"], 0)
        self.assertEqual(len(stream["request_sha256"]), 64)
        self.assertGreater(stream["response_length"], 0)
        self.assertEqual(len(stream["response_sha256"]), 64)
        self.assertFalse(stream["payload_bytes_in_artifacts"])

    def test_protected_flow_plan_declares_provider_artifact_and_validation_contract(
        self,
    ) -> None:
        plan = _plan("quic-protected-flow-plan")

        self.assertEqual(
            plan["provider_requirements"],
            {
                "endpoint_count": 2,
                "roles": ["stimulus", "target"],
                "capabilities": [
                    "two_endpoints",
                    "controlled_service_startup",
                    "udp_capture",
                    "artifact_collection",
                    "endpoint_teardown",
                ],
                "controlled_service_startup": True,
                "udp_capture": True,
                "collect_artifacts_before_teardown": True,
                "always_teardown": True,
                "live_requires_explicit_target_and_adapter": True,
            },
        )
        self.assertIn("udp", plan["capture"]["filter"])
        self.assertEqual(plan["capture"]["points"], ["stimulus", "target"])
        self.assertEqual(plan["capture"]["artifacts"], plan["artifact_outputs"])
        self.assertTrue(
            all(path.startswith("target/") for path in plan["artifact_outputs"])
        )
        validation = plan["flow_validation"]
        self.assertIn("Established", validation["client_state_trace"])
        self.assertIn("Established", validation["server_state_trace"])
        self.assertEqual(
            validation["required_packet_spaces"],
            ["Initial", "Handshake", "Application"],
        )
        self.assertEqual(
            validation["recovery_counters"],
            [
                "timeout_events",
                "pto_firings",
                "declared_losses",
                "regenerated_transmits",
            ],
        )
        self.assertEqual(
            validation["close_outcome"], "graceful_application_close"
        )
        self.assertTrue(validation["reject_secrets"])
        self.assertTrue(plan["safety"]["documentation_addresses"])
        self.assertTrue(plan["safety"]["deterministic_seed"])
        self.assertFalse(plan["safety"]["developer_host_raw_send"])

    def test_protected_flow_catalog_metadata_is_stateful_not_udp_echo(self) -> None:
        case = cases.PROBE_CASE_BY_NAME["quic-protected-flow-plan"]

        self.assertTrue(case.metadata["stateful_endpoint_flow"])
        self.assertTrue(case.metadata["distinct_from_udp_echo"])
        self.assertTrue(case.metadata["requires_controlled_quic_service"])
        self.assertEqual(case.metadata["quic_version"], 1)
        self.assertEqual(case.metadata["alpn"], "crafter-flow")
        self.assertEqual(
            list(case.required_capabilities),
            [
                "two_endpoints",
                "controlled_service_startup",
                "udp_capture",
                "artifact_collection",
                "endpoint_teardown",
            ],
        )

    def test_plans_are_deterministic(self) -> None:
        self.assertEqual(
            _plan("quic-retry-observation", seed=9810, sequence=2),
            _plan("quic-retry-observation", seed=9810, sequence=2),
        )

    def test_target_setup_routes_initial_case_to_udp_responder(self) -> None:
        setup = target_services.target_service_setup_plan(
            probe_plans=[_plan("quic-initial-udp-observation")],
            dry_run=True,
        )

        services = setup["services"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["name"], "quic-controlled-udp")
        self.assertEqual(services[0]["protocol"], "udp")
        self.assertEqual(services[0]["port"], 4433)
        self.assertFalse(setup["starts_services"])


if __name__ == "__main__":
    unittest.main()
