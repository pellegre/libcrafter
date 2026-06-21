"""Unit coverage for lab-derived probe target service setup."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.lab.engine.model import LabEndpoint, LabRole, LabSession
from tools.probe.engine import cases as probe_cases
from tools.probe.engine import cli
from tools.probe.engine.lab import probe_address_context_from_lab_session
from tools.probe.engine.model import ProbeRunRequest

IGMP_TARGET_SERVICE_DIR = Path("tools/probe/target_services/igmp")


class ProbeTargetServicesTest(unittest.TestCase):
    def test_service_probe_plans_use_lab_endpoint_addresses(self) -> None:
        context, original_plans, rewritten_plans = _rewritten_service_plans()

        stimulus_ipv4 = str(context["stimulus_ipv4"])
        target_ipv4 = str(context["target_ipv4"])
        self.assertEqual(stimulus_ipv4, "10.77.0.10")
        self.assertEqual(target_ipv4, "10.77.0.20")

        for original, rewritten in zip(original_plans, rewritten_plans):
            with self.subTest(case=rewritten["case"]):
                self.assertEqual(rewritten["source_ipv4"], stimulus_ipv4)
                self.assertEqual(rewritten["destination_ipv4"], target_ipv4)
                self.assertEqual(
                    rewritten["target_service"]["kind"],
                    original["target_service"]["kind"],
                )
                self.assertEqual(
                    rewritten["target_service"]["port"],
                    original["target_service"]["port"],
                )
                self.assertEqual(rewritten["target_service"]["bind_ipv4"], target_ipv4)
                self.assertEqual(
                    rewritten["target_service"]["source_ipv4"],
                    stimulus_ipv4,
                )

    def test_target_service_setup_plan_uses_lab_endpoint_addresses(self) -> None:
        context, _original_plans, rewritten_plans = _rewritten_service_plans()
        stimulus_ipv4 = str(context["stimulus_ipv4"])
        target_ipv4 = str(context["target_ipv4"])

        setup = cli._target_service_setup_plan(
            probe_plans=rewritten_plans,
            dry_run=True,
        )

        tcp_services = [
            service
            for service in setup["services"]
            if service["purpose"] == "tcp-syn-open"
        ]
        dns_services = [
            service
            for service in setup["services"]
            if service["purpose"] == "dns-query"
        ]
        self.assertEqual(len(tcp_services), 1)
        self.assertEqual(len(dns_services), 1)
        self.assertEqual(tcp_services[0]["bind_ipv4"], target_ipv4)
        self.assertEqual(tcp_services[0]["source_ipv4"], stimulus_ipv4)
        self.assertEqual(dns_services[0]["bind_ipv4"], target_ipv4)
        self.assertEqual(dns_services[0]["source_ipv4"], stimulus_ipv4)

        self.assertEqual(len(setup["closed_tcp_ports"]), 1)
        self.assertEqual(setup["closed_tcp_ports"][0]["bind_ipv4"], target_ipv4)
        self.assertEqual(setup["closed_tcp_ports"][0]["source_ipv4"], stimulus_ipv4)

    def test_target_setup_and_cleanup_accept_lab_endpoint_context(self) -> None:
        context, _original_plans, rewritten_plans = _rewritten_service_plans()
        endpoints = context["endpoints"]
        target_endpoint = endpoints["target"]
        fake_wire = _FakeWire()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            setup = cli._prepare_wire_probe_target(
                wire=fake_wire,
                target_endpoint=target_endpoint,
                artifact_root="/root/libcrafter/artifacts/probe/target-services",
                probe_plans=rewritten_plans,
                output_dir=output_dir,
            )
            cleanup = cli._cleanup_wire_probe_target(
                wire=fake_wire,
                target_endpoint=target_endpoint,
                artifact_root="/root/libcrafter/artifacts/probe/target-services",
                output_dir=output_dir,
            )

        self.assertIsNotNone(setup)
        self.assertEqual(setup["exit_code"], 0)
        self.assertEqual(cleanup["exit_code"], 0)
        self.assertEqual(fake_wire.exec_calls[0]["endpoint_id"], "qemu-target")
        self.assertEqual(fake_wire.exec_calls[1]["endpoint_id"], "qemu-target")

        setup_script = fake_wire.exec_calls[0]["command"][2]
        self.assertIn("tcp_bind_ipv4=10.77.0.20", setup_script)
        self.assertIn("dns_bind_ipv4=10.77.0.20", setup_script)
        self.assertIn('check_port_free "$tcp_bind_ipv4"', setup_script)
        self.assertIn("sock.bind((bind_ip, port))", setup_script)
        self.assertIn('"$tcp_bind_ipv4"', setup_script)


class IgmpProbeTargetServiceTest(unittest.TestCase):
    def test_igmp_target_service_assets_exist(self) -> None:
        self.assertTrue((IGMP_TARGET_SERVICE_DIR / "README.md").is_file())
        self.assertTrue((IGMP_TARGET_SERVICE_DIR / "provision-listener.sh").is_file())
        self.assertTrue((IGMP_TARGET_SERVICE_DIR / "provision-router.sh").is_file())
        self.assertTrue((IGMP_TARGET_SERVICE_DIR / "cleanup.sh").is_file())

    def test_igmp_target_service_is_lab_only_and_dry_run_visible(self) -> None:
        readme = (IGMP_TARGET_SERVICE_DIR / "README.md").read_text()
        listener = (IGMP_TARGET_SERVICE_DIR / "provision-listener.sh").read_text()
        router = (IGMP_TARGET_SERVICE_DIR / "provision-router.sh").read_text()
        combined = "\n".join([readme, listener, router])

        self.assertIn("lab-only", readme)
        self.assertIn("--dry-run", combined)
        self.assertIn("LIBCRAFTER_PROBE_LAB_TARGET=1", combined)
        self.assertIn("target/probe/target-services/igmp", combined)
        self.assertIn("listener-plan.json", combined)
        self.assertIn("router-plan.json", combined)
        self.assertIn("router-skip.json", combined)
        self.assertIn("requires_controlled_router", router)
        self.assertIn("requires_multicast", router)
        self.assertIn("233.252.0.42", combined)


class _FakeProcessResult:
    stdout = ""
    stderr = ""
    exit_code = 0
    ok = True
    error = None


class _FakeWireResponse:
    def __init__(self, operation: str, endpoint_id: str) -> None:
        self.operation = operation
        self.endpoint_id = endpoint_id
        self.result = _FakeProcessResult()

    def metadata(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "endpoint_id": self.endpoint_id,
            "argv": ["tools/endpoint/run", self.operation, self.endpoint_id],
            "exit_code": self.result.exit_code,
            "ok": self.result.ok,
            "artifacts": [],
        }


class _FakeWire:
    def __init__(self) -> None:
        self.exec_calls: list[dict[str, object]] = []

    def exec(
        self,
        endpoint_id: str,
        command: list[str],
        *,
        timeout: int | float | None = None,
    ) -> _FakeWireResponse:
        self.exec_calls.append(
            {
                "endpoint_id": endpoint_id,
                "command": command,
                "timeout": timeout,
            }
        )
        return _FakeWireResponse("exec", endpoint_id)


def _rewritten_service_plans() -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[dict[str, object]],
]:
    request = ProbeRunRequest(
        provider="qemu",
        profile="smoke",
        seed=2,
        count=3,
        case_names=["tcp-syn-open", "tcp-syn-closed", "dns-query"],
        dry_run=True,
    )
    cases = [
        probe_cases.PROBE_CASE_BY_NAME["tcp-syn-open"],
        probe_cases.PROBE_CASE_BY_NAME["tcp-syn-closed"],
        probe_cases.PROBE_CASE_BY_NAME["dns-query"],
    ]
    original_plans = cli._probe_plans_for_cases(request, cases)
    context = probe_address_context_from_lab_session(_fake_session())
    rewritten_plans = cli._probe_plans_with_lab_endpoint_addresses(
        original_plans,
        address_context=context,
    )
    return context, original_plans, rewritten_plans


def _fake_session() -> LabSession:
    return LabSession(
        provider="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        session_id="qemu-probe-session",
        roles=[
            LabRole(name="stimulus", planned_ipv4="10.77.0.10", peer_roles=["target"]),
            LabRole(name="target", planned_ipv4="10.77.0.20", peer_roles=["stimulus"]),
        ],
        endpoints=[
            _endpoint("stimulus", "10.77.0.10", "target", "10.77.0.20"),
            _endpoint("target", "10.77.0.20", "stimulus", "10.77.0.10"),
        ],
        dry_run=True,
    )


def _endpoint(
    role: str,
    ipv4: str,
    peer_role: str,
    peer_ipv4: str,
) -> LabEndpoint:
    return LabEndpoint(
        endpoint_id=f"qemu-{role}",
        role=role,
        interface="private",
        ipv4=ipv4,
        peer_addresses={peer_role: {"ipv4": peer_ipv4}},
        wire_manifest={
            "endpoint_id": f"qemu-{role}",
            "provider": "qemu",
            "role": role,
        },
        metadata={
            "provider": "qemu",
            "wire_provider": "qemu",
            "wire_exposure": "private",
        },
    )


if __name__ == "__main__":
    unittest.main()
