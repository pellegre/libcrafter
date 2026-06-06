"""Coverage for the Hetzner lab provider adapter."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from tools.lab.engine.model import LabCommandPlan, LabRequest, LabRole
from tools.lab.engine.providers.hetzner import (
    HETZNER_LAB_PROVIDER_ADAPTER,
    hetzner_private_group,
    hetzner_session_id,
)
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)


class HetznerProviderMetadataTest(unittest.TestCase):
    def test_adapter_maps_lab_provider_to_private_wire_provider(self) -> None:
        adapter = HETZNER_LAB_PROVIDER_ADAPTER

        self.assertEqual(adapter.name, "hetzner")
        self.assertEqual(adapter.wire_provider, "hetzner")
        self.assertEqual(adapter.wire_exposure, "private")
        self.assertIn("HETZNER_API_TOKEN", adapter.credential_label)
        self.assertIn("HCLOUD_TOKEN", adapter.credential_label)

    def test_credentials_are_detected_from_either_supported_environment_name(self) -> None:
        adapter = HETZNER_LAB_PROVIDER_ADAPTER

        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(adapter.credentials_available())

        with patch.dict(os.environ, {"HETZNER_API_TOKEN": "token"}, clear=True):
            self.assertTrue(adapter.credentials_available())

        with patch.dict(os.environ, {"HCLOUD_TOKEN": "token"}, clear=True):
            self.assertTrue(adapter.credentials_available())


class HetznerProviderRolePlanningTest(unittest.TestCase):
    def test_private_group_and_session_id_are_deterministic(self) -> None:
        request = _request(seed=7, workload_label="probe")

        self.assertEqual(hetzner_session_id(request), "lab-hetzner-probe-smoke-seed-7")
        self.assertEqual(
            hetzner_private_group(request),
            "lab-hetzner-probe-smoke-seed-7-private",
        )

    def test_plan_roles_preserves_requested_ip_and_fills_defaults(self) -> None:
        request = _request(
            roles=[
                LabRole(name="stimulus", requested_private_ipv4="10.0.25.50"),
                LabRole(name="target"),
            ],
        )
        adapter = HETZNER_LAB_PROVIDER_ADAPTER

        roles = adapter.plan_roles(request)

        self.assertEqual(roles[0].requested_private_ipv4, "10.0.25.50")
        self.assertEqual(roles[0].planned_ipv4, "10.0.25.50")
        self.assertEqual(roles[1].requested_private_ipv4, None)
        self.assertEqual(roles[1].planned_ipv4, "10.0.25.20")
        self.assertEqual(adapter.requested_private_ip(roles[1], request), "10.0.25.20")
        self.assertEqual(roles[0].peer_roles, ["target"])
        self.assertEqual(roles[1].peer_roles, ["stimulus"])
        self.assertEqual(roles[0].metadata["private_network"], True)

    def test_role_private_ipv4_metadata_is_treated_as_requested_input(self) -> None:
        request = _request(
            roles=[LabRole(name="stimulus"), LabRole(name="target")],
            metadata={"role_private_ipv4s": {"stimulus": "10.0.25.77"}},
        )

        role = HETZNER_LAB_PROVIDER_ADAPTER.plan_roles(request)[0]

        self.assertEqual(role.requested_private_ipv4, "10.0.25.77")
        self.assertEqual(role.planned_ipv4, "10.0.25.77")
        self.assertEqual(role.metadata["address_source"], "metadata.role_private_ipv4s")


class HetznerProviderCapabilityTest(unittest.TestCase):
    def test_common_capabilities_are_normalized(self) -> None:
        capabilities = HETZNER_LAB_PROVIDER_ADAPTER.default_provider_capabilities(
            dry_run=True,
        )

        self.assertEqual(capabilities["provider"], "hetzner")
        self.assertTrue(capabilities["dry_run"])
        self.assertTrue(capabilities["ipv4_unicast"])
        self.assertFalse(capabilities["ipv6_unicast"])
        self.assertTrue(capabilities["ipv4"])
        self.assertFalse(capabilities["ipv6"])
        self.assertFalse(capabilities["l2"])
        self.assertTrue(capabilities["controlled_service"])
        self.assertIn("controlled_router", capabilities["capability_names"])


class HetznerProviderWorkflowTest(unittest.TestCase):
    def test_provider_workflow_plans_endpoint_commands_without_live_mutation_in_dry_run(self) -> None:
        request = _request()
        adapter = HETZNER_LAB_PROVIDER_ADAPTER

        workflow = adapter.provider_workflow(request)
        validation = adapter.validate_provider_workflow(workflow, dry_run=True)

        self.assertTrue(validation.passed, validation.errors)
        self.assertEqual(workflow[0].purpose, "check-hetzner-private-wire")
        create_commands = [
            command for command in workflow if command.operation == "endpoint.create"
        ]
        self.assertEqual(len(create_commands), 2)
        self.assertTrue(all("--dry-run" in command.argv for command in create_commands))
        self.assertTrue(
            all("--confirm-live-run" not in command.argv for command in create_commands)
        )
        self.assertFalse(any(command.live_mutation for command in workflow))
        self.assertIn("--private-group", create_commands[0].argv)
        self.assertIn(hetzner_private_group(request), create_commands[0].argv)
        self.assertIn("10.0.25.10", create_commands[0].argv)


class HetznerProviderSessionPlanningTest(unittest.TestCase):
    def test_plan_session_uses_wire_dry_run_and_returns_lab_session(self) -> None:
        request = _request()
        client = _FakeEndpointClient()

        session = HETZNER_LAB_PROVIDER_ADAPTER.plan_session(request, client=client)

        self.assertEqual(session.provider, "hetzner")
        self.assertEqual(session.wire_provider, "hetzner")
        self.assertEqual(session.wire_exposure, "private")
        self.assertTrue(session.dry_run)
        self.assertEqual(session.remote_dir, "/root/libcrafter")
        self.assertEqual(session.remote_artifact_root, "/root/libcrafter/artifacts")
        self.assertEqual([endpoint.role for endpoint in session.endpoints], ["stimulus", "target"])
        self.assertEqual(session.endpoints[0].ipv4, "10.0.25.10")
        self.assertEqual(session.endpoints[0].peer_addresses, {"target": {"ipv4": "10.0.25.20"}})
        self.assertEqual(session.metadata["private_group"], hetzner_private_group(request))
        self.assertEqual(len(session.command_records), 2)
        self.assertEqual(session.created_endpoint_ids, [])
        self.assertTrue(all(check.passed for check in session.validation_checks))

        self.assertEqual([call["role"] for call in client.calls], ["stimulus", "target"])
        self.assertEqual([call["private_ip"] for call in client.calls], ["10.0.25.10", "10.0.25.20"])
        self.assertTrue(all(call["private_group"] == hetzner_private_group(request) for call in client.calls))
        self.assertTrue(all(call["dry_run"] for call in client.calls))
        self.assertTrue(all(call["write_manifest"] is False for call in client.calls))

    def test_live_request_without_confirmation_is_rejected_before_wire_create(self) -> None:
        request = _request(dry_run=False, confirm_live_run=False)
        client = _FakeEndpointClient()

        with self.assertRaisesRegex(PermissionError, "confirm_live_run"):
            HETZNER_LAB_PROVIDER_ADAPTER.wire_endpoint_plan(request, client=client)

        self.assertEqual(client.calls, [])


def _request(
    *,
    seed: int = 1,
    workload_label: str = "probe",
    roles: list[LabRole] | None = None,
    dry_run: bool = True,
    confirm_live_run: bool = False,
    metadata: dict[str, object] | None = None,
) -> LabRequest:
    return LabRequest(
        provider="hetzner",
        profile="smoke",
        seed=seed,
        roles=roles
        or [
            LabRole(name="stimulus", requested_private_ipv4="10.0.25.10"),
            LabRole(name="target", requested_private_ipv4="10.0.25.20"),
        ],
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        workload_label=workload_label,
        metadata=metadata or {},
    )


class _FakeEndpointClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str | None,
        private_ip: str | None,
        dry_run: bool,
        write_manifest: bool,
        confirm_live_run: bool,
    ) -> "_FakeEndpointCreateResponse":
        call = {
            "provider": provider,
            "exposure": exposure,
            "role": role,
            "private_group": private_group,
            "private_ip": private_ip,
            "dry_run": dry_run,
            "write_manifest": write_manifest,
            "confirm_live_run": confirm_live_run,
        }
        self.calls.append(call)
        manifest = _manifest(
            role=role,
            private_group=private_group,
            private_ip=private_ip,
            dry_run=dry_run,
        )
        return _FakeEndpointCreateResponse(manifest=manifest, call=call)


class _FakeEndpointCreateResponse:
    def __init__(self, *, manifest: EndpointManifest, call: dict[str, object]) -> None:
        self.manifest = manifest
        self.json_data = manifest.to_dict()
        self.call = call

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: list[str] = (),
    ) -> LabCommandPlan:
        argv = [
            "tools/endpoint/run",
            "create",
            "--provider",
            str(self.call["provider"]),
            "--exposure",
            str(self.call["exposure"]),
            "--role",
            str(self.call["role"]),
            "--private-group",
            str(self.call["private_group"]),
            "--private-ip",
            str(self.call["private_ip"]),
            "--json",
        ]
        if self.call["dry_run"]:
            argv.append("--dry-run")
        return LabCommandPlan(
            purpose=purpose or "endpoint create",
            role=role,
            argv=argv,
            operation="endpoint.create",
            dry_run=bool(self.call["dry_run"]),
            live_mutation=not bool(self.call["dry_run"]),
            artifacts=list(artifacts),
            metadata={
                "provider": self.call["provider"],
                "exposure": self.call["exposure"],
                "private_group": self.call["private_group"],
                "private_ip": self.call["private_ip"],
            },
        )


def _manifest(
    *,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> EndpointManifest:
    endpoint_role = _slug(role)
    endpoint_id = f"planned-hetzner-private-{endpoint_role}"
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="hetzner",
        exposure="private",
        status="planned" if dry_run else "created",
        role=role,
        created_at="planned",
        ssh=EndpointSSHInfo(host="planned", user="root"),
        interfaces=[
            NetworkInterface(
                name="private",
                exposure="private",
                ipv4=private_ip,
                provider_network_id=f"planned-private-network-{private_group}",
                metadata={"private_group": private_group},
            )
        ],
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-lab/{endpoint_id}",
        metadata={"private_group": private_group},
    )


def _slug(value: str) -> str:
    return "-".join(part for part in value.replace("_", "-").lower().split("-") if part)


if __name__ == "__main__":
    unittest.main()
