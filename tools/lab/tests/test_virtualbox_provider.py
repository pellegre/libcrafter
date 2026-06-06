"""Coverage for the VirtualBox lab provider adapter."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.lab.engine.model import LabCommandPlan, LabRequest, LabRole
from tools.lab.engine.providers.virtualbox import (
    VIRTUALBOX_LAB_PROVIDER_ADAPTER,
    VIRTUALBOX_WIRE_POLICY,
    virtualbox_private_group,
    virtualbox_private_network_metadata,
    virtualbox_session_id,
)
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)
from tools.endpoint.engine.providers.virtualbox.constants import VBOX_DEFAULT_PRIVATE_CIDR


class VirtualBoxProviderMetadataTest(unittest.TestCase):
    def test_adapter_maps_lab_provider_to_private_wire_provider(self) -> None:
        adapter = VIRTUALBOX_LAB_PROVIDER_ADAPTER

        self.assertEqual(adapter.name, "virtualbox")
        self.assertEqual(adapter.wire_provider, "virtualbox")
        self.assertEqual(adapter.wire_exposure, "private")
        self.assertEqual(adapter.credential_label, "none")
        self.assertTrue(adapter.credentials_available())
        self.assertEqual(adapter.missing_credential_reason, "")


class VirtualBoxProviderRolePlanningTest(unittest.TestCase):
    def test_session_id_and_private_metadata_are_deterministic(self) -> None:
        request = _request(seed=7, workload_label="probe")

        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(
                virtualbox_session_id(request),
                "lab-virtualbox-probe-smoke-seed-7",
            )
            private_group = virtualbox_private_group(request)
            network = virtualbox_private_network_metadata(private_group)

        self.assertEqual(private_group, "lab-virtualbox-probe-smoke-seed-7-private")
        self.assertEqual(network["resource_type"], "virtualbox-internal-network")
        self.assertEqual(network["wire_exposure"], "private")
        self.assertEqual(network["private_group"], private_group)
        self.assertEqual(network["ip_range"], VBOX_DEFAULT_PRIVATE_CIDR)
        self.assertTrue(network["isolated"])

    def test_plan_roles_fills_private_fallbacks(self) -> None:
        request = _request(
            roles=[
                LabRole(name="stimulus", planned_ipv4="10.78.0.50"),
                LabRole(name="target"),
            ],
        )
        adapter = VIRTUALBOX_LAB_PROVIDER_ADAPTER

        roles = adapter.plan_roles(request)

        self.assertEqual(roles[0].planned_ipv4, "10.78.0.50")
        self.assertEqual(roles[1].planned_ipv4, "10.78.0.20")
        self.assertEqual(adapter.private_group(request), "lab-virtualbox-probe-smoke-seed-1-private")
        self.assertEqual(adapter.requested_private_ip(roles[0], request), "10.78.0.50")
        self.assertEqual(roles[0].peer_roles, ["target"])
        self.assertEqual(roles[1].peer_roles, ["stimulus"])
        self.assertTrue(roles[0].metadata["private_network"])
        self.assertFalse(roles[0].metadata["bridged_lan"])

    def test_role_private_ipv4_metadata_is_used_as_planned_fallback(self) -> None:
        request = _request(
            roles=[LabRole(name="stimulus"), LabRole(name="target")],
            metadata={"role_private_ipv4s": {"stimulus": "10.78.0.77"}},
        )

        role = VIRTUALBOX_LAB_PROVIDER_ADAPTER.plan_roles(request)[0]

        self.assertEqual(role.planned_ipv4, "10.78.0.77")
        self.assertEqual(
            role.metadata["planned_private_address_source"],
            "metadata.role_private_ipv4s",
        )


class VirtualBoxProviderCapabilityTest(unittest.TestCase):
    def test_common_capabilities_and_wire_policy_are_normalized(self) -> None:
        capabilities = VIRTUALBOX_LAB_PROVIDER_ADAPTER.default_provider_capabilities(
            dry_run=True,
        )

        self.assertEqual(capabilities["provider"], "virtualbox")
        self.assertTrue(capabilities["dry_run"])
        self.assertTrue(capabilities["ipv4_unicast"])
        self.assertFalse(capabilities["ipv6_unicast"])
        self.assertTrue(capabilities["ipv4"])
        self.assertFalse(capabilities["ipv6"])
        self.assertTrue(capabilities["l2"])
        self.assertTrue(capabilities["link_layer_send"])
        self.assertTrue(capabilities["link_layer_capture"])
        self.assertTrue(capabilities["broadcast"])
        self.assertTrue(capabilities["provider_mac_known"])
        self.assertTrue(capabilities["controlled_service"])
        self.assertEqual(capabilities["wire_policy"], VIRTUALBOX_WIRE_POLICY)

    def test_planned_infrastructure_reports_private_network(self) -> None:
        request = _request()

        with patch.dict("os.environ", {}, clear=True):
            infrastructure = VIRTUALBOX_LAB_PROVIDER_ADAPTER.planned_infrastructure(request)

        self.assertEqual(infrastructure["provider"], "virtualbox")
        self.assertEqual(infrastructure["wire_provider"], "virtualbox")
        self.assertEqual(infrastructure["wire_exposure"], "private")
        self.assertEqual(infrastructure["network"]["private_group"], VIRTUALBOX_LAB_PROVIDER_ADAPTER.private_group(request))
        self.assertEqual(infrastructure["network"]["ip_range"], VBOX_DEFAULT_PRIVATE_CIDR)
        self.assertEqual(infrastructure["resource_counts"]["vms"], 2)
        self.assertEqual(infrastructure["credentials"]["required_for_live"], False)
        self.assertEqual(infrastructure["wire_policy"], VIRTUALBOX_WIRE_POLICY)
        self.assertTrue(infrastructure["private_network"])
        self.assertFalse(infrastructure["bridged_lan"])


class VirtualBoxProviderWorkflowTest(unittest.TestCase):
    def test_provider_workflow_plans_private_wire_commands(self) -> None:
        request = _request()
        adapter = VIRTUALBOX_LAB_PROVIDER_ADAPTER

        workflow = adapter.provider_workflow(request)
        validation = adapter.validate_provider_workflow(workflow, dry_run=True)

        self.assertTrue(validation.passed, validation.errors)
        self.assertEqual(workflow[0].purpose, "check-virtualbox-private-wire")
        create_commands = [
            command for command in workflow if command.operation == "wire.create"
        ]
        self.assertEqual(len(create_commands), 2)
        self.assertTrue(all("--dry-run" in command.argv for command in create_commands))
        self.assertTrue(
            all("--confirm-live-run" not in command.argv for command in create_commands)
        )
        self.assertFalse(any(command.live_mutation for command in workflow))
        for command in create_commands:
            self.assertIn("--private-group", command.argv)
            self.assertIn("--private-ip", command.argv)
            self.assertIn("virtualbox", command.argv)
            self.assertIn("private", command.argv)


class VirtualBoxProviderSessionPlanningTest(unittest.TestCase):
    def test_plan_session_uses_wire_dry_run_and_returns_lab_session(self) -> None:
        request = _request()
        client = _FakeWireClient()

        session = VIRTUALBOX_LAB_PROVIDER_ADAPTER.plan_session(request, client=client)

        self.assertEqual(session.provider, "virtualbox")
        self.assertEqual(session.wire_provider, "virtualbox")
        self.assertEqual(session.wire_exposure, "private")
        self.assertTrue(session.dry_run)
        self.assertEqual(session.remote_dir, "/root/libcrafter")
        self.assertEqual(session.remote_artifact_root, "/root/libcrafter/artifacts")
        self.assertEqual([endpoint.role for endpoint in session.endpoints], ["stimulus", "target"])
        self.assertEqual(session.endpoints[0].ipv4, "10.78.0.10")
        self.assertEqual(session.endpoints[0].peer_addresses, {"target": {"ipv4": "10.78.0.20"}})
        self.assertEqual(session.metadata["private_group"], "lab-virtualbox-probe-smoke-seed-1-private")
        self.assertTrue(session.metadata["private_network"])
        self.assertFalse(session.metadata["bridged_lan"])
        self.assertEqual(session.metadata["wire_policy"], VIRTUALBOX_WIRE_POLICY)
        self.assertEqual(len(session.command_records), 2)
        self.assertEqual(session.created_endpoint_ids, [])
        self.assertTrue(all(check.passed for check in session.validation_checks))
        for command in session.command_records:
            self.assertIn("--private-group", command.argv)
            self.assertIn("--private-ip", command.argv)

        self.assertEqual([call["role"] for call in client.calls], ["stimulus", "target"])
        self.assertEqual(
            [call["private_group"] for call in client.calls],
            [
                "lab-virtualbox-probe-smoke-seed-1-private",
                "lab-virtualbox-probe-smoke-seed-1-private",
            ],
        )
        self.assertEqual([call["private_ip"] for call in client.calls], ["10.78.0.10", "10.78.0.20"])
        self.assertTrue(all(call["dry_run"] for call in client.calls))
        self.assertTrue(all(call["write_manifest"] is False for call in client.calls))

    def test_live_request_without_confirmation_is_rejected_before_wire_create(self) -> None:
        request = _request(dry_run=False, confirm_live_run=False)
        client = _FakeWireClient()

        with self.assertRaisesRegex(PermissionError, "confirm_live_run"):
            VIRTUALBOX_LAB_PROVIDER_ADAPTER.wire_endpoint_plan(request, client=client)

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
        provider="virtualbox",
        profile="smoke",
        seed=seed,
        roles=roles or [LabRole(name="stimulus"), LabRole(name="target")],
        dry_run=dry_run,
        confirm_live_run=confirm_live_run,
        workload_label=workload_label,
        metadata=metadata or {},
    )


class _FakeWireClient:
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
    ) -> "_FakeWireCreateResponse":
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
        manifest = _manifest(role=role, dry_run=dry_run)
        return _FakeWireCreateResponse(manifest=manifest, call=call)


class _FakeWireCreateResponse:
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
            "create-endpoint",
            "--provider",
            str(self.call["provider"]),
            "--exposure",
            str(self.call["exposure"]),
            "--role",
            str(self.call["role"]),
            "--json",
        ]
        if self.call["private_group"] is not None:
            argv.extend(["--private-group", str(self.call["private_group"])])
        if self.call["private_ip"] is not None:
            argv.extend(["--private-ip", str(self.call["private_ip"])])
        if self.call["dry_run"]:
            argv.append("--dry-run")
        return LabCommandPlan(
            purpose=purpose or "wire create",
            role=role,
            argv=argv,
            operation="wire.create",
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


def _manifest(*, role: str, dry_run: bool) -> EndpointManifest:
    endpoint_role = _slug(role)
    endpoint_id = f"planned-virtualbox-private-{endpoint_role}"
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="virtualbox",
        exposure="private",
        status="planned" if dry_run else "created",
        role=role,
        created_at="planned",
        ssh=EndpointSSHInfo(
            host="127.0.0.1",
            user="root",
            metadata={
                "planned": True,
                "transport": "virtualbox-nat-port-forward",
                "control_interface": "nat-control",
            },
        ),
        interfaces=[
            NetworkInterface(
                name="nat-control",
                exposure="control",
                metadata={"type": "nat-control", "adapter": 1, "network": "nat"},
            ),
            NetworkInterface(
                name="private",
                exposure="private",
                ipv4="10.78.0.10" if role == "stimulus" else "10.78.0.20",
                provider_network_id="virtualbox-private-group-lab-virtualbox-probe-smoke-seed-1-private",
                metadata={
                    "planned": True,
                    "type": "virtualbox-internal-network",
                    "adapter": 2,
                    "private_group": "lab-virtualbox-probe-smoke-seed-1-private",
                    "private_network": True,
                },
            ),
        ],
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-lab/{endpoint_id}",
        metadata={
            "created": False,
            "dry_run": dry_run,
            "virtualbox": {
                "command": "VBoxManage",
                "private_group": "lab-virtualbox-probe-smoke-seed-1-private",
                "private_network": True,
            },
        },
    )


def _slug(value: str) -> str:
    return "-".join(part for part in value.replace("_", "-").lower().split("-") if part)


if __name__ == "__main__":
    unittest.main()
