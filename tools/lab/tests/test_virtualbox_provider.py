"""Coverage for the VirtualBox lab provider adapter."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from tools.lab.engine.model import LabCommandPlan, LabRequest, LabRole
from tools.lab.engine.providers.virtualbox import (
    VIRTUALBOX_LAB_PROVIDER_ADAPTER,
    VIRTUALBOX_WIRE_POLICY,
    virtualbox_lan_metadata,
    virtualbox_session_id,
)
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)
from tools.wire.engine.providers.virtualbox.constants import VBOX_BRIDGE_IFACE_ENV


class VirtualBoxProviderMetadataTest(unittest.TestCase):
    def test_adapter_maps_lab_provider_to_lan_wire_provider(self) -> None:
        adapter = VIRTUALBOX_LAB_PROVIDER_ADAPTER

        self.assertEqual(adapter.name, "virtualbox")
        self.assertEqual(adapter.wire_provider, "virtualbox")
        self.assertEqual(adapter.wire_exposure, "lan")
        self.assertEqual(adapter.credential_label, "none")
        self.assertTrue(adapter.credentials_available())
        self.assertEqual(adapter.missing_credential_reason, "")


class VirtualBoxProviderRolePlanningTest(unittest.TestCase):
    def test_session_id_and_lan_metadata_are_deterministic(self) -> None:
        request = _request(seed=7, workload_label="probe")

        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(
                virtualbox_session_id(request),
                "lab-virtualbox-probe-smoke-seed-7",
            )
            network = virtualbox_lan_metadata()

        self.assertEqual(network["resource_type"], "virtualbox-bridged-lan")
        self.assertEqual(network["wire_exposure"], "lan")
        self.assertEqual(network["bridge_interface"], "auto")
        self.assertEqual(network["bridge_env"], VBOX_BRIDGE_IFACE_ENV)
        self.assertFalse(network["isolated"])

    def test_plan_roles_fills_documentation_lan_fallbacks(self) -> None:
        request = _request(
            roles=[
                LabRole(name="stimulus", planned_ipv4="192.0.2.50"),
                LabRole(name="target"),
            ],
        )
        adapter = VIRTUALBOX_LAB_PROVIDER_ADAPTER

        roles = adapter.plan_roles(request)

        self.assertEqual(roles[0].planned_ipv4, "192.0.2.50")
        self.assertEqual(roles[1].planned_ipv4, "192.0.2.20")
        self.assertIsNone(adapter.private_group(request))
        self.assertIsNone(adapter.requested_private_ip(roles[0], request))
        self.assertEqual(roles[0].peer_roles, ["target"])
        self.assertEqual(roles[1].peer_roles, ["stimulus"])
        self.assertFalse(roles[0].metadata["private_network"])
        self.assertTrue(roles[0].metadata["bridged_lan"])

    def test_role_lan_ipv4_metadata_is_used_as_planned_fallback(self) -> None:
        request = _request(
            roles=[LabRole(name="stimulus"), LabRole(name="target")],
            metadata={"role_lan_ipv4s": {"stimulus": "198.51.100.77"}},
        )

        role = VIRTUALBOX_LAB_PROVIDER_ADAPTER.plan_roles(request)[0]

        self.assertEqual(role.planned_ipv4, "198.51.100.77")
        self.assertEqual(
            role.metadata["planned_lan_address_source"],
            "metadata.role_lan_ipv4s",
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
        self.assertFalse(capabilities["l2"])
        self.assertTrue(capabilities["controlled_service"])
        self.assertEqual(capabilities["wire_policy"], VIRTUALBOX_WIRE_POLICY)

    def test_planned_infrastructure_reports_bridged_lan(self) -> None:
        request = _request()

        with patch.dict("os.environ", {VBOX_BRIDGE_IFACE_ENV: "wlan0"}, clear=True):
            infrastructure = VIRTUALBOX_LAB_PROVIDER_ADAPTER.planned_infrastructure(request)

        self.assertEqual(infrastructure["provider"], "virtualbox")
        self.assertEqual(infrastructure["wire_provider"], "virtualbox")
        self.assertEqual(infrastructure["wire_exposure"], "lan")
        self.assertEqual(infrastructure["network"]["bridge_interface"], "wlan0")
        self.assertEqual(infrastructure["resource_counts"]["vms"], 2)
        self.assertEqual(infrastructure["credentials"]["required_for_live"], False)
        self.assertEqual(infrastructure["wire_policy"], VIRTUALBOX_WIRE_POLICY)
        self.assertFalse(infrastructure["private_network"])
        self.assertTrue(infrastructure["bridged_lan"])


class VirtualBoxProviderWorkflowTest(unittest.TestCase):
    def test_provider_workflow_plans_lan_wire_commands_without_private_flags(self) -> None:
        request = _request()
        adapter = VIRTUALBOX_LAB_PROVIDER_ADAPTER

        workflow = adapter.provider_workflow(request)
        validation = adapter.validate_provider_workflow(workflow, dry_run=True)

        self.assertTrue(validation.passed, validation.errors)
        self.assertEqual(workflow[0].purpose, "check-virtualbox-lan-wire")
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
            self.assertNotIn("--private-group", command.argv)
            self.assertNotIn("--private-ip", command.argv)
            self.assertIn("virtualbox", command.argv)
            self.assertIn("lan", command.argv)


class VirtualBoxProviderSessionPlanningTest(unittest.TestCase):
    def test_plan_session_uses_wire_dry_run_and_returns_lab_session(self) -> None:
        request = _request()
        client = _FakeWireClient()

        session = VIRTUALBOX_LAB_PROVIDER_ADAPTER.plan_session(request, client=client)

        self.assertEqual(session.provider, "virtualbox")
        self.assertEqual(session.wire_provider, "virtualbox")
        self.assertEqual(session.wire_exposure, "lan")
        self.assertTrue(session.dry_run)
        self.assertEqual(session.remote_dir, "/root/libcrafter")
        self.assertEqual(session.remote_artifact_root, "/root/libcrafter/artifacts")
        self.assertEqual([endpoint.role for endpoint in session.endpoints], ["stimulus", "target"])
        self.assertEqual(session.endpoints[0].ipv4, "192.0.2.10")
        self.assertEqual(session.endpoints[0].peer_addresses, {"target": {"ipv4": "192.0.2.20"}})
        self.assertIsNone(session.metadata["private_group"])
        self.assertFalse(session.metadata["private_network"])
        self.assertTrue(session.metadata["bridged_lan"])
        self.assertEqual(session.metadata["wire_policy"], VIRTUALBOX_WIRE_POLICY)
        self.assertEqual(len(session.command_records), 2)
        self.assertEqual(session.created_endpoint_ids, [])
        self.assertTrue(all(check.passed for check in session.validation_checks))
        for command in session.command_records:
            self.assertNotIn("--private-group", command.argv)
            self.assertNotIn("--private-ip", command.argv)

        self.assertEqual([call["role"] for call in client.calls], ["stimulus", "target"])
        self.assertEqual([call["private_group"] for call in client.calls], [None, None])
        self.assertEqual([call["private_ip"] for call in client.calls], [None, None])
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
            "tools/wire/run",
            "create-endpoint",
            "--provider",
            str(self.call["provider"]),
            "--exposure",
            str(self.call["exposure"]),
            "--role",
            str(self.call["role"]),
            "--json",
        ]
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
    endpoint_id = f"planned-virtualbox-lan-{endpoint_role}"
    return EndpointManifest(
        endpoint_id=endpoint_id,
        provider="virtualbox",
        exposure="lan",
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
                name="lan",
                exposure="lan",
                provider_network_id="planned-virtualbox-bridged-lan",
                metadata={
                    "planned": True,
                    "type": "bridged-lan",
                    "adapter": 2,
                    "bridge_interface": "auto",
                    "bridge_selection": "auto",
                    "bridge_env": VBOX_BRIDGE_IFACE_ENV,
                    "bridge_validated": False,
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
                "bridge_interface": "auto",
                "bridge_selection": "auto",
                "bridge_env": VBOX_BRIDGE_IFACE_ENV,
            },
        },
    )


def _slug(value: str) -> str:
    return "-".join(part for part in value.replace("_", "-").lower().split("-") if part)


if __name__ == "__main__":
    unittest.main()

