"""Shared provider matrix coverage for lab session planning."""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from tools.lab.engine.model import LabCommandPlan, LabRequest, LabRole
from tools.lab.engine.providers import registered_provider_names, resolve_lab_provider
from tools.lab.engine.providers.base import LabProviderAdapter
from tools.wire.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)


@dataclass(frozen=True, slots=True)
class _ProviderCase:
    name: str
    wire_provider: str
    wire_exposure: str
    uses_private_wire_flags: bool
    alpha_ipv4: str
    beta_ipv4: str


PROVIDER_CASES = (
    _ProviderCase(
        name="hetzner",
        wire_provider="hetzner",
        wire_exposure="private",
        uses_private_wire_flags=True,
        alpha_ipv4="10.0.25.101",
        beta_ipv4="10.0.25.102",
    ),
    _ProviderCase(
        name="qemu",
        wire_provider="qemu",
        wire_exposure="private",
        uses_private_wire_flags=True,
        alpha_ipv4="10.77.0.101",
        beta_ipv4="10.77.0.102",
    ),
    _ProviderCase(
        name="virtualbox",
        wire_provider="virtualbox",
        wire_exposure="private",
        uses_private_wire_flags=True,
        alpha_ipv4="10.78.0.101",
        beta_ipv4="10.78.0.102",
    ),
)


class LabProviderMatrixTest(unittest.TestCase):
    def test_registered_provider_matrix_plans_two_generic_roles(self) -> None:
        self.assertEqual(
            registered_provider_names(),
            tuple(case.name for case in PROVIDER_CASES),
        )

        for case in PROVIDER_CASES:
            with self.subTest(provider=case.name):
                adapter = resolve_lab_provider(case.name)
                client = _FakeWireClient()
                request = _request(case, requested_addresses=False)

                session = adapter.plan_session(request, client=client)

                self.assertEqual(session.provider, case.name)
                self.assertEqual(session.wire_provider, case.wire_provider)
                self.assertEqual(session.wire_exposure, case.wire_exposure)
                self.assertTrue(session.dry_run)
                self.assertEqual([role.name for role in session.roles], ["alpha", "beta"])
                self.assertEqual([endpoint.role for endpoint in session.endpoints], ["alpha", "beta"])
                self.assertEqual(session.created_endpoint_ids, [])
                self.assertFalse(session.infrastructure_metadata["creates_infrastructure"])
                self.assertTrue(session.infrastructure_metadata["dry_run"])
                self.assertEqual(session.provider_capabilities["provider"], case.name)
                self.assertTrue(session.provider_capabilities["dry_run"])
                self.assertTrue(session.provider_capabilities["ipv4_unicast"])
                self.assertIn(
                    "controlled_router",
                    session.provider_capabilities["capability_names"],
                )
                self.assertTrue(
                    all(check.passed for check in session.validation_checks),
                    session.validation_checks,
                )
                self.assertEqual(
                    session.cleanup_state,
                    {
                        "status": "not_started",
                        "artifact_collection_attempted": False,
                        "teardown_attempted": False,
                    },
                )

                self.assertEqual([call["role"] for call in client.calls], ["alpha", "beta"])
                self.assertTrue(all(call["dry_run"] for call in client.calls))
                self.assertTrue(all(call["write_manifest"] is False for call in client.calls))
                self.assertTrue(all(call["confirm_live_run"] is False for call in client.calls))
                self.assertTrue(all(not command.live_mutation for command in session.command_records))

                self._assert_provider_workflow(session.provider_workflow, adapter, case)

    def test_private_wire_flags_follow_provider_policy_for_requested_addresses(self) -> None:
        for case in PROVIDER_CASES:
            with self.subTest(provider=case.name):
                adapter = resolve_lab_provider(case.name)
                client = _FakeWireClient()
                request = _request(case, requested_addresses=True)

                session = adapter.plan_session(request, client=client)
                create_workflow = [
                    command
                    for command in session.provider_workflow
                    if command.operation == "wire.create"
                ]

                self.assertEqual(len(create_workflow), 2)
                if case.uses_private_wire_flags:
                    self.assertIsNotNone(session.metadata["private_group"])
                    self.assertTrue(session.infrastructure_metadata["private_network"])
                    self.assertEqual(
                        [role.requested_private_ipv4 for role in session.roles],
                        [case.alpha_ipv4, case.beta_ipv4],
                    )
                    self.assertEqual(
                        [call["private_ip"] for call in client.calls],
                        [case.alpha_ipv4, case.beta_ipv4],
                    )
                    self.assertTrue(all(call["private_group"] for call in client.calls))
                    for command, expected_ip in zip(
                        create_workflow,
                        [case.alpha_ipv4, case.beta_ipv4],
                        strict=True,
                    ):
                        self.assertIn("--private-group", command.argv)
                        self.assertIn("--private-ip", command.argv)
                        self.assertIn(expected_ip, command.argv)
                        self.assertEqual(command.metadata["private_ip"], expected_ip)
                        self.assertTrue(command.metadata["private_group"])
                        self.assertTrue(command.metadata["private_network"])
                        self.assertFalse(command.metadata["creates_infrastructure"])
                else:
                    self.assertIsNone(session.metadata["private_group"])
                    self.assertFalse(session.infrastructure_metadata["private_network"])
                    self.assertEqual(
                        [role.requested_private_ipv4 for role in session.roles],
                        [None, None],
                    )
                    self.assertEqual(
                        [role.planned_ipv4 for role in session.roles],
                        [case.alpha_ipv4, case.beta_ipv4],
                    )
                    self.assertEqual([call["private_group"] for call in client.calls], [None, None])
                    self.assertEqual([call["private_ip"] for call in client.calls], [None, None])
                    for command in create_workflow:
                        self.assertNotIn("--private-group", command.argv)
                        self.assertNotIn("--private-ip", command.argv)
                        self.assertIsNone(command.metadata["private_group"])
                        self.assertFalse(command.metadata["private_network"])
                        self.assertFalse(command.metadata["creates_infrastructure"])

    def _assert_provider_workflow(
        self,
        workflow: list[LabCommandPlan],
        adapter: LabProviderAdapter,
        case: _ProviderCase,
    ) -> None:
        operations = [command.operation for command in workflow]

        self.assertEqual(
            operations,
            [
                "wire.doctor",
                "wire.create",
                "wire.create",
                "wire.collect_artifacts",
                "wire.destroy",
            ],
        )
        self.assertTrue(all(command.dry_run for command in workflow))
        self.assertTrue(all(not command.live_mutation for command in workflow))
        self.assertEqual([command.role for command in workflow if command.role], ["alpha", "beta"])
        for command in workflow:
            self.assertEqual(command.metadata["provider"], case.name)
            self.assertEqual(command.metadata["exposure"], case.wire_exposure)
            self.assertEqual(command.metadata["operation"], command.operation)
            self.assertTrue(command.metadata["wire_command"])
            if command.operation in {"wire.doctor", "wire.create"}:
                self.assertIn("--dry-run", command.argv)
            if command.operation in {"wire.collect_artifacts", "wire.destroy"}:
                self.assertTrue(command.metadata["always_attempt"])

        validation = adapter.validate_provider_workflow(workflow, dry_run=True)
        self.assertTrue(validation.passed, validation.errors)


def _request(case: _ProviderCase, *, requested_addresses: bool) -> LabRequest:
    if requested_addresses:
        roles = [
            LabRole(name="alpha", requested_private_ipv4=case.alpha_ipv4),
            LabRole(name="beta", requested_private_ipv4=case.beta_ipv4),
        ]
    else:
        roles = [LabRole(name="alpha"), LabRole(name="beta")]

    return LabRequest(
        provider=case.name,
        profile="smoke",
        seed=42,
        roles=roles,
        dry_run=True,
        confirm_live_run=False,
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
        return _FakeWireCreateResponse(
            manifest=_manifest(
                provider=provider,
                exposure=exposure,
                role=role,
                private_group=private_group,
                private_ip=private_ip,
                dry_run=dry_run,
            ),
            call=call,
        )


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
            "--dry-run",
        ]
        if self.call["private_group"] is not None:
            argv.extend(["--private-group", str(self.call["private_group"])])
        if self.call["private_ip"] is not None:
            argv.extend(["--private-ip", str(self.call["private_ip"])])
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


def _manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
    dry_run: bool,
) -> EndpointManifest:
    interfaces = []
    if provider in {"qemu", "virtualbox"}:
        interfaces.append(
            NetworkInterface(
                name="control",
                exposure="control",
                metadata={"planned": True, "type": "control"},
            )
        )
    metadata: dict[str, object] = {"planned": True}
    if private_group is not None:
        metadata["private_group"] = private_group
    if provider == "qemu":
        metadata.update({"backend": "socket-mcast", "type": "qemu-private-net"})
    if provider == "virtualbox":
        metadata.update(
            {
                "bridge_interface": "auto",
                "bridge_selection": "auto",
                "bridge_env": "LIBCRAFTER_VBOX_BRIDGE_IFACE",
                "type": "bridged-lan",
            }
        )

    interfaces.append(
        NetworkInterface(
            name=exposure,
            exposure=exposure,
            ipv4=private_ip,
            provider_network_id=private_group,
            metadata=metadata,
        )
    )

    return EndpointManifest(
        endpoint_id=f"planned-{provider}-{exposure}-{role}",
        provider=provider,
        exposure=exposure,
        status="planned" if dry_run else "created",
        role=role,
        created_at="planned",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root"),
        interfaces=interfaces,
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-lab-provider-matrix/{provider}-{exposure}-{role}",
        metadata={"private_group": private_group} if private_group is not None else {},
    )


if __name__ == "__main__":
    unittest.main()
