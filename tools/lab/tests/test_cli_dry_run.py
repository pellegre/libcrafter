"""Dry-run coverage for the standalone lab CLI."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from tools.lab.engine import cli
from tools.lab.engine.model import LabCommandPlan
from tools.endpoint.engine.model import (
    EndpointManifest,
    EndpointSSHInfo,
    NetworkInterface,
    ProviderResources,
)


class LabCliProviderListTest(unittest.TestCase):
    def test_providers_json_returns_registered_provider_metadata(self) -> None:
        exit_code, stdout, stderr = _run_cli("providers", "--json")

        self.assertEqual(exit_code, 0, stderr)
        payload = json.loads(stdout)
        providers = {provider["name"]: provider for provider in payload["providers"]}

        self.assertTrue(payload["ok"])
        self.assertEqual(sorted(providers), ["docker", "hetzner", "qemu", "virtualbox"])
        self.assertEqual(providers["docker"]["wire_provider"], "docker")
        self.assertEqual(providers["docker"]["wire_exposure"], "private")
        self.assertEqual(providers["hetzner"]["wire_provider"], "hetzner")
        self.assertEqual(providers["hetzner"]["wire_exposure"], "private")
        self.assertEqual(providers["qemu"]["wire_provider"], "qemu")
        self.assertEqual(providers["qemu"]["wire_exposure"], "private")
        self.assertEqual(providers["virtualbox"]["wire_provider"], "virtualbox")
        self.assertEqual(providers["virtualbox"]["wire_exposure"], "private")
        for provider in providers.values():
            self.assertIn("credentials_available", provider)
            self.assertEqual(provider["capabilities"]["provider"], provider["name"])
            self.assertTrue(provider["capabilities"]["dry_run"])


class LabCliDoctorTest(unittest.TestCase):
    def test_doctor_calls_wire_doctor_through_registered_adapter_in_dry_run(self) -> None:
        fake = _FakeEndpointClient()

        with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
            exit_code, stdout, stderr = _run_cli(
                "doctor",
                "--provider",
                "virtualbox",
                "--json",
            )

        self.assertEqual(exit_code, 0, stderr)
        payload = json.loads(stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["provider"], "virtualbox")
        self.assertEqual(payload["wire_provider"], "virtualbox")
        self.assertEqual(payload["wire_exposure"], "private")
        self.assertTrue(payload["dry_run"])
        self.assertEqual(
            fake.doctor_calls,
            [{"provider": "virtualbox", "exposure": "private", "dry_run": True}],
        )
        self.assertEqual(payload["wire_doctor"]["provider"], "virtualbox")
        self.assertEqual(payload["command_records"][0]["operation"], "endpoint.doctor")
        self.assertFalse(payload["command_records"][0]["live_mutation"])
        self.assertEqual(fake.create_calls, [])


class LabCliPlanTest(unittest.TestCase):
    def test_plan_defaults_to_smoke_roles_when_roles_are_omitted(self) -> None:
        fake = _FakeEndpointClient()

        with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
            exit_code, stdout, stderr = _run_cli(
                "plan",
                "--provider",
                "docker",
                "--dry-run",
                "--json",
            )

        self.assertEqual(exit_code, 0, stderr)
        session = json.loads(stdout)
        self.assertEqual([role["name"] for role in session["roles"]], ["stimulus", "target"])
        self.assertEqual([call["role"] for call in fake.create_calls], ["stimulus", "target"])
        self.assertTrue(all(call["dry_run"] for call in fake.create_calls))

    def test_plan_emits_lab_session_for_each_provider_without_writing_manifests(self) -> None:
        cases = [
            ("docker", "docker", "private"),
            ("hetzner", "hetzner", "private"),
            ("qemu", "qemu", "private"),
            ("virtualbox", "virtualbox", "private"),
        ]

        for provider, wire_provider, exposure in cases:
            with self.subTest(provider=provider):
                fake = _FakeEndpointClient()
                with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
                    exit_code, stdout, stderr = _run_cli(
                        "plan",
                        "--provider",
                        provider,
                        "--profile",
                        "smoke",
                        "--seed",
                        "1",
                        "--role",
                        "stimulus",
                        "--role",
                        "target",
                        "--dry-run",
                        "--json",
                    )

                self.assertEqual(exit_code, 0, stderr)
                session = json.loads(stdout)
                self.assertEqual(session["provider"], provider)
                self.assertEqual(session["wire_provider"], wire_provider)
                self.assertEqual(session["wire_exposure"], exposure)
                self.assertTrue(session["dry_run"])
                self.assertEqual([role["name"] for role in session["roles"]], ["stimulus", "target"])
                self.assertEqual([endpoint["role"] for endpoint in session["endpoints"]], ["stimulus", "target"])
                self.assertEqual(session["created_endpoint_ids"], [])
                self.assertEqual(len(session["command_records"]), 2)
                self.assertTrue(
                    all(check["passed"] for check in session["validation_checks"]),
                    session["validation_checks"],
                )

                self.assertEqual([call["role"] for call in fake.create_calls], ["stimulus", "target"])
                self.assertTrue(all(call["provider"] == wire_provider for call in fake.create_calls))
                self.assertTrue(all(call["exposure"] == exposure for call in fake.create_calls))
                self.assertTrue(all(call["dry_run"] for call in fake.create_calls))
                self.assertTrue(all(call["write_manifest"] is False for call in fake.create_calls))
                self.assertTrue(all(call["confirm_live_run"] is False for call in fake.create_calls))
                if exposure == "private":
                    self.assertTrue(all(call["private_group"] for call in fake.create_calls))
                    self.assertTrue(all(call["private_ip"] for call in fake.create_calls))
                else:
                    self.assertEqual([call["private_group"] for call in fake.create_calls], [None, None])
                    self.assertEqual([call["private_ip"] for call in fake.create_calls], [None, None])
                self.assertEqual(fake.doctor_calls, [])

    def test_plan_accepts_workload_label_and_role_address_overrides(self) -> None:
        fake = _FakeEndpointClient()

        with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
            exit_code, stdout, stderr = _run_cli(
                "plan",
                "--provider",
                "qemu",
                "--profile",
                "smoke",
                "--seed",
                "1",
                "--workload-label",
                "probe",
                "--role",
                "stimulus=10.77.0.88",
                "--role",
                "target",
                "--role-address",
                "target=10.77.0.99",
                "--dry-run",
                "--json",
            )

        self.assertEqual(exit_code, 0, stderr)
        session = json.loads(stdout)
        self.assertEqual(session["session_id"], "lab-qemu-probe-smoke-seed-1")
        self.assertEqual(
            [role["requested_private_ipv4"] for role in session["roles"]],
            ["10.77.0.88", "10.77.0.99"],
        )
        self.assertEqual(
            [call["private_ip"] for call in fake.create_calls],
            ["10.77.0.88", "10.77.0.99"],
        )


class LabCliCreateDryRunTest(unittest.TestCase):
    def test_create_dry_run_uses_default_roles_without_persisting_manifest(self) -> None:
        fake = _FakeEndpointClient()

        with patch("tools.lab.engine.endpoint_client.EndpointClient", return_value=fake):
            exit_code, stdout, stderr = _run_cli(
                "create",
                "--provider",
                "docker",
                "--dry-run",
                "--json",
            )

        self.assertEqual(exit_code, 0, stderr)
        session = json.loads(stdout)
        self.assertTrue(session["dry_run"])
        self.assertEqual([role["name"] for role in session["roles"]], ["stimulus", "target"])
        self.assertEqual(session["created_endpoint_ids"], [])
        self.assertEqual([call["role"] for call in fake.create_calls], ["stimulus", "target"])
        self.assertTrue(all(call["dry_run"] for call in fake.create_calls))
        self.assertTrue(all(call["write_manifest"] is False for call in fake.create_calls))
        self.assertTrue(all(call["confirm_live_run"] is False for call in fake.create_calls))


def _run_cli(*args: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = cli.main(list(args))
    return exit_code, stdout.getvalue(), stderr.getvalue()


class _FakeEndpointClient:
    def __init__(self) -> None:
        self.doctor_calls: list[dict[str, object]] = []
        self.create_calls: list[dict[str, object]] = []

    def doctor(
        self,
        *,
        provider: str,
        exposure: str,
        dry_run: bool,
    ) -> "_FakeEndpointResponse":
        call = {"provider": provider, "exposure": exposure, "dry_run": dry_run}
        self.doctor_calls.append(call)
        return _FakeEndpointResponse(
            operation="doctor",
            provider=provider,
            exposure=exposure,
            role=None,
            dry_run=dry_run,
            manifest=None,
            json_data={
                "ok": True,
                "provider": provider,
                "exposure": exposure,
                "dry_run": dry_run,
                "checks": [],
            },
        )

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
    ) -> "_FakeEndpointResponse":
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
        self.create_calls.append(call)
        manifest = _manifest(
            provider=provider,
            exposure=exposure,
            role=role,
            private_group=private_group,
            private_ip=private_ip,
        )
        return _FakeEndpointResponse(
            operation="create",
            provider=provider,
            exposure=exposure,
            role=role,
            dry_run=dry_run,
            manifest=manifest,
            json_data=manifest.to_dict(),
        )


class _FakeEndpointResponse:
    def __init__(
        self,
        *,
        operation: str,
        provider: str,
        exposure: str,
        role: str | None,
        dry_run: bool,
        manifest: EndpointManifest | None,
        json_data: dict[str, object],
    ) -> None:
        self.operation = operation
        self.provider = provider
        self.exposure = exposure
        self.role = role
        self.dry_run = dry_run
        self.manifest = manifest
        self.json_data = json_data
        self.ok = True

    def command_plan(
        self,
        *,
        purpose: str | None = None,
        role: str | None = None,
        artifacts: list[str] = (),
    ) -> LabCommandPlan:
        argv = [
            "tools/endpoint/run",
            "doctor" if self.operation == "doctor" else "create",
            "--provider",
            self.provider,
            "--exposure",
            self.exposure,
            "--json",
            "--dry-run",
        ]
        if self.operation == "create" and (role or self.role):
            argv.extend(["--role", role or self.role or "role"])
        return LabCommandPlan(
            purpose=purpose or f"endpoint {self.operation}",
            role=role,
            argv=argv,
            operation=f"endpoint.{self.operation}",
            dry_run=self.dry_run,
            live_mutation=False,
            artifacts=list(artifacts),
            metadata={
                "provider": self.provider,
                "exposure": self.exposure,
                "dry_run": self.dry_run,
            },
        )


def _manifest(
    *,
    provider: str,
    exposure: str,
    role: str,
    private_group: str | None,
    private_ip: str | None,
) -> EndpointManifest:
    interface_metadata: dict[str, object] = {}
    if private_group is not None:
        interface_metadata["private_group"] = private_group
    if provider == "virtualbox":
        interface_metadata["bridge_interface"] = "auto"
    return EndpointManifest(
        endpoint_id=f"planned-{provider}-{exposure}-{role}",
        provider=provider,
        exposure=exposure,
        status="planned",
        role=role,
        created_at="planned",
        ssh=EndpointSSHInfo(host="127.0.0.1", user="root", port=22),
        interfaces=[
            NetworkInterface(
                name=exposure,
                exposure=exposure,
                ipv4=private_ip,
                provider_network_id=private_group,
                metadata=interface_metadata,
            )
        ],
        provider_resources=ProviderResources(),
        artifact_dir=f"/tmp/libcrafter-lab-test/{provider}-{exposure}-{role}",
        metadata={"private_group": private_group} if private_group is not None else {},
    )


if __name__ == "__main__":
    unittest.main()
