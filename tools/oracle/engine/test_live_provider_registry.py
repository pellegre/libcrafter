"""Unit coverage for oracle live provider adapter registration."""

from __future__ import annotations

import contextlib
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.oracle.engine import cli
from tools.oracle.engine.model import PacketPlan
from tools.oracle.engine.providers.hetzner import ORACLE_PRIVATE_GROUP
from tools.oracle.engine.providers.registry import (
    UnknownLiveProviderError,
    registered_provider_names,
    resolve_live_provider,
)


class LiveProviderRegistryTest(unittest.TestCase):
    def test_hetzner_provider_is_registered(self) -> None:
        self.assertEqual(registered_provider_names(), ("hetzner",))

        adapter = resolve_live_provider("hetzner")

        self.assertEqual(adapter.name, "hetzner")
        self.assertEqual(adapter.wire_provider, "hetzner")
        self.assertEqual(adapter.wire_exposure, "private")
        self.assertEqual(adapter.endpoint_roles, ("libcrafter", "reference_backend"))
        self.assertEqual(adapter.private_group, ORACLE_PRIVATE_GROUP)

    def test_unknown_provider_error_names_requested_and_known_providers(self) -> None:
        with self.assertRaises(UnknownLiveProviderError) as error:
            resolve_live_provider("virtualbox")

        message = str(error.exception)
        self.assertIn("virtualbox", message)
        self.assertIn("hetzner", message)

    def test_hetzner_adapter_exposes_report_plans(self) -> None:
        adapter = resolve_live_provider("hetzner")

        capabilities = adapter.default_provider_capabilities(dry_run=True)
        infrastructure = adapter.planned_infrastructure(dry_run=True)
        endpoints = adapter.endpoints(dry_run=True)
        workflow = adapter.provider_workflow(dry_run=True)
        bootstrap = adapter.endpoint_bootstrap_plan(dry_run=True)

        self.assertEqual(capabilities["provider"], "hetzner")
        self.assertEqual(infrastructure["provider"], "hetzner")
        self.assertEqual(set(endpoints), {"libcrafter", "reference_backend"})
        self.assertTrue(all(endpoint.metadata["private_network"] for endpoint in endpoints.values()))
        self.assertTrue(adapter.validate_provider_workflow(workflow, dry_run=True).passed)
        self.assertTrue(adapter.validate_endpoint_bootstrap(bootstrap, dry_run=True).passed)
        self.assertEqual(
            {command.role for command in bootstrap},
            {"libcrafter", "reference_backend"},
        )

        workflow_purposes = {command.purpose for command in workflow}
        self.assertIn(adapter.artifact_collection_purpose, workflow_purposes)
        self.assertIn(adapter.teardown_purpose, workflow_purposes)
        doctor = next(command for command in workflow if command.purpose == "check-hetzner-provider")
        self.assertIn("--provider", doctor.argv)
        self.assertIn("hetzner", doctor.argv)
        self.assertIn("--exposure", doctor.argv)
        self.assertIn("private", doctor.argv)

    def test_hetzner_adapter_plans_wire_endpoints_with_private_exposure(self) -> None:
        adapter = resolve_live_provider("hetzner")
        client = _FakeWireClient()

        plan = adapter.wire_endpoint_plan(dry_run=True, client=client)

        self.assertEqual(plan["provider"], "hetzner")
        self.assertEqual(plan["exposure"], "private")
        self.assertEqual(plan["private_group"], ORACLE_PRIVATE_GROUP)
        self.assertEqual(set(plan["live_endpoints"]), {"libcrafter", "reference_backend"})
        self.assertEqual(
            [(call["provider"], call["exposure"], call["role"]) for call in client.calls],
            [
                ("hetzner", "private", "libcrafter"),
                ("hetzner", "private", "reference_backend"),
            ],
        )
        self.assertTrue(all(call["dry_run"] for call in client.calls))
        self.assertTrue(all(call["private_group"] == ORACLE_PRIVATE_GROUP for call in client.calls))

    def test_hetzner_adapter_exposes_execution_policy_hooks(self) -> None:
        adapter = resolve_live_provider("hetzner")
        plan = PacketPlan(
            stack=["ipv4"],
            fields={"ipv4": {"ttl": 1}},
            profile="default",
            seed=7,
            index=3,
            direction="reference_to_libcrafter",
            family="ipv4",
            metadata={"root": "l3:ipv4"},
        )

        policy = adapter.wire_comparison_policy(plan)
        transit_plan = adapter.apply_transit_plan(plan)
        libcrafter_command = adapter.endpoint_remote_command(
            endpoint_role="libcrafter",
            remote_dir="/root/libcrafter",
            request_path="/tmp/request.json",
            out_dir="/tmp/out",
        )
        reference_command = adapter.endpoint_remote_command(
            endpoint_role="reference_backend",
            remote_dir="/root/libcrafter",
            request_path="/tmp/request.json",
            out_dir="/tmp/out",
        )

        self.assertEqual(policy["provider"], "hetzner")
        self.assertEqual(policy["compare_root"], "l3:ipv4")
        self.assertIn("ipv4.ttl", policy["mutable_fields"])
        self.assertFalse(policy["strict_bytes"])
        self.assertEqual(transit_plan.fields["ipv4"]["ttl"], 64)
        self.assertEqual(transit_plan.metadata["wire"]["provider"], "hetzner")
        self.assertEqual(libcrafter_command[:2], ["bash", "-lc"])
        self.assertIn("cargo run", libcrafter_command[2])
        self.assertEqual(reference_command[:2], ["bash", "-lc"])
        self.assertIn("python3 -m engine.backends.scapy.live", reference_command[2])

    def test_live_parser_accepts_local_dry_run_and_registered_providers(self) -> None:
        parser = cli.build_parser()

        local_args = parser.parse_args(["live", "--provider", "local-dry-run"])
        hetzner_args = parser.parse_args(["live", "--provider", "hetzner"])

        self.assertEqual(local_args.provider, "local-dry-run")
        self.assertEqual(hetzner_args.provider, "hetzner")
        with (
            self.assertRaises(SystemExit),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            parser.parse_args(["live", "--provider", "virtualbox"])

    def test_live_dispatch_resolves_hetzner_adapter(self) -> None:
        args = _live_args("hetzner")
        seen: dict[str, object] = {}

        def fake_live_provider(_args, adapter) -> int:
            seen["provider"] = _args.provider
            seen["adapter"] = adapter
            return 17

        with patch.object(cli, "_live_provider", side_effect=fake_live_provider):
            code = cli._live(args)

        self.assertEqual(code, 17)
        self.assertEqual(seen["provider"], "hetzner")
        self.assertIs(seen["adapter"], resolve_live_provider("hetzner"))

    def test_live_dispatch_rejects_unknown_provider_before_planning(self) -> None:
        args = _live_args("virtualbox")
        stderr = io.StringIO()

        with (
            patch.object(cli, "_live_provider") as live_provider,
            contextlib.redirect_stderr(stderr),
        ):
            code = cli._live(args)

        self.assertEqual(code, 2)
        live_provider.assert_not_called()
        self.assertIn("virtualbox", stderr.getvalue())
        self.assertIn("hetzner", stderr.getvalue())


class _FakeRecord:
    def __init__(self, role: str) -> None:
        self.role = role

    def to_dict(self) -> dict[str, object]:
        return {
            "operation": "create-endpoint",
            "role": self.role,
            "exit_code": 0,
        }


class _FakeWireClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str,
        private_ip: str,
        dry_run: bool,
        confirm_live_run: bool,
    ):
        self.calls.append(
            {
                "provider": provider,
                "exposure": exposure,
                "role": role,
                "private_group": private_group,
                "private_ip": private_ip,
                "dry_run": dry_run,
                "confirm_live_run": confirm_live_run,
            }
        )
        endpoint_id = f"{provider}-{exposure}-{role}"
        return SimpleNamespace(
            manifest=SimpleNamespace(endpoint_id=endpoint_id),
            record=_FakeRecord(role),
            json_data={
                "endpoint_id": endpoint_id,
                "provider": provider,
                "exposure": exposure,
                "role": role,
                "interfaces": [
                    {
                        "name": "oracle0",
                        "exposure": exposure,
                        "ipv4": private_ip,
                        "metadata": {"private_group": private_group},
                    }
                ],
                "metadata": {"private_group": private_group},
            },
        )


def _live_args(provider: str) -> SimpleNamespace:
    return SimpleNamespace(
        backend="scapy",
        provider=provider,
        out="target/oracle/test-live-provider-dispatch",
        direction="live_exchange",
        dry_run=True,
        profile="smoke",
        seed=1,
        count=1,
    )


if __name__ == "__main__":
    unittest.main()
