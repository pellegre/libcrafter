"""Unit coverage for oracle-owned lab endpoint bootstrap."""

from __future__ import annotations

import unittest

from tools.lab.engine.model import LabEndpoint, LabRole, LabSession
from tools.lab.engine.repo import RepoBootstrapCommand, RepoBootstrapContext
from tools.oracle.engine import bootstrap as oracle_bootstrap
from tools.oracle.engine.providers.registry import resolve_live_provider


PROVIDERS = ("hetzner", "qemu", "virtualbox")


class OracleBootstrapTest(unittest.TestCase):
    def test_provider_bootstrap_plans_share_oracle_roles_and_commands(self) -> None:
        plans_by_provider = {
            provider: _endpoint_bootstrap_plan(provider)
            for provider in PROVIDERS
        }

        baseline_argv = {
            command.role: command.argv
            for command in plans_by_provider["hetzner"]
        }
        for provider, plans in plans_by_provider.items():
            with self.subTest(provider=provider):
                by_role = {command.role: command for command in plans}

                self.assertEqual(set(by_role), {"libcrafter", "reference_backend"})
                self.assertEqual(by_role["libcrafter"].argv, baseline_argv["libcrafter"])
                self.assertEqual(
                    by_role["reference_backend"].argv,
                    baseline_argv["reference_backend"],
                )
                self.assertFalse(
                    any(command.sends_live_packets for command in plans),
                )
                self.assertFalse(
                    any(command.expects_live_packets for command in plans),
                )
                self.assertTrue(
                    _validate_endpoint_bootstrap(provider, plans).passed,
                )

    def test_provider_bootstrap_plans_keep_topology_metadata(self) -> None:
        for provider in PROVIDERS:
            with self.subTest(provider=provider):
                plans = _endpoint_bootstrap_plan(provider)
                for command in plans:
                    if provider == "virtualbox":
                        self.assertFalse(command.metadata["private_network"])
                        self.assertTrue(command.metadata["bridged_lan"])
                    else:
                        self.assertTrue(command.metadata["private_network"])
                        self.assertEqual(
                            command.metadata["private_group"],
                            "oracle-live-private",
                        )

    def test_lab_bootstrap_hook_runs_from_unpacked_repository(self) -> None:
        for provider in PROVIDERS:
            adapter = resolve_live_provider(provider)
            hook = oracle_bootstrap.endpoint_bootstrap_command_hook(
                adapter.name,
                _endpoint_bootstrap_topology(adapter),
            )
            with self.subTest(provider=provider):
                context = _repo_context(provider, adapter)

                command = hook(context)

                self.assertIsInstance(command, RepoBootstrapCommand)
                self.assertEqual(command.argv[:2], ["bash", "-lc"])
                script = command.argv[2]
                self.assertIn("cd /root/libcrafter", script)
                self.assertIn("/root/libcrafter/artifacts/oracle/bootstrap/libcrafter", script)
                self.assertNotIn("tar -xzf", script)
                self.assertNotIn("rm -rf /root/libcrafter", script)

    def test_oracle_bootstrap_command_does_not_unpack_repository(self) -> None:
        for provider in PROVIDERS:
            adapter = resolve_live_provider(provider)
            endpoints = adapter.endpoints(dry_run=True)
            with self.subTest(provider=provider):
                command = oracle_bootstrap.endpoint_bootstrap_command(
                    provider=adapter.name,
                    endpoint=endpoints["libcrafter"],
                    peer=endpoints["reference_backend"],
                    remote_archive="/tmp/repo.tar.gz",
                    remote_dir="/root/libcrafter",
                    topology_metadata=_endpoint_bootstrap_topology(adapter),
                )

                self.assertEqual(command[:2], ["bash", "-lc"])
                self.assertNotIn("tar -xzf", command[2])
                self.assertNotIn("rm -rf /root/libcrafter", command[2])


def _endpoint_bootstrap_plan(provider: str):
    adapter = resolve_live_provider(provider)
    capabilities = adapter.default_provider_capabilities(dry_run=True)
    return oracle_bootstrap.endpoint_bootstrap_plan(
        adapter.name,
        True,
        capabilities,
        _endpoint_bootstrap_topology(adapter),
    )


def _validate_endpoint_bootstrap(provider: str, plans):
    adapter = resolve_live_provider(provider)
    return oracle_bootstrap.validate_endpoint_bootstrap(
        adapter.name,
        plans,
        dry_run=True,
        topology_metadata=_endpoint_bootstrap_topology(adapter),
    )


def _endpoint_bootstrap_topology(adapter) -> dict[str, object]:
    capabilities = adapter.default_provider_capabilities(dry_run=True)
    return oracle_bootstrap.endpoint_bootstrap_topology(
        adapter.packet_exchange_metadata(dry_run=True),
        capabilities,
    )


def _repo_context(provider: str, adapter) -> RepoBootstrapContext:
    endpoints = adapter.endpoints(dry_run=True)
    exposure = adapter.wire_exposure
    roles = [
        LabRole(name="libcrafter", peer_roles=["reference_backend"]),
        LabRole(name="reference_backend", peer_roles=["libcrafter"]),
    ]
    lab_endpoints = {
        role: LabEndpoint(
            endpoint_id=f"{provider}-{role.replace('_', '-')}",
            role=role,
            interface=endpoint.interface,
            ipv4=endpoint.address,
            ipv6=endpoint.ipv6_address,
            metadata=endpoint.metadata,
        )
        for role, endpoint in endpoints.items()
    }
    session = LabSession(
        provider=provider,
        wire_provider=provider,
        wire_exposure=exposure,
        session_id=f"{provider}-oracle-session",
        roles=roles,
        endpoints=list(lab_endpoints.values()),
        remote_dir="/root/libcrafter",
        remote_artifact_root="/root/libcrafter/artifacts/oracle",
        dry_run=False,
    )
    return RepoBootstrapContext(
        session=session,
        endpoint=lab_endpoints["libcrafter"],
        role=roles[0],
        remote_archive="/root/libcrafter-repo.tar.gz",
        remote_dir="/root/libcrafter",
        remote_artifact_root="/root/libcrafter/artifacts/oracle",
        endpoints_by_role=lab_endpoints,
    )


if __name__ == "__main__":
    unittest.main()
