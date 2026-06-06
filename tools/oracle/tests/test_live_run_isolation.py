"""Unit coverage for per-run private-group isolation of concurrent live runs.

Concurrent oracle ``run live`` invocations (e.g. an ICMP run and a DNS run,
possibly in different worktrees) must not reuse the same Hetzner private
network. They are isolated by ``ORACLE_LIVE_PRIVATE_GROUP``: the live CLI sets a
unique value per invocation, and the provider adapters resolve every runtime
private-group reference through ``_oracle_private_group()`` so the override
reaches network/IP allocation. With the env unset, the stable default
``oracle-live-private`` is used so the rest of the unit suite stays deterministic.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools.oracle.engine import cli
from tools.oracle.engine.providers.hetzner import ORACLE_PRIVATE_GROUP
from tools.oracle.engine.providers.registry import resolve_live_provider


OVERRIDE_GROUP = "oracle-live-concurrencytest"
OTHER_OVERRIDE_GROUP = "oracle-live-secondrun"


class _RecordingEndpointClient:
    """Wire client double that records the private group used per create call."""

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def create(
        self,
        *,
        provider: str,
        exposure: str,
        role: str,
        private_group: str | None = None,
        private_ip: str | None = None,
        dry_run: bool = False,
        confirm_live_run: bool = False,
    ) -> SimpleNamespace:
        self.calls.append(
            {
                "provider": provider,
                "exposure": exposure,
                "role": role,
                "private_group": private_group,
                "private_ip": private_ip,
            }
        )
        endpoint_id = f"{provider}-{exposure}-{role}"
        return SimpleNamespace(
            manifest=SimpleNamespace(endpoint_id=endpoint_id),
            record=None,
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
                        "provider_network_id": private_group,
                        "metadata": {"private_group": private_group},
                    }
                ],
                "metadata": {"private_group": private_group},
            },
        )


class LiveRunIsolationTest(unittest.TestCase):
    def test_override_group_flows_into_hetzner_metadata_and_argv(self) -> None:
        adapter = resolve_live_provider("hetzner")
        client = _RecordingEndpointClient()

        with patch.dict(
            os.environ,
            {"ORACLE_LIVE_PRIVATE_GROUP": OVERRIDE_GROUP},
            clear=False,
        ):
            exchange_metadata = adapter.packet_exchange_metadata(dry_run=True)
            infrastructure = adapter.planned_infrastructure(dry_run=True)
            plan = adapter.wire_endpoint_plan(dry_run=True, client=client)
            workflow = adapter.provider_workflow(dry_run=True)

        # Exchange + infrastructure metadata follow the override, not the default.
        self.assertEqual(exchange_metadata["private_group"], OVERRIDE_GROUP)
        self.assertNotEqual(exchange_metadata["private_group"], ORACLE_PRIVATE_GROUP)

        # The derived Hetzner network identity (which names the network
        # `wire-<private_group>`) follows the override too, so concurrent runs
        # land on distinct isolated networks.
        self.assertEqual(infrastructure["network"]["private_group"], OVERRIDE_GROUP)
        self.assertEqual(plan["private_group"], OVERRIDE_GROUP)

        # Every wire create call (argv-equivalent) uses the override.
        self.assertEqual(
            [call["private_group"] for call in client.calls],
            [OVERRIDE_GROUP, OVERRIDE_GROUP],
        )

        # The static create argv builder also carries the override.
        create_commands = [
            command
            for command in workflow
            if command.metadata.get("operation") == "create"
        ]
        self.assertTrue(create_commands)
        for command in create_commands:
            self.assertIn("--private-group", command.argv)
            group_index = command.argv.index("--private-group") + 1
            self.assertEqual(command.argv[group_index], OVERRIDE_GROUP)
            self.assertEqual(command.metadata["private_group"], OVERRIDE_GROUP)

    def test_override_group_flows_into_qemu_metadata(self) -> None:
        adapter = resolve_live_provider("qemu")
        client = _RecordingEndpointClient()

        with patch.dict(
            os.environ,
            {"ORACLE_LIVE_PRIVATE_GROUP": OVERRIDE_GROUP},
            clear=False,
        ):
            exchange_metadata = adapter.packet_exchange_metadata(dry_run=True)
            infrastructure = adapter.planned_infrastructure(dry_run=True)
            plan = adapter.wire_endpoint_plan(dry_run=True, client=client)

        self.assertEqual(exchange_metadata["private_group"], OVERRIDE_GROUP)
        self.assertEqual(infrastructure["network"]["private_group"], OVERRIDE_GROUP)
        self.assertEqual(plan["private_group"], OVERRIDE_GROUP)
        self.assertEqual(
            [call["private_group"] for call in client.calls],
            [OVERRIDE_GROUP, OVERRIDE_GROUP],
        )

    def test_default_group_used_without_override(self) -> None:
        # Guard against accidental leakage of the env var from the host/test runner.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ORACLE_LIVE_PRIVATE_GROUP", None)

            for provider in ("hetzner", "qemu"):
                adapter = resolve_live_provider(provider)
                client = _RecordingEndpointClient()
                exchange_metadata = adapter.packet_exchange_metadata(dry_run=True)
                infrastructure = adapter.planned_infrastructure(dry_run=True)
                plan = adapter.wire_endpoint_plan(dry_run=True, client=client)

                self.assertEqual(
                    exchange_metadata["private_group"],
                    ORACLE_PRIVATE_GROUP,
                    provider,
                )
                self.assertEqual(
                    infrastructure["network"]["private_group"],
                    ORACLE_PRIVATE_GROUP,
                    provider,
                )
                self.assertEqual(plan["private_group"], ORACLE_PRIVATE_GROUP, provider)
                self.assertEqual(
                    [call["private_group"] for call in client.calls],
                    [ORACLE_PRIVATE_GROUP, ORACLE_PRIVATE_GROUP],
                    provider,
                )

    def test_distinct_overrides_yield_distinct_isolation_groups(self) -> None:
        adapter = resolve_live_provider("hetzner")

        with patch.dict(
            os.environ,
            {"ORACLE_LIVE_PRIVATE_GROUP": OVERRIDE_GROUP},
            clear=False,
        ):
            first = adapter.packet_exchange_metadata(dry_run=True)["private_group"]

        with patch.dict(
            os.environ,
            {"ORACLE_LIVE_PRIVATE_GROUP": OTHER_OVERRIDE_GROUP},
            clear=False,
        ):
            second = adapter.packet_exchange_metadata(dry_run=True)["private_group"]

        self.assertEqual(first, OVERRIDE_GROUP)
        self.assertEqual(second, OTHER_OVERRIDE_GROUP)
        self.assertNotEqual(first, second)

    def test_seed_mints_unique_group_when_unset(self) -> None:
        # The per-run seed must set a unique ORACLE_LIVE_PRIVATE_GROUP so two
        # concurrent invocations do not share a provider network.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ORACLE_LIVE_PRIVATE_GROUP", None)
            cli._seed_live_private_group()
            seeded = os.environ.get("ORACLE_LIVE_PRIVATE_GROUP")

        self.assertIsNotNone(seeded)
        assert seeded is not None
        self.assertTrue(seeded.startswith("oracle-live-"))
        self.assertNotEqual(seeded, ORACLE_PRIVATE_GROUP)

    def test_seed_mints_distinct_groups_across_invocations(self) -> None:
        groups: set[str] = set()
        for _ in range(2):
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ORACLE_LIVE_PRIVATE_GROUP", None)
                cli._seed_live_private_group()
                value = os.environ.get("ORACLE_LIVE_PRIVATE_GROUP")
                assert value is not None
                groups.add(value)
        self.assertEqual(len(groups), 2)

    def test_seed_honours_operator_provided_group(self) -> None:
        with patch.dict(
            os.environ,
            {"ORACLE_LIVE_PRIVATE_GROUP": OVERRIDE_GROUP},
            clear=False,
        ):
            cli._seed_live_private_group()
            self.assertEqual(
                os.environ.get("ORACLE_LIVE_PRIVATE_GROUP"),
                OVERRIDE_GROUP,
            )

    def test_live_provider_seeds_group_before_provider_work(self) -> None:
        # `_live_provider` must seed the isolation group before any corpus or
        # lab-request construction. We short-circuit naturally via an invalid
        # `direction`, which raises ValueError on the first line of the work
        # block (after seeding) and returns exit code 2 without touching infra.
        import io
        import contextlib

        args = SimpleNamespace(
            backend="scapy",
            provider="hetzner",
            out="target/oracle/test-live-isolation-seed",
            direction="not-a-direction",
            dry_run=True,
            profile="smoke",
            seed=1,
            count=1,
        )
        adapter = resolve_live_provider("hetzner")

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ORACLE_LIVE_PRIVATE_GROUP", None)
            with contextlib.redirect_stderr(io.StringIO()):
                code = cli._live_provider(args, adapter)
            seeded = os.environ.get("ORACLE_LIVE_PRIVATE_GROUP")

        self.assertEqual(code, 2)
        self.assertIsNotNone(seeded)
        assert seeded is not None
        self.assertTrue(seeded.startswith("oracle-live-"))
        self.assertNotEqual(seeded, ORACLE_PRIVATE_GROUP)


if __name__ == "__main__":
    unittest.main()
