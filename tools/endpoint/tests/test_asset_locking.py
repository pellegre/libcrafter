"""Persistent endpoint asset lease locking coverage."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import TracebackType
from unittest import mock

from tools.endpoint.engine import assets as asset_module
from tools.endpoint.engine.assets import (
    AssetHardware,
    AssetLeaseConflict,
    AssetLockBlocked,
    AssetSSHInfo,
    EndpointAsset,
    EndpointLease,
    acquire_endpoint_asset,
    asset_lease_expired,
    asset_lock_path,
    read_endpoint_asset,
    release_endpoint_asset,
    write_endpoint_asset,
)


class EndpointAssetLockingTest(unittest.TestCase):
    def test_acquire_reads_and_writes_while_holding_asset_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_asset(root))
                held = {"active": False}
                events: list[tuple[str, Path]] = []

                class TrackingLock:
                    def __init__(self, path: Path) -> None:
                        self.path = path

                    def __enter__(self) -> "TrackingLock":
                        held["active"] = True
                        events.append(("enter", self.path))
                        return self

                    def __exit__(
                        self,
                        exc_type: type[BaseException] | None,
                        exc: BaseException | None,
                        traceback: TracebackType | None,
                    ) -> None:
                        events.append(("exit", self.path))
                        held["active"] = False

                original_read = asset_module.read_endpoint_asset
                original_write = asset_module.write_endpoint_asset

                def checked_read(
                    asset_id: str,
                    config: object | None = None,
                ) -> EndpointAsset:
                    self.assertTrue(held["active"])
                    return original_read(asset_id, config)  # type: ignore[arg-type]

                def checked_write(
                    asset: EndpointAsset,
                    config: object | None = None,
                ) -> Path:
                    self.assertTrue(held["active"])
                    return original_write(asset, config)  # type: ignore[arg-type]

                with (
                    mock.patch.object(asset_module, "read_endpoint_asset", checked_read),
                    mock.patch.object(asset_module, "write_endpoint_asset", checked_write),
                ):
                    leased = acquire_endpoint_asset(
                        "qemu-reusable-a",
                        "agent-30",
                        1800,
                        owner="clew-step-30",
                        now="2026-06-28T12:00:00Z",
                        lock_factory=TrackingLock,
                    )

                self.assertEqual(leased.lease.holder, "agent-30")  # type: ignore[union-attr]
                self.assertEqual(
                    events,
                    [
                        ("enter", asset_lock_path("qemu-reusable-a")),
                        ("exit", asset_lock_path("qemu-reusable-a")),
                    ],
                )
                loaded = read_endpoint_asset("qemu-reusable-a")
                self.assertEqual(
                    loaded.lease.expires_at,  # type: ignore[union-attr]
                    "2026-06-28T12:30:00Z",
                )
                self.assertEqual(
                    loaded.lease.metadata["owner"],  # type: ignore[union-attr]
                    "clew-step-30",
                )

    def test_blocked_concurrent_acquire_fails_without_overwriting_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(_asset(root))

                class BlockedLock:
                    def __init__(self, path: Path) -> None:
                        self.path = path

                    def __enter__(self) -> "BlockedLock":
                        raise AssetLockBlocked(f"blocked: {self.path}")

                    def __exit__(
                        self,
                        exc_type: type[BaseException] | None,
                        exc: BaseException | None,
                        traceback: TracebackType | None,
                    ) -> None:
                        return None

                with self.assertRaisesRegex(AssetLockBlocked, "blocked"):
                    acquire_endpoint_asset(
                        "qemu-reusable-a",
                        "agent-30",
                        1800,
                        now="2026-06-28T12:00:00Z",
                        lock_factory=BlockedLock,
                    )

                self.assertIsNone(read_endpoint_asset("qemu-reusable-a").lease)

    def test_expired_lease_can_be_recovered_by_new_holder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _asset(
                        root,
                        lease=EndpointLease(
                            holder="agent-29",
                            leased_at="2026-06-28T11:00:00Z",
                            leased_until="2026-06-28T12:00:00Z",
                            ttl_seconds=3600,
                            metadata={"owner": "old-owner"},
                        ),
                    )
                )

                leased = acquire_endpoint_asset(
                    "qemu-reusable-a",
                    "agent-30",
                    120,
                    metadata={"purpose": "packet validation"},
                    now="2026-06-28T12:01:00Z",
                )

                self.assertEqual(
                    leased.lease.holder,  # type: ignore[union-attr]
                    "agent-30",
                )
                self.assertEqual(
                    leased.lease.leased_at,  # type: ignore[union-attr]
                    "2026-06-28T12:01:00Z",
                )
                self.assertEqual(
                    leased.lease.expires_at,  # type: ignore[union-attr]
                    "2026-06-28T12:03:00Z",
                )
                self.assertEqual(
                    leased.lease.metadata["owner"],  # type: ignore[union-attr]
                    "agent-30",
                )
                self.assertEqual(
                    leased.lease.metadata["purpose"],  # type: ignore[union-attr]
                    "packet validation",
                )
                self.assertFalse(
                    asset_lease_expired(
                        leased.lease,  # type: ignore[arg-type]
                        now="2026-06-28T12:02:59Z",
                    )
                )
                self.assertTrue(
                    asset_lease_expired(
                        leased.lease,  # type: ignore[arg-type]
                        now="2026-06-28T12:03:00Z",
                    )
                )

    def test_active_lease_for_another_holder_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _asset(
                        root,
                        lease=EndpointLease(
                            holder="agent-29",
                            leased_at="2026-06-28T12:00:00Z",
                            leased_until="2026-06-28T12:30:00Z",
                            ttl_seconds=1800,
                        ),
                    )
                )

                with self.assertRaisesRegex(AssetLeaseConflict, "agent-29"):
                    acquire_endpoint_asset(
                        "qemu-reusable-a",
                        "agent-30",
                        1800,
                        now="2026-06-28T12:01:00Z",
                    )

                self.assertEqual(
                    read_endpoint_asset("qemu-reusable-a").lease.holder,  # type: ignore[union-attr]
                    "agent-29",
                )

    def test_release_is_idempotent_and_protects_other_active_holder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with _endpoint_env(root):
                write_endpoint_asset(
                    _asset(
                        root,
                        lease=EndpointLease(
                            holder="agent-30",
                            leased_at="2026-06-28T12:00:00Z",
                            leased_until="2026-06-28T12:30:00Z",
                            ttl_seconds=1800,
                        ),
                    )
                )

                released = release_endpoint_asset(
                    "qemu-reusable-a",
                    "agent-30",
                    now="2026-06-28T12:10:00Z",
                )
                self.assertIsNone(released.lease)
                released_again = release_endpoint_asset(
                    "qemu-reusable-a",
                    "agent-30",
                    now="2026-06-28T12:10:01Z",
                )
                self.assertIsNone(released_again.lease)

                write_endpoint_asset(
                    _asset(
                        root,
                        lease=EndpointLease(
                            holder="agent-31",
                            leased_at="2026-06-28T12:00:00Z",
                            leased_until="2026-06-28T12:30:00Z",
                            ttl_seconds=1800,
                        ),
                    )
                )
                with self.assertRaisesRegex(AssetLeaseConflict, "agent-31"):
                    release_endpoint_asset(
                        "qemu-reusable-a",
                        "agent-30",
                        now="2026-06-28T12:10:00Z",
                    )
                self.assertEqual(
                    read_endpoint_asset("qemu-reusable-a").lease.holder,  # type: ignore[union-attr]
                    "agent-31",
                )


def _asset(
    root: Path,
    *,
    lease: EndpointLease | None = None,
) -> EndpointAsset:
    return EndpointAsset(
        asset_id="qemu-reusable-a",
        substrate="qemu",
        status="available",
        supported_profiles=["linux-root", "packet-capture"],
        ssh=AssetSSHInfo(
            host="192.0.2.10",
            user="root",
            port=2222,
            identity_file=str(
                root / "wire-state" / "assets" / "qemu-reusable-a" / "id_ed25519"
            ),
            known_hosts_file=str(
                root / "wire-state" / "assets" / "qemu-reusable-a" / "known_hosts"
            ),
        ),
        hardware=AssetHardware(cpu_count=4, memory_mb=8192),
        last_check="2026-06-28T12:00:00Z",
        lease=lease,
        metadata={"owner": "endpoint-test"},
    )


def _endpoint_env(root: Path) -> mock._patch_dict[str, str]:
    return mock.patch.dict(
        os.environ,
        {
            "LIBCRAFTER_ENDPOINT_STATE_ROOT": str(root / "wire-state"),
            "LIBCRAFTER_ENDPOINT_ARTIFACT_ROOT": str(root / "wire-artifacts"),
        },
    )


if __name__ == "__main__":
    unittest.main()
