"""QEMU provider constants."""

from __future__ import annotations

from collections.abc import Callable

from ...process import CommandResult


QEMU_SYSTEM_COMMAND = "qemu-system-x86_64"
QEMU_ACCEL_ENV = "LIBCRAFTER_QEMU_ACCEL"
QEMU_DEFAULT_ACCEL = "tcg"
SUPPORTED_QEMU_ACCELS = frozenset({"tcg", "kvm"})
QEMU_MEMORY_MB_ENV = "LIBCRAFTER_QEMU_MEMORY_MB"
QEMU_DEFAULT_MEMORY_MB = 2048
QEMU_CPUS_ENV = "LIBCRAFTER_QEMU_CPUS"
QEMU_DEFAULT_CPUS = 2
QEMU_PRIVATE_CIDR_ENV = "LIBCRAFTER_QEMU_PRIVATE_CIDR"
QEMU_DEFAULT_PRIVATE_CIDR = "10.77.0.0/24"
QEMU_SSH_HOST = "127.0.0.1"
QEMU_SSH_USER = "root"
QEMU_SSH_GUEST_PORT = 22
PLANNED_CREATED_AT = "planned"
CONFIRMATION_ERROR = (
    "protected provider execution requires --confirm-live-run; no QEMU resources were created"
)
QemuRunner = Callable[..., CommandResult]
