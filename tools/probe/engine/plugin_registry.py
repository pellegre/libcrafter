"""Generic name-keyed plugin registry with auto-discovery for the probe engine.

A :class:`PluginRegistry` maps a string name to an arbitrary value (a protocol
plugin, a builder, a descriptor) and rejects duplicate registrations. The
:func:`autodiscover` helper imports every non-dunder submodule of a package so
that each module can self-register at import time.

This generalizes probe's existing ``PLAN_BUILDERS`` + ``register_plan_builder``
seam in :mod:`planning`. The engine is imported both as ``engine.*`` (CLI via
``python -m engine.cli``) and as ``tools.probe.engine.*`` (tests), so callers
must pass ``__name__``-relative package names to :func:`autodiscover` for it to
work under either import root.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterable
from typing import Generic, TypeVar

T = TypeVar("T")


class UnknownPluginError(ValueError):
    """Raised when a registry is asked for a name that is not registered."""

    def __init__(self, kind: str, name: str, known: Iterable[str]) -> None:
        self.kind = kind
        self.name = name
        self.known = tuple(known)
        known_text = ", ".join(self.known) or "<none>"
        super().__init__(
            f"unknown {kind} plugin {name!r}; known: {known_text}"
        )


class PluginRegistry(Generic[T]):
    """A name-keyed registry of plugin values that rejects duplicates.

    ``kind`` labels the registry in error messages (for example
    ``"probe-protocol"``).
    """

    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._values: dict[str, T] = {}

    @property
    def kind(self) -> str:
        """Return the registry kind label used in error messages."""

        return self._kind

    def register(self, name: str, value: T) -> None:
        """Register ``value`` under ``name``; raise on a duplicate name."""

        if name in self._values:
            raise ValueError(
                f"duplicate {self._kind} plugin {name!r} already registered"
            )
        self._values[name] = value

    def get(self, name: str) -> T | None:
        """Return the value registered under ``name`` or ``None``."""

        return self._values.get(name)

    def require(self, name: str) -> T:
        """Return the value registered under ``name`` or raise.

        Raises :class:`UnknownPluginError` when ``name`` is not registered.
        """

        try:
            return self._values[name]
        except KeyError as exc:
            raise UnknownPluginError(self._kind, name, self.names()) from exc

    def names(self) -> tuple[str, ...]:
        """Return registered names sorted alphabetically."""

        return tuple(sorted(self._values))

    def values(self) -> tuple[T, ...]:
        """Return registered values in sorted-name order."""

        return tuple(self._values[name] for name in self.names())


def autodiscover(package_name: str, package_path: Iterable[str]) -> None:
    """Import every protocol submodule of a package so each self-registers.

    ``package_name`` must be the importable package name (typically the
    package's own ``__name__``) and ``package_path`` its ``__path__``. Every
    non-dunder submodule is imported, skipping any name starting with ``_`` and
    any ``base`` module (shared contract, not a protocol). Importing each module
    is what triggers its ``register(...)`` call.
    """

    for module_info in pkgutil.iter_modules(list(package_path)):
        modname = module_info.name
        if modname.startswith("_") or modname == "base":
            continue
        importlib.import_module(f"{package_name}.{modname}")
