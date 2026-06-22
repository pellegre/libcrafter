"""Generic name-keyed plugin registry with package auto-discovery.

The oracle's per-stage protocol plugins (generator sampling, Scapy encode/decode,
Wireshark decode) all share one registration shape: a protocol module registers a
value under a layer name, and the stage orchestrator looks it up by name. This
module provides that shared mechanism so every stage registry mirrors the in-repo
``providers/registry.py`` and ``backends/registry.py`` conventions instead of
hand-rolling its own dict and ``Unknown...Error``.

Auto-discovery imports every non-dunder submodule of a ``protocols`` package so
each protocol module self-registers at import. Discovery uses ``__name__``-relative
module names supplied by the caller, so it works whether the engine is imported as
``engine.*`` (CLI, ``python -m engine.cli``) or as ``tools.oracle.engine.*``
(tests), with ``tools/`` resolved as a PEP 420 namespace package.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Generic, TypeVar

_T = TypeVar("_T")


class UnknownPluginError(ValueError):
    """Raised when a registry is asked for a name that is not registered."""

    def __init__(self, kind: str, name: str, known: tuple[str, ...]) -> None:
        known_names = ", ".join(known) or "<none>"
        super().__init__(
            f"unsupported oracle {kind} plugin {name!r}; known {kind} plugins: {known_names}"
        )
        self.kind = kind
        self.name = name
        self.known = known


class PluginRegistry(Generic[_T]):
    """A name-keyed registry of per-protocol plugins for one oracle stage."""

    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._plugins: dict[str, _T] = {}

    @property
    def kind(self) -> str:
        """Return the registry kind used in error messages."""

        return self._kind

    def register(self, name: str, value: _T) -> None:
        """Register ``value`` under ``name``; reject duplicate registrations.

        A protocol must not register the same layer twice, so a repeated name is a
        programming error rather than an override.
        """

        if name in self._plugins:
            raise ValueError(
                f"duplicate oracle {self._kind} plugin {name!r}; already registered"
            )
        self._plugins[name] = value

    def get(self, name: str) -> _T | None:
        """Return the registered plugin for ``name`` or ``None`` if absent."""

        return self._plugins.get(name)

    def require(self, name: str) -> _T:
        """Return the registered plugin for ``name`` or raise ``UnknownPluginError``."""

        try:
            return self._plugins[name]
        except KeyError as exc:
            raise UnknownPluginError(self._kind, name, self.names()) from exc

    def names(self) -> tuple[str, ...]:
        """Return the registered names in sorted order."""

        return tuple(sorted(self._plugins))

    def values(self) -> tuple[_T, ...]:
        """Return the registered plugins in name order."""

        return tuple(self._plugins[name] for name in self.names())


def autodiscover(package_name: str, package_path) -> None:
    """Import every non-dunder submodule of a ``protocols`` package.

    ``package_name`` is the package's ``__name__`` and ``package_path`` is its
    ``__path__``; passing both makes discovery work under either import root. Each
    imported module self-registers its plugins as a side effect of import. Submodule
    names starting with ``_`` and a ``base`` module (the plugin contract, not a
    protocol) are skipped.
    """

    for module_info in pkgutil.iter_modules(package_path):
        modname = module_info.name
        if modname.startswith("_") or modname == "base":
            continue
        importlib.import_module(f"{package_name}.{modname}")
