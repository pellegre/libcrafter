# Appliance Modules

Appliance modules describe tracked, reusable hardware or userland extensions for
the standard libcrafter appliance. Each module owns one directory under this
tree and declares its generic manifest in `module.json`.

Module manifests may describe supported appliance profiles, optional image
extension metadata, host or VM preparation requirements, non-mutating readiness
checks, generic device families, generic interface roles, and documentation-only
metadata.

Modules must not store real hardware serial numbers, USB IDs, MAC addresses,
SSIDs, provider identifiers, credentials, public addresses, or local live host
details. Host-specific dongle assignment, USB passthrough, kernel driver state,
monitor-mode setup, RF channel state, and provider wiring belong in ignored
operator configuration or endpoint asset state, not in tracked module
manifests.
