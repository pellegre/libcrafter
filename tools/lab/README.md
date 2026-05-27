# Lab

`lab` is the standalone multi-endpoint topology tool for libcrafter live
validation. It composes lower-level `wire` endpoints into role-based sessions
for workloads such as `oracle` and `probe`.

This initial scaffold provides the command surface before provider adapters and
session lifecycle code are wired in:

```sh
tools/lab/run --help
tools/lab/run providers --help
tools/lab/run plan --help
tools/lab/run doctor --help
tools/lab/run create --help
tools/lab/run destroy --help
tools/lab/run list-sessions --help
tools/lab/run session-info --help
```

Live provider-backed actions will stay behind explicit confirmation flags.
Dry-run planning remains the default path for CI-safe inspection.
