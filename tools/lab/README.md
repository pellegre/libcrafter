# Lab

`lab` is the standalone multi-endpoint session tool for libcrafter live
validation. It composes lower-level `wire` endpoints into role-based sessions
for workloads such as `oracle` and `probe`, records provider capabilities and
command metadata, persists session manifests, and owns repository
push/bootstrap, artifact collection, and cleanup.

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

Registered providers are Hetzner, QEMU, and VirtualBox:

```sh
tools/lab/run providers --json
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json
```

Live provider-backed actions stay behind explicit confirmation flags:

```sh
tools/lab/run create --provider qemu --profile smoke --seed 1 --role stimulus --role target --confirm-live-run --json
tools/lab/run destroy SESSION_ID --json
```

Most validation should enter through `tools/oracle/run live` or
`tools/probe/run`; lab provides their provider-neutral substrate.
