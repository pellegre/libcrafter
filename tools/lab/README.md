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

Registered providers are Hetzner, QEMU, VirtualBox, and Docker. The Docker lab
provider maps to `docker/private`: an isolated provider-owned bridge for
private multi-endpoint sessions. Docker `lan` and `wan` stay direct wire smoke
modes, not lab-backed multi-endpoint modes.

```sh
tools/lab/run providers --json
tools/lab/run plan --provider hetzner --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider virtualbox --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run plan --provider docker --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/oracle/run live --provider docker --dry-run --profile smoke --seed 12345 --count 10
tools/probe/run --provider docker --dry-run --profile smoke --seed 1 --count 10
```

`docker/private` advertises IPv4 unicast, link-layer send and capture,
broadcast, provider MAC knowledge, and controlled services. It does not
advertise IPv6 or a controlled router. The provider keeps the normal lab
offline-default behavior: dry-runs create no Docker resources, and live
creation requires explicit confirmation.

Live provider-backed actions stay behind explicit confirmation flags:

```sh
tools/lab/run create --provider qemu --profile smoke --seed 1 --role stimulus --role target --confirm-live-run --json
tools/lab/run create --provider docker --profile smoke --seed 1 --role stimulus --role target --confirm-live-run --json
tools/lab/run destroy SESSION_ID --json
```

Most validation should enter through `tools/oracle/run live` or
`tools/probe/run`; lab provides their provider-neutral substrate.

Use direct wire smokes for Docker LAN and WAN checks:

```sh
tools/endpoint/smoke/live_docker_lan_icmp.py --plan-only
tools/endpoint/smoke/live_docker_wan_dns.py --plan-only
```

Those smokes test NAT-backed L3 reachability from one constrained container.
They do not assert true LAN L2 behavior, WAN L2 behavior, public inbound
reachability, or lab-backed LAN/WAN multi-endpoint sessions.
