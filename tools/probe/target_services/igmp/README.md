# IGMP Probe Target Service

This directory contains lab-only scaffolding for IGMP live behavior tests. The
scripts are target-service assets: they are meant to run on a disposable
provider endpoint selected by `tools/lab` and `tools/probe`, not on the
developer host.

The service has two controlled roles:

- `provision-listener.sh` starts a small IPv4 multicast listener that joins a
  documentation multicast group and records received datagrams.
- `provision-router.sh` records the multicast-router test role and skips safely
  unless the provider declares controlled-router and multicast support.
- `cleanup.sh` stops the listener process and removes disposable runtime state.

Both provisioning scripts accept `--dry-run` and write inspectable plan or skip
records under `target/probe/target-services/igmp` by default. Dry-runs do not
join multicast groups, change kernel state, or start processes.

Live provisioning is protected by `LIBCRAFTER_PROBE_LAB_TARGET=1`. Without that
lab endpoint marker, live mode exits before joining a multicast group or
touching target runtime state. This keeps IGMP validation from relying on
developer-host multicast membership.

## Defaults

- `IGMP_ARTIFACT_ROOT=target/probe/target-services/igmp`
- `IGMP_GROUP=233.252.0.42`
- `IGMP_PORT=5000`
- `IGMP_BIND_IPV4=0.0.0.0`
- `IGMP_BIND_IFACE=` (recorded in plans for provider wiring)
- `IGMP_PROVIDER_MULTICAST=0`
- `IGMP_PROVIDER_CONTROLLED_ROUTER=0`

`233.252.0.0/24` is the IPv4 multicast documentation block. Do not commit real
provider endpoint addresses, public IPs, credentials, or live packet captures
from IGMP lab runs.

## Dry-Run Examples

```sh
tools/probe/target_services/igmp/provision-listener.sh --dry-run
tools/probe/target_services/igmp/provision-router.sh --dry-run
```

## Live Lab Example

The live path is for a disposable target endpoint only:

```sh
LIBCRAFTER_PROBE_LAB_TARGET=1 \
IGMP_ARTIFACT_ROOT=/root/libcrafter/target/probe/target-services/igmp \
IGMP_GROUP=233.252.0.42 \
IGMP_BIND_IPV4=10.77.0.20 \
tools/probe/target_services/igmp/provision-listener.sh
```

Provider-backed runs should collect the generated files from the artifact root:

- `listener-plan.json`
- `listener.stdout.txt`
- `listener.stderr.txt`
- `listener.pid`
- `router-plan.json`
- `router-skip.json`

