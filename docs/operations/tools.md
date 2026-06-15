# Tools Overview

The `tools/` directory holds the four Python/Rust modules that take `crafter`
off the developer machine and onto disposable, provider-backed infrastructure
for live validation. They form a layered stack: the lower two manage where
packets run, and the upper two decide what to validate.

```text
        oracle        probe          <- user-facing validators
           \           /
            \         /
              lab                     <- multi-endpoint role sessions
               |
            endpoint                  <- one disposable endpoint
```

Read the stack bottom-up: `endpoint` owns one disposable machine, `lab`
composes endpoints into a role session, and `oracle` and `probe` are the two
validators you actually invoke. Most workflows enter through `oracle` or
`probe`; they reach down through `lab` to `endpoint` for you.

## endpoint

`endpoint` manages the lifecycle of a single disposable endpoint: create, exec,
upload, download, collect-artifacts, and destroy, across the Hetzner, QEMU,
VirtualBox, and Docker providers. It owns only mechanical endpoint plumbing —
provisioning, SSH transport, file transfer, and artifact collection — and never
infers packet semantics. Reach for it directly only to confirm a provider is
ready (`doctor`) or to debug one endpoint in isolation; otherwise it is the
substrate that `lab` drives. Full setup, credentials, and cleanup live in the
[endpoint provider guide](endpoint.md) and
[`tools/endpoint/README.md`](../../tools/endpoint/README.md).

Safe dry-run / offline examples:

```sh
tools/endpoint/run doctor --provider qemu --exposure private --json
tools/endpoint/run create --provider qemu --exposure private --private-group lab-a --dry-run --json
tools/endpoint/run list
```

## lab

`lab` composes endpoints into a multi-endpoint, role-based session (for example
a `stimulus` endpoint and a `target` endpoint) and owns session planning,
provider capability metadata, repository push/bootstrap, artifact collection,
and cleanup. It is protocol-agnostic: it passes caller-supplied profile, role,
and workload fields through without inferring behavior from them. You rarely run
`lab` directly — it is the provider-neutral substrate that `oracle` live runs
and `probe` runs sit on. Use it on its own mainly to plan or inspect a session
shape. See the [lab sessions guide](lab.md) and
[`tools/lab/README.md`](../../tools/lab/README.md).

Safe dry-run / offline examples:

```sh
tools/lab/run providers --json
tools/lab/run plan --provider qemu --dry-run --profile smoke --seed 1 --role stimulus --role target --json
tools/lab/run doctor --help
```

## oracle

`oracle` answers "do libcrafter's bytes and decoded model match a reference
backend?" It generates a packet corpus from executable specs and compares
libcrafter against a full read/write/live reference backend or a parser-only
backend (Wireshark/tshark) across offline, pcap, and live modes. Run it after changing
builders, decoders, or pcap I/O, to catch wire-level regressions before they
ship. Offline and pcap modes need no provider; live modes plan through `lab`.
See the [oracle validation guide](validation.md) and
[`tools/oracle/README.md`](../../tools/oracle/README.md).

Safe dry-run / offline examples:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
tools/oracle/run pcap --profile smoke --seed 1 --count 10
tools/oracle/run live --provider local-dry-run --profile smoke --seed 1 --count 10
```

## probe

`probe` answers "does a real peer respond the way libcrafter expects?" It sends
libcrafter-built packets through a disposable `lab` session, captures the
kernel or controlled-service replies, decodes them with libcrafter, and checks
them against each case contract (DNS, DHCP, ARP, UDP behavior, plus an IPSec
suite). Run it after changing send paths or request/response interaction logic.
Dry-runs plan the full exchange — request artifacts, target setup, role
addresses — without starting services or sending traffic. See the
[probe validation guide](probe.md) and
[`tools/probe/README.md`](../../tools/probe/README.md).

Safe dry-run / offline examples:

```sh
tools/probe/run --provider qemu --dry-run --profile smoke --seed 1 --count 10
tools/probe/run --provider qemu --dry-run --profile behavior --seed 1052 --count 40
tools/probe/run --provider qemu --dry-run --profile ipsec --out target/probe/ipsec-dry-run
```

## Safe by default

Every tool defaults to dry-run/offline: dry-run plans create no provider
resources, read no credentials, and send no packets. A live, provider-backed run
is opt-in and requires an explicit confirmation flag (`--confirm-live-run`, or
`--live` for the VirtualBox smoke) plus provider credentials in the environment
(`HETZNER_API_TOKEN` or `HCLOUD_TOKEN` for Hetzner; local prerequisites for
QEMU, VirtualBox, and Docker). The example commands on this page are all
dry-run/offline and use no live targets. Keep crafted live traffic on disposable
provider endpoints, not on the developer machine.
