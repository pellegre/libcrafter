# RIP Probe Daemon Provisioning

`provision-daemon.sh` is run by probe-owned target-service setup on a disposable
lab endpoint to install FRR and configure an FRR `ripd` peer for the `crafter`
RIP stimulus driver. It is intentionally not run from the repository host.

The target serves RIPv2 (RFC 2453) over UDP/520, answers the all-RIP-routers
multicast group `224.0.0.9`, and advertises a documentation-range prefix so the
driver can validate a received RIP response. RIPv1 (RFC 1058) requests are still
answered by the same daemon, and RFC 2453 simple-password / RFC 2082 Keyed-MD5
authentication can be turned on by environment variable.

Defaults use documentation addresses:

- `DRIVER_IP=192.0.2.10` (the `crafter` stimulus driver source address)
- `RIP_NETWORK=192.0.2.0/24` (the network FRR runs RIP on)
- `RIP_ORIGINATE_PREFIX=198.51.100.0/24` (advertised through a Null0 static
  route and `redistribute static`)
- `RIP_BIND_IFACE=` (unset by default; an additional `network <iface>` line when
  set)
- `RIP_AUTH_MODE=none` (one of `none`, `simple`, `md5`)
- `RIP_AUTH_KEY=` (required when `RIP_AUTH_MODE` is `simple` or `md5`)
- `FRR_CONF=/etc/frr/frr.conf`
- `FRR_DAEMONS=/etc/frr/daemons`
- `FRR_TEMPLATE=tools/probe/target_services/rip/ripd.conf.template`

Example lab-endpoint use:

```sh
DRIVER_IP=192.0.2.10 ./provision-daemon.sh
```

With RIPv2 simple-password authentication:

```sh
DRIVER_IP=192.0.2.10 RIP_AUTH_MODE=simple RIP_AUTH_KEY=docs-only \
    ./provision-daemon.sh
```

The script enables `zebra` and `ripd`, renders `ripd.conf.template` from the
environment, installs it as the FRR config, and restarts FRR. It is idempotent:
re-running it re-renders the config and restarts the daemon. Provisioning
stdout/stderr are captured by the probe target-service setup into
`live-artifacts/probe/target-services/rip-provision.{stdout,stderr}.txt`. Inspect
the learned RIB on the endpoint with `vtysh -c 'show ip rip'`.

## RFC scope

- RFC 1058 — RIP version 1 requests are answered by the same daemon.
- RFC 2453 — RIPv2, the default served version, including simple-password
  authentication.
- RFC 2082 — RIPv2 Keyed-MD5 authentication (`RIP_AUTH_MODE=md5`).

RIPng (RFC 2080, UDP/521) is a separate IPv6 daemon and is out of scope for this
IPv4 `ripd` target.

## Documentation-address-only policy

All defaults and examples use documentation address space (`192.0.2.0/24`,
`198.51.100.0/24`). Do not point this target at real networks, and do not commit
endpoint-specific hostnames, public IPs, provider IDs, credentials, or live
packet captures from lab runs. Live runs require explicit confirmation and
provider credentials per the probe live-path policy.
