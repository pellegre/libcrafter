# BGP Lab Peer Provisioning

`provision-peer.sh` is run on a disposable lab endpoint to install FRR and
configure a BGP peer for the `crafter` BGP session driver. It is intentionally
not run from the repository host.

Defaults use documentation addresses and private ASNs:

- `DRIVER_IP=192.0.2.10`
- `DRIVER_AS=65000`
- `PEER_AS=65001`
- `PEER_ROUTER_ID=192.0.2.1`
- `PEER_ORIGINATE_PREFIX=198.51.100.0/24`
- `FRR_CONF=/etc/frr/frr.conf`
- `FRR_DAEMONS=/etc/frr/daemons`
- `FRR_TEMPLATE=tools/live-lab/bgp/frr.conf.template`

Example lab-endpoint use:

```sh
DRIVER_IP=192.0.2.10 ./provision-peer.sh
```

The script enables `zebra`, `staticd`, and `bgpd`. The generated FRR config
uses `router bgp 65001`, sets the driver neighbor as `remote-as 65000`,
activates IPv4 and IPv6 unicast address families, and originates
`198.51.100.0/24` through a Null0 static route so the driver can validate a
received UPDATE.

Do not commit endpoint-specific hostnames, public IPs, provider IDs,
credentials, or live packet captures from lab runs.
