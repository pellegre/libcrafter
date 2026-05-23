# Examples

The Rust examples live under `crates/crafter/examples/` and build against the
public `crafter` facade API. They are intended to be small templates that agents
can copy when generating packet tools.

Most examples are packet builders or offline readers. They use
dry-run send plans unless `--live` is explicitly supplied.




These examples are for isolated lab networks only. They must not be run on a
developer workstation, a shared LAN, or any network where the traffic does not
belong to the test operator.

By default these examples only compile packets and print dry-run plans. Any
traffic-changing behavior requires all of the following:

- `--live`
- `--i-understand-isolated-lab`
- `LIBCRAFTER_LIVE_LAB=1`

The examples do not write firewall rules or change kernel forwarding settings.
They print packet plans and leave host mutation to disposable live-lab
orchestration.

Run a dry-run locally:

```sh
```

Run live examples only from a disposable lab created by `tools/live-lab/`:

```sh
  --live --i-understand-isolated-lab --iface replace-with-lab-interface
```
