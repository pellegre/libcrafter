# Examples

The Rust examples live under `crates/crafter/examples/` and build against the
public `crafter` facade API. They are intended to be small templates that agents
can copy when generating packet tools.

Most examples are safe-by-default packet builders or offline readers. They use
dry-run send plans unless `--live` is explicitly supplied.

## Local Runs

Build every example:

```sh
cargo build --examples
```

Run representative examples locally:

```sh
cargo run --example hello_world -- --dry-run
cargo run --example ping -- --iface dry-run0
cargo run --example dns_query -- --dry-run --name example.com
```

Examples that accept `--live` still default to dry-run mode and should be used
only for bounded validation in controlled environments.
