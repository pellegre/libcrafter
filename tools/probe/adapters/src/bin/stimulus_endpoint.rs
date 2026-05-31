//! libcrafter probe stimulus endpoint binary.
//!
//! Thin entrypoint over the `probe_adapters` library. All argument parsing,
//! the JSON request/plan contracts, packet construction, live send/capture,
//! validation, and report writing live in the library's `common` and
//! per-protocol modules.

use probe_adapters::common::{run, ExampleResult};

fn main() -> ExampleResult<()> {
    run()
}
