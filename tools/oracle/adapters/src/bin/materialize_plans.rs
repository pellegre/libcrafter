// Offline oracle vector generator.
//
// The packet/DNS materializer is shared with the `live_endpoint` bin via the
// `materialize_core` module so both build packets from identical code and the
// live endpoint can never drift behind the offline materializer.
#[path = "../materialize_core.rs"]
mod materialize_core;

fn main() -> materialize_core::ExampleResult<()> {
    materialize_core::main()
}
