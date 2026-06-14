// Offline oracle vector generator.
//
// The packet/DNS materializer is shared with the `live_endpoint` bin so both
// build packets from identical code and the live endpoint can never drift
// behind the offline materializer.
mod materialize_core;

fn main() -> materialize_core::ExampleResult<()> {
    materialize_core::main()
}
