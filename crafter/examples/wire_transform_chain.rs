mod common;

use common::{print_help_if_requested, ExampleResult};
use crafter::prelude::*;

#[derive(Debug, Default)]
struct StatefulDemoTransform {
    seen: usize,
}

impl StatefulDemoTransform {
    fn new() -> Self {
        Self::default()
    }

    fn trace(note: &str) -> TransformTrace {
        TransformTrace::new("stateful-demo").with_note(note)
    }
}

impl PacketTransform for StatefulDemoTransform {
    fn name(&self) -> &'static str {
        "stateful-demo"
    }

    fn transform(
        &mut self,
        mut record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> crafter::wire::Result<()>,
    ) -> crafter::wire::Result<()> {
        self.seen += 1;

        match self.seen {
            1 => {
                record
                    .metadata_mut()
                    .push_transform_trace(Self::trace("one output"));
                emit(record)
            }
            2 => Ok(()),
            3 => {
                let mut first = record.clone();
                first
                    .metadata_mut()
                    .push_transform_trace(Self::trace("fanout first"));
                emit(first)?;

                record
                    .metadata_mut()
                    .push_transform_trace(Self::trace("fanout second"));
                emit(record)
            }
            _ => {
                record
                    .metadata_mut()
                    .push_transform_trace(Self::trace("pass through"));
                emit(record)
            }
        }
    }
}

fn main() -> ExampleResult<()> {
    if print_help_if_requested(
        "usage: cargo run --example wire_transform_chain\n\nRun an offline in-memory Sniffer transform chain.",
    ) {
        return Ok(());
    }

    let source = VecPacketSource::from_packets([
        Raw::from("keep-one"),
        Raw::from("drop-me"),
        Raw::from("duplicate-me"),
    ]);

    let records = Sniffer::new(source)
        .with(StatefulDemoTransform::new())
        .with(TraceAppendTransform::new("after-state").with_note("yielded"))
        .collect_records()?;

    if records.len() != 3 {
        return Err(format!("expected 3 transformed records, got {}", records.len()).into());
    }

    println!("example: wire_transform_chain");
    println!("mode: offline");
    println!("source records: 3");
    println!("yielded records: {}", records.len());

    for (index, record) in records.iter().enumerate() {
        println!("record[{index}] summary: {}", record.packet().summary());
        for trace in record.metadata().transforms() {
            println!(
                "record[{index}] transform: {} note={}",
                trace.name(),
                trace.note().unwrap_or("-")
            );
        }
    }

    Ok(())
}
