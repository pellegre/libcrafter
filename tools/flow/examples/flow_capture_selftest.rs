use std::env;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crafter_flow::{CaptureSource, PcapCaptureSource};

const DEFAULT_COUNT: usize = 5;
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const CAPTURE_POLL_MS: u64 = 250;

struct Args {
    iface: String,
    filter: Option<String>,
    count: usize,
    timeout: Duration,
}

fn usage(program: &str) -> String {
    format!("usage: {program} --iface <name> [--filter <bpf>] [--count <n>] [--timeout-ms <ms>]")
}

fn parse_value<'a>(
    args: &mut impl Iterator<Item = &'a String>,
    flag: &str,
    program: &str,
) -> Result<&'a str, String> {
    args.next()
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value\n{}", usage(program)))
}

fn parse_args() -> Result<Args, String> {
    let raw_args: Vec<String> = env::args().collect();
    let program = raw_args
        .first()
        .map(String::as_str)
        .unwrap_or("flow_capture_selftest");
    let mut args = raw_args.iter().skip(1);
    let mut iface = None;
    let mut filter = None;
    let mut count = DEFAULT_COUNT;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iface" => iface = Some(parse_value(&mut args, "--iface", program)?.to_string()),
            "--filter" => filter = Some(parse_value(&mut args, "--filter", program)?.to_string()),
            "--count" => {
                count = parse_value(&mut args, "--count", program)?
                    .parse()
                    .map_err(|_| {
                        format!("--count must be a positive integer\n{}", usage(program))
                    })?;
            }
            "--timeout-ms" => {
                timeout_ms = parse_value(&mut args, "--timeout-ms", program)?
                    .parse()
                    .map_err(|_| {
                        format!(
                            "--timeout-ms must be a positive integer\n{}",
                            usage(program)
                        )
                    })?;
            }
            "--help" | "-h" => return Err(usage(program)),
            unknown => return Err(format!("unknown argument: {unknown}\n{}", usage(program))),
        }
    }

    let iface = iface.ok_or_else(|| format!("--iface is required\n{}", usage(program)))?;
    if count == 0 {
        return Err(format!("--count must be at least 1\n{}", usage(program)));
    }
    if timeout_ms == 0 {
        return Err(format!(
            "--timeout-ms must be at least 1\n{}",
            usage(program)
        ));
    }

    Ok(Args {
        iface,
        filter,
        count,
        timeout: Duration::from_millis(timeout_ms),
    })
}

fn run(args: Args) -> Result<usize, String> {
    let source_timeout = args.timeout.min(Duration::from_millis(CAPTURE_POLL_MS));
    let mut source = PcapCaptureSource::open(&args.iface, args.filter.as_deref(), source_timeout)
        .map_err(|err| err.to_string())?;
    let deadline = Instant::now() + args.timeout;
    let mut captured = 0;

    while captured < args.count {
        let now = Instant::now();
        if now >= deadline {
            break;
        }

        let remaining = deadline.saturating_duration_since(now);
        let poll_timeout = remaining.min(Duration::from_millis(CAPTURE_POLL_MS));
        match source
            .next_packet(poll_timeout)
            .map_err(|err| err.to_string())?
        {
            Some(packet) => {
                captured += 1;
                println!("#{captured}: {}", packet.summary());
            }
            None => {}
        }
    }

    Ok(captured)
}

fn main() -> ExitCode {
    match parse_args().and_then(run) {
        Ok(captured) => {
            println!("captured={captured}");
            if captured >= 1 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}
