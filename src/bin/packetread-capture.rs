//! Privileged capture helper. This is the only Packetread process that needs
//! `CAP_NET_RAW`: it opens the capture devices and streams raw packets to the
//! unprivileged application over stdout (see `packetread::helper`). It never
//! decodes packets, reads files or writes anywhere else.
use packetread::helper::Frame;
use std::{
    io::{self, BufWriter, Write},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

const USAGE: &str =
    "usage: packetread-capture --list\n       packetread-capture -i IFACE [-i IFACE…] \
    [--filter BPF] [--snaplen 64..262144] [--promiscuous]";

struct Options {
    interfaces: Vec<String>,
    filter: String,
    snaplen: i32,
    promiscuous: bool,
}

fn options(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        interfaces: Vec::new(),
        filter: String::new(),
        snaplen: 65_535,
        promiscuous: false,
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "-i" => options.interfaces.push(value()?),
            "--filter" => options.filter = value()?,
            "--snaplen" => {
                options.snaplen = value()?
                    .parse()
                    .ok()
                    .filter(|n| (64..=262_144).contains(n))
                    .ok_or("invalid --snaplen")?
            }
            "--promiscuous" => options.promiscuous = true,
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if options.interfaces.is_empty() || options.interfaces.len() > 32 {
        return Err("name 1–32 interfaces with -i".into());
    }
    Ok(options)
}

// timeval fields are narrower than i64 on some targets.
#[allow(clippy::useless_conversion)]
fn capture(options: &Options, out: &mut impl Write) -> Result<(), Box<dyn std::error::Error>> {
    let mut captures = Vec::new();
    for interface in &options.interfaces {
        let mut capture = pcap::Capture::from_device(interface.as_str())?
            .promisc(options.promiscuous)
            .snaplen(options.snaplen)
            .buffer_size(4 * 1024 * 1024)
            .timeout(20)
            .open()?
            .setnonblock()?;
        if !options.filter.trim().is_empty() {
            capture.filter(&options.filter, true)?;
        }
        captures.push(capture);
    }
    let (mut last_write, mut last_stats) = (Instant::now(), Instant::now());
    loop {
        let mut idle = true;
        for capture in &mut captures {
            let link = capture.get_datalink().0;
            // A bounded burst per interface keeps a busy one from starving the rest.
            for _ in 0..64 {
                match capture.next_packet() {
                    Ok(packet) => {
                        idle = false;
                        Frame::Packet {
                            link,
                            timestamp_ns: i64::from(packet.header.ts.tv_sec) * 1_000_000_000
                                + i64::from(packet.header.ts.tv_usec) * 1000,
                            wire_len: packet.header.len,
                            data: packet.data.to_vec(),
                        }
                        .write(out)?;
                    }
                    Err(pcap::Error::TimeoutExpired) => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        if last_stats.elapsed() >= Duration::from_millis(500) {
            let dropped = captures
                .iter_mut()
                .filter_map(|c| c.stats().ok())
                .map(|s| s.dropped)
                .sum();
            Frame::Stats { dropped }.write(out)?;
            last_stats = Instant::now();
            last_write = Instant::now();
        }
        if idle {
            if last_write.elapsed() >= Duration::from_millis(50) {
                Frame::Tick.write(out)?;
                last_write = Instant::now();
            }
            // A failed flush means the application is gone: stop capturing.
            out.flush()?;
            thread::sleep(Duration::from_millis(2));
        } else {
            last_write = Instant::now();
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = BufWriter::new(io::stdout().lock());
    if args == ["--list"] {
        return match pcap::Device::list() {
            Ok(devices) => {
                for device in devices {
                    let description = device.desc.unwrap_or_default().replace(['\t', '\n'], " ");
                    let _ = writeln!(
                        out,
                        "{}\t{description}",
                        device.name.replace(['\t', '\n'], " ")
                    );
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("packetread-capture: {error}");
                ExitCode::FAILURE
            }
        };
    }
    let result = match options(args.into_iter()) {
        Ok(options) => capture(&options, &mut out).map_err(|error| error.to_string()),
        Err(error) => {
            eprintln!("packetread-capture: {error}\n{USAGE}");
            Err(error)
        }
    };
    if let Err(error) = result {
        // Best effort: the reader may already have gone away.
        let _ = Frame::Error(error).write(&mut out);
        let _ = out.flush();
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
