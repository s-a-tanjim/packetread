mod cli;

use clap::Parser;
use cli::{Cli, Command};
use packetread::{
    analysis::Analyzer,
    crypto,
    decode::{decode_as, register, safe_text, Extension, LuaDecoder, Packet, SchemaDecoder},
    export::{Format, Writer},
    filter::Filter,
    follow::Follower,
    graph::{Flow, GraphKind, TcpGraph, Voip},
    offline::OfflineCapture,
    profile::Profile,
    source::{interfaces, Limits, LiveSpec, Output, Seek, SourceSpec, Worker},
    stats::{Expert, Stats, Unit},
    tls::{decrypt, KeyLog},
    tui,
};
use std::{
    collections::BTreeMap,
    error::Error,
    io::{IsTerminal, Read},
    path::Path,
    sync::atomic::AtomicBool,
    sync::Arc,
};

const MIB: u64 = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("packetread: {}", safe_text(&error.to_string()));
        std::process::exit(1);
    }
}

/// Runs `each` on every analyzed packet of `file` that matches `filter`.
fn analyzed(
    file: &Path,
    keylog: &Option<Arc<KeyLog>>,
    filter: &str,
    mut each: impl FnMut(&Packet) -> std::io::Result<()>,
) -> Result<(), Box<dyn Error>> {
    let filter = Filter::parse(filter)?;
    let mut capture = OfflineCapture::open(file)?;
    let mut analyzer = Analyzer::new(keylog.clone());
    while let Some(mut packet) = capture.next_packet(&AtomicBool::new(false))? {
        analyzer.observe(&mut packet);
        if filter.matches(&packet) {
            each(&packet)?;
        }
    }
    Ok(())
}

/// Captures to the output file without the interface until a stop limit is
/// reached or the user interrupts; the file is always completed.
fn capture_headless(spec: SourceSpec) -> Result<(), Box<dyn Error>> {
    use std::sync::atomic::Ordering;
    let interrupted = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, Arc::clone(&interrupted))?;
    }
    let worker = Worker::start(spec, Seek::default())?;
    eprintln!("Capturing; press Ctrl+C to stop.");
    let status = loop {
        // Packets are only saved here, so the queue is drained and dropped.
        while worker.packets.try_recv().is_ok() {}
        let status = worker.status();
        if status.done {
            break status;
        }
        if interrupted.load(Ordering::Relaxed) {
            worker.stop();
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    println!(
        "Captured {} packets, saved {}",
        status.packets, status.saved
    );
    match status.error {
        // Stopping kills the helper; that is the expected way out.
        Some(error) if !interrupted.load(Ordering::Relaxed) => Err(error.into()),
        _ => Ok(()),
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    for path in &cli.decoder {
        // `.lua` files are sandboxed scripts; anything else is a field layout.
        let mut text = String::new();
        let decoder: Arc<dyn Extension> = std::fs::File::open(path)
            .and_then(|file| file.take(MIB).read_to_string(&mut text))
            .map_err(|error| error.to_string())
            .and_then(|_| {
                Ok(if path.extension().is_some_and(|e| e == "lua") {
                    Arc::new(LuaDecoder::parse(&text)?) as Arc<dyn Extension>
                } else {
                    Arc::new(SchemaDecoder::parse(&text)?)
                })
            })
            .map_err(|error| format!("{}: {error}", path.display()))?;
        register(decoder);
    }
    for rule in &cli.decode_as {
        decode_as(rule)?;
    }
    // Keys are untrusted files: each loader bounds and validates its input.
    let named = |path: &Path, error: String| format!("{}: {error}", path.display());
    for path in &cli.tls_key {
        let mut pem = String::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(MIB).read_to_string(&mut pem))
            .map_err(|e| named(path, e.to_string()))?;
        crypto::add_tls_key(&pem).map_err(|e| named(path, e))?;
    }
    for path in &cli.keytab {
        // Bounded: the loader rejects anything over 1 MiB.
        let mut data = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(MIB + 1).read_to_end(&mut data))
            .map_err(|e| named(path, e.to_string()))?;
        crypto::load_keytab(&data).map_err(|e| named(path, e))?;
    }
    for rule in &cli.esp_sa {
        crypto::add_esp_sa(rule)?;
    }
    for rule in &cli.wpa_key {
        crypto::add_wpa_key(rule)?;
    }
    let keylog = match &cli.keylog {
        Some(path) if cli.command.as_ref().is_some_and(Command::is_offline) => Some(Arc::new(
            KeyLog::load(path).map_err(|error| format!("{}: {error}", path.display()))?,
        )),
        _ => None,
    };
    let keylog = KeyLog::or_private_keys(keylog);
    let source = match cli.command {
        Some(Command::Interfaces) => {
            for (name, description) in interfaces()? {
                println!("{:<20} {}", safe_text(&name), safe_text(&description));
            }
            return Ok(());
        }
        Some(Command::Summary { file }) => {
            let mut capture = OfflineCapture::open(file)?;
            let mut counts = BTreeMap::new();
            let (mut packets, mut bytes, mut warnings) = (0u64, 0u64, 0u64);
            while let Some(packet) = capture.next_packet(&AtomicBool::new(false))? {
                *counts.entry(packet.summary.protocol.name()).or_insert(0u64) += 1;
                warnings += u64::from(packet.summary.warning.is_some());
                packets += 1;
                bytes += u64::from(packet.wire_len);
            }
            println!("Packets: {packets}\nWire bytes: {bytes}\nPackets with warnings: {warnings}");
            for (protocol, count) in counts {
                println!("{protocol:<12} {count}");
            }
            // PCAPNG metadata is text from the file.
            let metadata = capture.metadata();
            for line in &metadata.section {
                println!("{}", safe_text(line));
            }
            for (index, interface) in metadata.interfaces.iter().enumerate() {
                println!("Interface {index}: {}", safe_text(interface));
            }
            for (address, name) in metadata.names.iter().take(100) {
                println!("Name: {address} {}", safe_text(name));
            }
            return Ok(());
        }
        Some(Command::Merge { output, files }) => {
            if !matches!(Format::from_path(&output)?, Format::Pcap | Format::Pcapng) {
                return Err("--output needs a .pcap or .pcapng file".into());
            }
            let stop = AtomicBool::new(false);
            // One pending packet per input; the earliest is written next.
            let mut inputs = Vec::new();
            for file in &files {
                let mut capture = OfflineCapture::open(file)?;
                let next = capture.next_packet(&stop)?;
                inputs.push((capture, next));
            }
            let mut writer = Writer::create(&output)?;
            loop {
                let earliest = inputs
                    .iter()
                    .enumerate()
                    .filter_map(|(index, (_, next))| Some((next.as_ref()?.timestamp_ns, index)))
                    .min();
                let Some((_, index)) = earliest else {
                    break;
                };
                let (capture, next) = &mut inputs[index];
                if let Some(packet) = next.take() {
                    writer.write(&packet)?;
                }
                *next = capture.next_packet(&stop)?;
            }
            let writer = writer.finish()?;
            println!(
                "Merged {} packets from {} files into {}",
                writer.written,
                files.len(),
                output.display()
            );
            if writer.skipped > 0 {
                println!(
                    "Skipped {} packets with another link type; use .pcapng to keep them",
                    writer.skipped
                );
            }
            return Ok(());
        }
        Some(Command::Export {
            file,
            output,
            filter,
        }) => {
            // Validate the filter and input before creating the output file;
            // standard input can only be read once.
            Filter::parse(&filter)?;
            if file != Path::new("-") {
                analyzed(&file, &keylog, &filter, |_| Ok(()))?;
            }
            let mut writer = Writer::create(&output)?;
            analyzed(&file, &keylog, &filter, |packet| writer.write(packet))?;
            let writer = writer.finish()?;
            println!(
                "Exported {} packets to {}",
                writer.written,
                output.display()
            );
            if writer.skipped > 0 {
                println!(
                    "Skipped {} packets with another link type; use .pcapng to keep them",
                    writer.skipped
                );
            }
            return Ok(());
        }
        Some(Command::Stats {
            file,
            filter,
            interval,
            top,
            bytes,
        }) => {
            if !(0.001..=86_400.0).contains(&interval) {
                return Err("--interval must be between 0.001 and 86400 seconds".into());
            }
            let mut stats = Stats::new(interval);
            analyzed(&file, &keylog, &filter, |packet| {
                stats.add(packet);
                Ok(())
            })?;
            let unit = if bytes { Unit::Bytes } else { Unit::Packets };
            println!("{}", stats.report(top, unit).join("\n"));
            return Ok(());
        }
        Some(Command::Graph {
            file,
            stream,
            kind,
            width,
            height,
        }) => {
            let mut graph = TcpGraph::new(stream);
            analyzed(&file, &keylog, "", |packet| {
                graph.add(packet);
                Ok(())
            })?;
            let kind = match kind.as_str() {
                "throughput" => GraphKind::Throughput,
                "window" => GraphKind::Window,
                _ => GraphKind::Sequence,
            };
            let lines = graph.render(kind, width.into(), height.into());
            println!("{}", lines.join("\n"));
            return Ok(());
        }
        Some(Command::Flow { file, filter }) => {
            let mut flow = Flow::default();
            analyzed(&file, &keylog, &filter, |packet| {
                flow.add(packet);
                Ok(())
            })?;
            println!("{}", flow.report().join("\n"));
            return Ok(());
        }
        Some(Command::Voip { file }) => {
            let mut voip = Voip::default();
            analyzed(&file, &keylog, "", |packet| {
                voip.add(packet);
                Ok(())
            })?;
            println!("{}", voip.report().join("\n"));
            return Ok(());
        }
        Some(Command::Expert { file, filter }) => {
            let mut expert = Expert::default();
            analyzed(&file, &keylog, &filter, |packet| {
                expert.add(packet);
                Ok(())
            })?;
            println!("{}", expert.report().join("\n"));
            return Ok(());
        }
        Some(Command::Follow {
            file,
            stream,
            hex,
            objects,
        }) => {
            let mut follower = Follower::new(stream, 64 * MIB as usize);
            analyzed(&file, &None, "", |packet| {
                follower.push(packet);
                Ok(())
            })?;
            let mut stream = follower.finish();
            if stream.client.is_none() {
                return Err(format!("No conversation numbered {}", stream.id).into());
            }
            if let Some(log) = &keylog {
                stream = decrypt(&stream, log)?;
                println!("{} · decrypted", stream.title());
            } else {
                println!("{}", stream.title());
            }
            if let Some(directory) = objects {
                std::fs::create_dir_all(&directory)?;
                let found = stream.http_objects();
                for (index, (extension, body)) in found.iter().enumerate() {
                    // Names are generated here, never taken from the traffic.
                    let name = format!("stream{}_object{:03}.{extension}", stream.id, index + 1);
                    let path = directory.join(name);
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                    std::io::Write::write_all(&mut file, body)?;
                    println!("{} · {} bytes", path.display(), body.len());
                }
                println!("Saved {} HTTP objects", found.len());
                return Ok(());
            }
            println!("{}", stream.lines(hex).join("\n"));
            return Ok(());
        }
        Some(Command::Open { file }) => Some(SourceSpec::File(file)),
        Some(Command::Capture {
            interface,
            capture_filter,
            snaplen,
            promiscuous,
            write,
            rotate_mib,
            rotate_seconds,
            rotate_files,
            stop_after_seconds,
            stop_after_packets,
            stop_after_mib,
            remote,
            headless,
        }) => {
            if let Some(path) = &write {
                if !matches!(Format::from_path(path)?, Format::Pcap | Format::Pcapng) {
                    return Err("--write needs a .pcap or .pcapng file".into());
                }
            }
            let spec = SourceSpec::Live(LiveSpec {
                interfaces: interface,
                filter: capture_filter.unwrap_or_default(),
                snaplen,
                promiscuous,
                output: write.map(|path| Output {
                    path,
                    rotate_bytes: rotate_mib.map(|mib| mib.saturating_mul(MIB)),
                    rotate_seconds,
                    keep_files: rotate_files.map(|files| files as usize),
                }),
                limits: Limits {
                    seconds: stop_after_seconds,
                    packets: stop_after_packets,
                    bytes: stop_after_mib.map(|mib| mib.saturating_mul(MIB)),
                },
                remote,
            });
            if headless {
                return capture_headless(spec);
            }
            Some(spec)
        }
        None => None,
    };
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(
            "the TUI requires an interactive terminal; use `summary FILE` for text output".into(),
        );
    }
    let profile = Profile::load(&cli.profile)?;
    tui::run(tui::Options {
        source,
        memory: cli.memory.or(profile.memory).unwrap_or(256) as usize * MIB as usize,
        max_packets: cli.max_packets.or(profile.max_packets).unwrap_or(100_000) as usize,
        theme: cli
            .theme
            .or(profile.theme)
            .unwrap_or_else(|| "vivid".into()),
        filter: profile.filter.unwrap_or_default(),
        table_percent: profile.table_percent,
        details_percent: profile.details_percent,
        keylog: cli.keylog.or(profile.keylog),
        profile: cli.profile,
        colors: profile.colors,
        columns: profile.columns,
        buttons: profile.buttons,
        time_shift_ms: match cli.time_shift {
            Some(seconds) if seconds.abs() <= 315_360_000.0 => (seconds * 1000.0) as i64,
            Some(_) => return Err("--time-shift is limited to ten years".into()),
            None => profile.time_shift_ms.unwrap_or(0),
        },
    })?;
    Ok(())
}
