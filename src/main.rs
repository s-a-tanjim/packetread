mod cli;

use clap::Parser;
use cli::{Cli, Command};
use packetread::{decode::safe_text, offline::OfflineCapture, source::SourceSpec, tui};
use std::{collections::BTreeMap, error::Error, io::IsTerminal, sync::atomic::AtomicBool};

fn main() {
    if let Err(error) = run() {
        eprintln!("packetread: {}", safe_text(&error.to_string()));
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let source = match cli.command {
        Some(Command::Interfaces) => {
            for device in pcap::Device::list()? {
                println!(
                    "{:<20} {}",
                    safe_text(&device.name),
                    safe_text(&device.desc.unwrap_or_default())
                );
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
            return Ok(());
        }
        Some(Command::Open { file }) => Some(SourceSpec::File(file)),
        Some(Command::Capture {
            interface,
            capture_filter,
            snaplen,
            promiscuous,
        }) => Some(SourceSpec::Live {
            interface,
            filter: capture_filter.unwrap_or_default(),
            snaplen: snaplen as i32,
            promiscuous,
        }),
        None => None,
    };
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(
            "the TUI requires an interactive terminal; use `summary FILE` for text output".into(),
        );
    }
    tui::run(
        source,
        cli.memory as usize * 1024 * 1024,
        cli.max_packets as usize,
        &cli.theme,
    )?;
    Ok(())
}
