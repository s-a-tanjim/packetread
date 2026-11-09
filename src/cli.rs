use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Colorful, mouse-friendly terminal packet inspection")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Packet storage budget in MiB (process overhead is additional).
    #[arg(long, global = true, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=4096))]
    pub memory: u32,
    /// Maximum number of retained packets.
    #[arg(long, global = true, default_value_t = 100_000, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pub max_packets: u32,
    /// Theme: vivid, indexed, or contrast.
    #[arg(long, global = true, default_value = "vivid", value_parser = ["vivid", "indexed", "contrast"])]
    pub theme: String,
}

#[derive(Subcommand)]
pub enum Command {
    /// List available capture interfaces.
    Interfaces,
    /// Open a regular PCAP/PCAPNG file (pipes and devices are rejected).
    Open { file: PathBuf },
    /// Start a live capture.
    Capture {
        #[arg(short, long)]
        interface: String,
        #[arg(long)]
        capture_filter: Option<String>,
        /// Maximum captured bytes per packet.
        #[arg(long, default_value_t = 65535, value_parser = clap::value_parser!(u32).range(64..=262144))]
        snaplen: u32,
        #[arg(long)]
        promiscuous: bool,
    },
    /// Summarize the entire file without opening the TUI.
    Summary { file: PathBuf },
}
