use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about = "Colorful, mouse-friendly terminal packet inspection")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Packet storage budget in MiB (process overhead is additional) [default: 256].
    #[arg(long, global = true, value_parser = clap::value_parser!(u32).range(1..=4096))]
    pub memory: Option<u32>,
    /// Maximum number of retained packets [default: 100000].
    #[arg(long, global = true, value_parser = clap::value_parser!(u32).range(1..=1_000_000))]
    pub max_packets: Option<u32>,
    /// Theme: vivid, indexed, or contrast [default: vivid].
    #[arg(long, global = true, value_parser = ["vivid", "indexed", "contrast"])]
    pub theme: Option<String>,
    /// Configuration profile to load, and to save with `P` in the interface.
    #[arg(long, global = true, default_value = "default")]
    pub profile: String,
    /// TLS key log (SSLKEYLOGFILE format) for decrypting followed streams.
    #[arg(long, global = true)]
    pub keylog: Option<PathBuf>,
    /// Server RSA private key (PEM) for TLS sessions with RSA key exchange; may be repeated.
    #[arg(long, global = true, value_name = "FILE")]
    pub tls_key: Vec<PathBuf>,
    /// Kerberos keytab whose AES keys decrypt tickets and replies; may be repeated.
    #[arg(long, global = true, value_name = "FILE")]
    pub keytab: Vec<PathBuf>,
    /// IPsec ESP security association, e.g. 0x1000:aes-gcm:HEXKEY or
    /// 0x1001:aes-cbc:HEXKEY:12 (ICV bytes); may be repeated.
    #[arg(long, global = true, value_name = "SPI:CIPHER:KEY[:ICV]")]
    pub esp_sa: Vec<String>,
    /// WPA2 passphrase and network name for decrypting 802.11 captures; may be repeated.
    #[arg(long, global = true, value_name = "PASSPHRASE:SSID")]
    pub wpa_key: Vec<String>,
    /// Shift displayed clock times by this many seconds (may be negative).
    #[arg(
        long,
        global = true,
        allow_hyphen_values = true,
        value_name = "SECONDS"
    )]
    pub time_shift: Option<f64>,
    /// Custom decoder description file; may be repeated.
    #[arg(long, global = true)]
    pub decoder: Vec<PathBuf>,
    /// Decode a port as another protocol, e.g. udp:5300=dns or tcp:8025=smtp; may be repeated.
    #[arg(long, global = true, value_name = "TRANSPORT:PORT=PROTOCOL")]
    pub decode_as: Vec<String>,
}

impl Command {
    /// Commands that read a file and print, without the interface.
    pub fn is_offline(&self) -> bool {
        !matches!(
            self,
            Self::Interfaces | Self::Open { .. } | Self::Capture { .. }
        )
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// List available capture interfaces.
    Interfaces,
    /// Open a regular PCAP/PCAPNG file (pipes and devices are rejected).
    Open { file: PathBuf },
    /// Start a live capture.
    Capture {
        /// Interface to capture on; repeat for a multi-interface session.
        #[arg(short, long, required = true)]
        interface: Vec<String>,
        #[arg(long)]
        capture_filter: Option<String>,
        /// Maximum captured bytes per packet.
        #[arg(long, default_value_t = 65535, value_parser = clap::value_parser!(u32).range(64..=262144))]
        snaplen: u32,
        #[arg(long)]
        promiscuous: bool,
        /// Save captured packets to a new .pcap or .pcapng file.
        #[arg(short, long)]
        write: Option<PathBuf>,
        /// Start a new numbered capture file after this many MiB.
        #[arg(long, requires = "write", value_parser = clap::value_parser!(u64).range(1..))]
        rotate_mib: Option<u64>,
        /// Start a new numbered capture file after this many seconds.
        #[arg(long, requires = "write", value_parser = clap::value_parser!(u64).range(1..))]
        rotate_seconds: Option<u64>,
        /// Keep only the newest N capture files.
        #[arg(long, requires = "write", value_parser = clap::value_parser!(u64).range(1..=100_000))]
        rotate_files: Option<u64>,
        /// Stop capturing after this many seconds.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        stop_after_seconds: Option<u64>,
        /// Stop capturing after this many packets.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        stop_after_packets: Option<u64>,
        /// Stop capturing after this many MiB of traffic.
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
        stop_after_mib: Option<u64>,
        /// Capture on this SSH host by running its tcpdump (one interface;
        /// SSH must log in without a prompt). Exclude the SSH session itself
        /// with a capture filter such as "not port 22".
        #[arg(long, value_name = "[USER@]HOST")]
        remote: Option<String>,
        /// Capture to the --write file without the interface, until a stop
        /// limit or Ctrl+C.
        #[arg(long, requires = "write")]
        headless: bool,
    },
    /// Summarize the entire file without opening the TUI.
    Summary { file: PathBuf },
    /// Merge captures into one new file, ordered by time.
    Merge {
        /// New .pcap or .pcapng file (.pcapng keeps differing link types).
        #[arg(short, long)]
        output: PathBuf,
        #[arg(required = true, num_args = 1..=64)]
        files: Vec<PathBuf>,
    },
    /// Write a file's packets (optionally filtered) as .pcap, .pcapng, .json or .csv.
    Export {
        file: PathBuf,
        /// New output file; its extension selects the format.
        #[arg(short, long)]
        output: PathBuf,
        /// Display filter selecting the packets to export.
        #[arg(short, long, default_value = "")]
        filter: String,
    },
    /// Print conversation, endpoint, protocol, TCP and timing statistics.
    Stats {
        file: PathBuf,
        /// Display filter selecting the packets to count.
        #[arg(short, long, default_value = "")]
        filter: String,
        /// Traffic graph interval in seconds.
        #[arg(long, default_value_t = 1.0)]
        interval: f64,
        /// Rows per ranking.
        #[arg(long, default_value_t = 10)]
        top: usize,
        /// Graph bytes instead of packets.
        #[arg(long)]
        bytes: bool,
    },
    /// Reconstruct one TCP/UDP conversation (decrypted with --keylog).
    Follow {
        file: PathBuf,
        /// Conversation number, as shown by `stats` and the `stream` filter field.
        #[arg(short, long)]
        stream: u32,
        /// Print a hex dump instead of text.
        #[arg(long)]
        hex: bool,
        /// Save the HTTP message bodies of the stream into this directory.
        #[arg(long, value_name = "DIR")]
        objects: Option<PathBuf>,
    },
    /// Draw a TCP conversation as a text chart.
    Graph {
        file: PathBuf,
        /// Conversation number, as shown by `stats` and the `stream` filter field.
        #[arg(short, long)]
        stream: u32,
        /// sequence (time-sequence), throughput or window.
        #[arg(long, default_value = "sequence", value_parser = ["sequence", "throughput", "window"])]
        kind: String,
        #[arg(long, default_value_t = 72, value_parser = clap::value_parser!(u16).range(20..=400))]
        width: u16,
        #[arg(long, default_value_t = 16, value_parser = clap::value_parser!(u16).range(4..=100))]
        height: u16,
    },
    /// Draw a sequence diagram of the packets between hosts.
    Flow {
        file: PathBuf,
        /// Display filter selecting the packets to draw.
        #[arg(short, long, default_value = "")]
        filter: String,
    },
    /// List SIP calls and RTP streams with loss and jitter.
    Voip { file: PathBuf },
    /// List every anomaly: malformed packets, TCP problems, reassembly notes.
    Expert {
        file: PathBuf,
        /// Display filter selecting the packets to check.
        #[arg(short, long, default_value = "")]
        filter: String,
    },
}
