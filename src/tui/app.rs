use super::theme::Theme;
use crate::{
    decode::{tls::is_record, Layer},
    export::Writer,
    filter::{self, Field, Filter},
    follow::Follower,
    graph::{Flow, GraphKind, TcpGraph, Voip},
    ingest::Ingest,
    profile::Profile,
    session::Session,
    source::{interfaces, LiveSpec, Seek, SourceSpec},
    stats::{Expert, Stats, Unit},
    tls::{decrypt, KeyLog},
};
use ratatui::layout::Rect;
use std::{
    collections::BTreeSet,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Payload bytes shown when following one stream.
const FOLLOW_LIMIT: usize = 4 * 1024 * 1024;
const INTERVALS: [f64; 7] = [0.001, 0.01, 0.1, 1.0, 10.0, 60.0, 600.0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    Packets,
    Details,
    Bytes,
}

#[derive(Clone, Debug)]
pub enum Action {
    Open,
    Interfaces,
    Start,
    Stop,
    Follow,
    NextWindow,
    PrevWindow,
    /// Export the displayed packets, or only the selected one.
    Export(bool),
    Find,
    FindNext(bool),
    Mark,
    Comment,
    Goto,
    Stats,
    FollowStream,
    KeyLog,
    SaveProfile,
    ScrollText(isize),
    ViewUnit,
    ViewInterval(bool),
    ViewHex,
    ViewDecrypt,
    TimeFormat,
    Resolve,
    ApplyAsFilter,
    Expert,
    /// Apply the saved filter button with this index.
    SavedFilter(usize),
    /// Make the selected packet the zero point of relative times.
    TimeReference,
    Graph,
    FlowDiagram,
    Voip,
    Theme,
    Help,
    Quit,
    Bpf,
    Focus(Pane),
    Filter,
    ApplyFilter,
    Move(isize),
    Home,
    End,
    Toggle,
    SelectPacket(usize),
    SelectDetail(usize),
    SelectInterface(usize),
    Scroll(Pane, isize),
    ApplyDialog,
    CloseDialog,
}

#[derive(Clone, Copy, Debug)]
pub enum Drag {
    Horizontal,
    Vertical,
    Scroll(Pane),
}

#[derive(Default)]
pub struct Regions {
    pub buttons: Vec<(Rect, Action)>,
    pub packets: Rect,
    pub details: Rect,
    pub bytes: Rect,
    pub horizontal: Rect,
    pub vertical: Rect,
    pub scrollbars: Vec<(Rect, Pane)>,
    pub body: Rect,
}

impl Regions {
    pub fn hit(&self, x: u16, y: u16) -> Option<Action> {
        self.buttons
            .iter()
            .rev()
            .find(|(r, _)| contains(*r, x, y))
            .map(|(_, a)| a.clone())
    }
}

pub fn contains(rect: Rect, x: u16, y: u16) -> bool {
    x >= rect.x && x < rect.right() && y >= rect.y && y < rect.bottom()
}

#[derive(Default, Clone)]
pub struct TextInput {
    pub value: String,
    pub cursor: usize,
}

impl TextInput {
    pub fn new(value: String) -> Self {
        let cursor = value.len();
        Self { value, cursor }
    }
    pub fn insert(&mut self, text: &str) {
        let clean: String = text.chars().filter(|c| !c.is_control()).collect();
        if self.value.len() + clean.len() <= 4096 {
            self.value.insert_str(self.cursor, &clean);
            self.cursor += clean.len();
        }
    }
    pub fn left(&mut self) {
        self.cursor = self.value[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(i, _)| i);
    }
    pub fn right(&mut self) {
        if let Some(c) = self.value[self.cursor..].chars().next() {
            self.cursor += c.len_utf8();
        }
    }
    pub fn backspace(&mut self) {
        let old = self.cursor;
        self.left();
        self.value.drain(self.cursor..old);
    }
    pub fn delete(&mut self) {
        let start = self.cursor;
        self.right();
        self.value.drain(start..self.cursor);
        self.cursor = start;
    }
}

/// How the packet list shows time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeFormat {
    /// UTC time of day.
    Clock,
    /// Seconds since the first retained packet.
    Relative,
    /// Seconds since the previous displayed packet.
    Delta,
    /// UTC date and time.
    Date,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Help,
    Stats,
    Follow,
}

#[derive(Clone)]
pub enum Dialog {
    Help,
    Open(TextInput),
    Bpf(TextInput),
    Export(TextInput, bool),
    Find(TextInput),
    Comment(TextInput),
    Goto(TextInput),
    KeyLog(TextInput),
    Interfaces {
        entries: Vec<String>,
        selected: usize,
        /// Interfaces ticked for a multi-interface capture.
        checked: BTreeSet<usize>,
    },
    /// Scrollable read-only text: help, statistics or a followed stream.
    Text {
        title: String,
        lines: Vec<String>,
        offset: usize,
        view: View,
    },
}

pub const HELP: [&str; 44] = [
    "Mouse: click controls, packets, fields and tabs; wheel scrolls;",
    "  drag pane dividers or scrollbars to resize / navigate.",
    "Tab / 1 / 2 / 3: choose pane. Arrows / j k / PgUp PgDn: move.",
    "Enter / Left / Right: expand or collapse protocol layer.",
    "Space: auto-scroll ON/OFF. s: stop. r: new session.",
    "o: open file. i: interfaces (Space ticks several). b: BPF.",
    "/: edit display filter. Enter or Apply: apply it.",
    "  proto=tcp port=443 · addr=192.0.2.0/24 · len>1000",
    "  (proto=dns or proto=http) and not src=192.0.2.1",
    "  info~\"regex\" · bytes contains \"text\" · bytes contains de:ad",
    "  tcp.flags=syn · tcp.analysis=retransmission · stream=3",
    "  marked · comment · warning · reassembled · port=80-90",
    "f: find text (or hex:dead) in packet bytes. F3 or . next, , previous.",
    "  In a file, searching continues past the loaded window.",
    "m: mark packet. c: comment. Filter with `marked` / `comment`.",
    "w: save displayed packets. W: save the selected packet.",
    "  .pcap / .pcapng keep raw bytes; .json / .csv keep decoded data.",
    "S: statistics for displayed packets (conversations, endpoints,",
    "  protocol hierarchy, TCP diagnostics, response times, graph).",
    "F: follow the selected packet's TCP/UDP stream (h: hex).",
    "K: load a TLS key log (SSLKEYLOGFILE); F then shows plaintext.",
    "n / Next, p / Prev: move between bounded file windows.",
    ": go to a packet number, reloading the file window if needed.",
    "a: filter on the selected field (details) or conversation (packets).",
    "  Any decoded field is searchable: field contains \"server name\".",
    "E: expert information, every anomaly in the displayed packets.",
    "T: time as UTC clock, since first packet, since previous, or date.",
    "N: show host names learned from DNS answers in the capture.",
    "  Protocol fields compare by type: http.host == example.com,",
    "  ip.ttl < 10, dns.qry.name contains \"cdn\". Tab completes names.",
    "R: time reference; \"since first\" then counts from that packet.",
    "Y: graphs of the selected TCP stream (sequence, throughput, window).",
    "D: flow diagram of the displayed packets. V: VoIP calls and RTP.",
    "F5–F12 or the filter-bar buttons: saved filters from the profile.",
    "  Profiles also hold coloring rules (color = red FILTER), extra",
    "  columns (column = Host http.host) and time_shift = SECONDS.",
    "Captures may be gzip-compressed; snoop files are read too.",
    "P: save theme, filter and layout to the active profile.",
    "t: theme. q / Ctrl+C: quit. Esc: close dialog / editor.",
    "BPF controls capture; display filters search retained packets.",
    "OS drops may be unavailable. App drops and evictions differ.",
    "IP fragments are reassembled; TCP problems are flagged in Info.",
    "Live capture runs in the packetread-capture helper, the only",
    "  program that needs CAP_NET_RAW.",
];

pub struct App {
    pub session: Session,
    pub source: Option<SourceSpec>,
    pub ingest: Ingest,
    pub theme: Theme,
    pub pane: Pane,
    pub filter: TextInput,
    pub editing_filter: bool,
    pub filter_error: Option<String>,
    pub dialog: Option<Dialog>,
    pub notice: String,
    pub quit: bool,
    pub packet_offset: usize,
    pub detail_offset: usize,
    pub byte_offset: usize,
    pub layers: Vec<Layer>,
    pub collapsed: BTreeSet<usize>,
    pub detail_selected: usize,
    cached_id: Option<u64>,
    pub regions: Regions,
    pub drag: Option<Drag>,
    pub table_percent: u16,
    pub details_percent: u16,
    /// ID of the first packet of the current file window, and of earlier ones.
    window_first: u64,
    window_starts: Vec<u64>,
    /// A seek is loading: select its first packet (and report a failed search).
    select_first: bool,
    file_search: bool,
    find: Option<Filter>,
    pub keylog: Option<Arc<KeyLog>>,
    pub keylog_path: Option<PathBuf>,
    pub profile: String,
    stats_interval: f64,
    stats_unit: Unit,
    follow_hex: bool,
    follow_decrypt: bool,
    pub time_format: TimeFormat,
    /// Show DNS-learned host names instead of addresses.
    pub resolve: bool,
    /// Coloring rules: color name, filter text and the parsed filter.
    pub colors: Vec<(String, String, Filter)>,
    /// Extra columns: title, field name and the parsed field.
    pub columns: Vec<(String, String, Field)>,
    /// Saved filter buttons: label and filter text.
    pub buttons: Vec<(String, String)>,
    pub time_shift_ns: i128,
    /// Packet number and time that relative times count from.
    pub time_reference: Option<(u64, i128)>,
}

impl App {
    pub fn new(source: Option<SourceSpec>, memory: usize, max_packets: usize, theme: &str) -> Self {
        Self {
            session: Session::new(memory, max_packets),
            source,
            ingest: Ingest::default(),
            theme: Theme::named(theme),
            pane: Pane::Packets,
            filter: TextInput::default(),
            editing_filter: false,
            filter_error: None,
            dialog: None,
            notice: "Open a capture file or choose an interface to begin".into(),
            quit: false,
            packet_offset: 0,
            detail_offset: 0,
            byte_offset: 0,
            layers: Vec::new(),
            collapsed: BTreeSet::new(),
            detail_selected: 0,
            cached_id: None,
            regions: Regions::default(),
            drag: None,
            table_percent: 55,
            details_percent: 45,
            window_first: 1,
            window_starts: Vec::new(),
            select_first: false,
            file_search: false,
            find: None,
            keylog: None,
            keylog_path: None,
            profile: "default".into(),
            stats_interval: 1.0,
            stats_unit: Unit::Packets,
            follow_hex: false,
            follow_decrypt: true,
            time_format: TimeFormat::Clock,
            resolve: false,
            colors: Vec::new(),
            columns: Vec::new(),
            buttons: Vec::new(),
            time_shift_ns: 0,
            time_reference: None,
        }
    }

    /// Coloring rules, custom columns and saved filters, in profile syntax.
    /// Entries that do not parse are dropped (profiles validate on load).
    pub fn set_presentation(
        &mut self,
        colors: Vec<(String, String)>,
        columns: Vec<(String, String)>,
        buttons: Vec<(String, String)>,
    ) {
        self.colors = colors
            .into_iter()
            .filter_map(|(color, text)| {
                let filter = Filter::parse(&text).ok()?;
                Some((color, text, filter))
            })
            .collect();
        self.columns = columns
            .into_iter()
            .filter_map(|(title, name)| {
                let field = Field::parse(&name).ok()?;
                Some((title, name, field))
            })
            .collect();
        self.buttons = buttons;
    }

    /// Completes the filter word before the cursor; several candidates are
    /// completed to their common prefix and listed in the status line.
    pub fn complete_filter(&mut self) {
        let input = &mut self.filter;
        let start = input.value[..input.cursor]
            .rfind(|c: char| c.is_whitespace() || "()!".contains(c))
            .map_or(0, |at| at + 1);
        let word = &input.value[start..input.cursor];
        let candidates = filter::completions(word);
        let Some(first) = candidates.first() else {
            self.notice = "No completion".into();
            return;
        };
        let common = candidates.iter().fold(first.len(), |length, candidate| {
            first
                .bytes()
                .zip(candidate.bytes())
                .take(length)
                .take_while(|(a, b)| a == b)
                .count()
        });
        let completed = first[..common].to_string();
        if completed.len() > word.len() {
            input.value.replace_range(start..input.cursor, &completed);
            input.cursor = start + completed.len();
        }
        if candidates.len() > 1 {
            let shown: Vec<_> = candidates.iter().take(10).map(String::as_str).collect();
            self.notice = format!("Completions: {}", shown.join("  "));
        }
        self.validate_filter();
    }

    fn open_text(&mut self, title: &str, lines: Vec<String>) {
        self.editing_filter = false;
        self.dialog = Some(Dialog::Text {
            title: title.into(),
            lines,
            offset: 0,
            view: View::Help,
        });
    }
    pub fn searching(&self) -> bool {
        self.file_search
    }
    pub fn start(&mut self) {
        if self.source.is_none() {
            self.apply(Action::Interfaces);
            return;
        }
        self.session.restart();
        self.window_first = 1;
        self.window_starts.clear();
        (self.select_first, self.file_search) = (false, false);
        self.launch(Seek::default());
    }

    /// Reloads the file window starting at packet `from`, or at the first
    /// later packet matching `find`.
    fn seek(&mut self, from: u64, find: Option<Filter>, select_first: bool) {
        self.session.next_window();
        // The caller words its own notice.
        self.session.take_notice();
        self.window_first = from;
        self.file_search = find.is_some();
        self.select_first = select_first;
        self.launch(Seek {
            from,
            find,
            keylog: None,
        });
    }

    fn launch(&mut self, mut seek: Seek) {
        let Some(spec) = self.source.clone() else {
            return;
        };
        seek.keylog = self.keylog.clone();
        // Dropping the old ingest cancels its worker, including a blocked
        // offline producer, before the new one starts.
        self.ingest = Ingest::default();
        self.cached_id = None;
        self.layers.clear();
        self.packet_offset = 0;
        match Ingest::start(spec, seek) {
            Ok(ingest) => {
                self.ingest = ingest;
                self.notice = "Opening source…".into();
            }
            Err(error) => self.notice = format!("Cannot start capture: {error}"),
        }
    }

    pub fn tick(&mut self) -> bool {
        let previous_status = self.ingest.status.clone();
        let previous_selection = self.session.selected();
        let previous_len = self.session.len();
        let previous_evicted = self.session.evicted();
        let was_filtering = self.session.filtering();
        let was_full = self.ingest.window_full;
        let rate_changed = self
            .ingest
            .tick(&mut self.session, Duration::from_millis(3));
        if self.ingest.window_full && !was_full && !self.notice.starts_with("No further match") {
            self.notice =
                "File window full · click Next to continue; earlier packets leave memory".into();
        }
        self.session.filter_step(Duration::from_millis(2));
        if self.select_first && !self.session.visible().is_empty() {
            self.session.select_index(0);
            self.window_first = self.session.packets().next().map_or(1, |p| p.id);
            (self.select_first, self.file_search) = (false, false);
            self.notice = format!("Showing packet {}", self.window_first);
        } else if self.file_search && self.ingest.status.done && !self.session.filtering() {
            // Nothing matched: return to the window the search started from.
            let back = self.window_starts.pop().unwrap_or(1);
            self.seek(back, None, false);
            self.notice = "No further match in the capture".into();
        }
        if self.cached_id != self.session.selected() {
            self.layers = self
                .session
                .selected_packet()
                .map(|p| {
                    let mut layers = p.layers();
                    if let Some(comment) = &p.comment {
                        layers.insert(
                            0,
                            Layer {
                                label: format!("Comment: {comment}"),
                                range: 0..0,
                                fields: Vec::new(),
                            },
                        );
                    }
                    layers
                })
                .unwrap_or_default();
            self.cached_id = self.session.selected();
            self.collapsed.clear();
            self.detail_selected = 0;
            self.detail_offset = 0;
            self.byte_offset = 0;
        }
        if let Some(notice) = self.session.take_notice() {
            self.notice = notice;
        }
        let status = &self.ingest.status;
        if status.permission_denied {
            self.notice =
                "Live capture needs CAP_NET_RAW · click Help for setup instructions".into();
            if previous_status.error != status.error && self.dialog.is_none() {
                self.dialog = Some(Dialog::Help);
            }
        } else if let Some(error) = &status.error {
            self.notice = format!("Source error: {error}");
        } else if self.notice == "Opening source…" && (status.packets > 0 || status.done) {
            self.notice = "Select packets and protocol fields to inspect their bytes".into();
        }
        rate_changed
            || was_filtering
            || *status != previous_status
            || self.session.selected() != previous_selection
            || self.session.len() != previous_len
            || self.session.evicted() != previous_evicted
    }

    pub fn detail_rows(&self) -> Vec<(usize, Option<usize>)> {
        let mut rows = Vec::new();
        for (layer_index, layer) in self.layers.iter().enumerate() {
            rows.push((layer_index, None));
            if !self.collapsed.contains(&layer_index) {
                for field in 0..layer.fields.len() {
                    rows.push((layer_index, Some(field)));
                }
            }
        }
        rows
    }
    pub fn selected_range(&self) -> Range<usize> {
        self.detail_rows()
            .get(self.detail_selected)
            .map(|&(l, f)| {
                f.map_or_else(
                    || self.layers[l].range.clone(),
                    |f| self.layers[l].fields[f].range.clone(),
                )
            })
            .unwrap_or(0..0)
    }
    pub fn max_offset(&self, pane: Pane) -> usize {
        match pane {
            Pane::Packets => self
                .session
                .visible()
                .len()
                .saturating_sub(self.regions.packets.height as usize),
            Pane::Details => self
                .detail_rows()
                .len()
                .saturating_sub(self.regions.details.height as usize),
            Pane::Bytes => self
                .session
                .selected_packet()
                .map_or(0, |p| p.view().0.len().div_ceil(self.bytes_per_line()))
                .saturating_sub(self.regions.bytes.height as usize),
        }
    }
    pub fn bytes_per_line(&self) -> usize {
        if self.regions.bytes.width >= 74 {
            16
        } else {
            8
        }
    }
    pub fn set_offset(&mut self, pane: Pane, offset: usize) {
        let offset = offset.min(self.max_offset(pane));
        match pane {
            Pane::Packets => {
                self.packet_offset = offset;
                self.session.unfollow();
            }
            Pane::Details => self.detail_offset = offset,
            Pane::Bytes => self.byte_offset = offset,
        }
    }
    pub fn offset(&self, pane: Pane) -> usize {
        match pane {
            Pane::Packets => self.packet_offset,
            Pane::Details => self.detail_offset,
            Pane::Bytes => self.byte_offset,
        }
    }

    pub fn apply(&mut self, action: Action) {
        match action {
            Action::Quit => self.quit = true,
            Action::Open => {
                self.editing_filter = false;
                self.dialog = Some(Dialog::Open(TextInput::default()));
            }
            Action::Interfaces => {
                self.editing_filter = false;
                match interfaces() {
                    Ok(entries) => {
                        self.dialog = Some(Dialog::Interfaces {
                            entries: entries.into_iter().map(|(name, _)| name).collect(),
                            selected: 0,
                            checked: BTreeSet::new(),
                        })
                    }
                    Err(error) => self.notice = format!("Cannot list interfaces: {error}"),
                }
            }
            Action::Start => self.start(),
            Action::Stop => {
                self.ingest.stop();
                self.notice = "Capture stopped; retained packets remain available".into();
            }
            Action::Follow => self.session.toggle_follow(),
            Action::NextWindow => {
                let next = self
                    .session
                    .last_id()
                    .map_or(self.window_first, |id| id + 1);
                if self.ingest.next_window(&mut self.session) {
                    self.window_starts.push(self.window_first);
                    self.window_first = next;
                    self.packet_offset = 0;
                }
            }
            Action::PrevWindow => {
                if self.window_first > 1 && matches!(self.source, Some(SourceSpec::File(_))) {
                    let from = self.window_starts.pop().unwrap_or(1);
                    self.seek(from, None, false);
                } else {
                    self.notice = "Already at the first file window".into();
                }
            }
            Action::Export(selected) => {
                self.open_input(Dialog::Export(TextInput::default(), selected))
            }
            Action::Find => self.open_input(Dialog::Find(TextInput::default())),
            Action::FindNext(forward) => self.find_next(forward),
            Action::Mark => {
                if let Some(mark) = self.session.selected_packet().map(|p| p.mark) {
                    self.session.annotate(Some(!mark), None);
                }
            }
            Action::Comment => {
                if let Some(packet) = self.session.selected_packet() {
                    let comment = packet.comment.clone().unwrap_or_default();
                    self.open_input(Dialog::Comment(TextInput::new(comment)));
                }
            }
            Action::Goto => self.open_input(Dialog::Goto(TextInput::default())),
            Action::KeyLog => {
                let path = self.keylog_path.as_ref().map(|p| p.display().to_string());
                self.open_input(Dialog::KeyLog(TextInput::new(path.unwrap_or_default())));
            }
            Action::Stats => self.open_stats(),
            Action::FollowStream => self.open_follow(),
            Action::SaveProfile => {
                let profile = Profile {
                    theme: Some(self.theme.name.into()),
                    filter: Some(self.filter.value.clone()),
                    memory: Some((self.session.byte_limit() / (1024 * 1024)).max(1) as u32),
                    max_packets: Some(self.session.packet_limit() as u32),
                    table_percent: Some(self.table_percent),
                    details_percent: Some(self.details_percent),
                    keylog: self.keylog_path.clone(),
                    colors: self
                        .colors
                        .iter()
                        .map(|(c, f, _)| (c.clone(), f.clone()))
                        .collect(),
                    columns: self
                        .columns
                        .iter()
                        .map(|(t, f, _)| (t.clone(), f.clone()))
                        .collect(),
                    buttons: self.buttons.clone(),
                    time_shift_ms: Some((self.time_shift_ns / 1_000_000) as i64)
                        .filter(|shift| *shift != 0),
                };
                self.notice = match profile.save(&self.profile) {
                    Ok(path) => format!("Profile saved to {}", path.display()),
                    Err(error) => format!("Cannot save profile: {error}"),
                };
            }
            Action::ScrollText(delta) => {
                if let Some(Dialog::Text { lines, offset, .. }) = &mut self.dialog {
                    *offset = offset
                        .saturating_add_signed(delta)
                        .min(lines.len().saturating_sub(1));
                }
            }
            Action::ViewUnit => {
                self.stats_unit = if self.stats_unit == Unit::Packets {
                    Unit::Bytes
                } else {
                    Unit::Packets
                };
                self.open_stats();
            }
            Action::ViewInterval(longer) => {
                let index = INTERVALS
                    .iter()
                    .position(|i| *i == self.stats_interval)
                    .unwrap_or(3);
                let index = if longer {
                    index + 1
                } else {
                    index.saturating_sub(1)
                };
                self.stats_interval = INTERVALS[index.min(INTERVALS.len() - 1)];
                self.open_stats();
            }
            Action::ViewHex => {
                self.follow_hex = !self.follow_hex;
                self.open_follow();
            }
            Action::ViewDecrypt => {
                self.follow_decrypt = !self.follow_decrypt;
                self.open_follow();
            }
            Action::TimeFormat => {
                self.time_format = match self.time_format {
                    TimeFormat::Clock => TimeFormat::Relative,
                    TimeFormat::Relative => TimeFormat::Delta,
                    TimeFormat::Delta => TimeFormat::Date,
                    TimeFormat::Date => TimeFormat::Clock,
                };
            }
            Action::Resolve => {
                self.resolve = !self.resolve;
                self.notice = if self.resolve {
                    "Showing host names learned from DNS answers in this capture".into()
                } else {
                    "Showing addresses".into()
                };
            }
            Action::ApplyAsFilter => match self.selection_filter() {
                Some(filter) => {
                    self.filter = TextInput::new(filter);
                    self.apply(Action::ApplyFilter);
                }
                None => self.notice = "Select a packet or a protocol field first".into(),
            },
            Action::Expert => {
                let mut expert = Expert::default();
                self.session
                    .visible_packets()
                    .for_each(|packet| expert.add(packet));
                self.editing_filter = false;
                self.dialog = Some(Dialog::Text {
                    title: " EXPERT INFORMATION · displayed packets ".into(),
                    lines: expert.report(),
                    offset: 0,
                    view: View::Help,
                });
            }
            Action::SavedFilter(index) => {
                if let Some((_, filter)) = self.buttons.get(index) {
                    self.filter = TextInput::new(filter.clone());
                    self.apply(Action::ApplyFilter);
                }
            }
            Action::TimeReference => {
                let selected = self
                    .session
                    .selected_packet()
                    .map(|p| (p.id, p.timestamp_ns));
                self.time_reference =
                    selected.filter(|reference| Some(*reference) != self.time_reference);
                self.time_format = TimeFormat::Relative;
                self.notice = match self.time_reference {
                    Some((id, _)) => format!("Times now count from packet {id}"),
                    None => "Time reference cleared".into(),
                };
            }
            Action::Graph => {
                let Some(stream) = self
                    .session
                    .selected_packet()
                    .filter(|p| p.summary.tcp.is_some())
                    .and_then(|p| p.summary.stream)
                else {
                    self.notice = "Select a TCP packet to graph its stream".into();
                    return;
                };
                let mut graph = TcpGraph::new(stream);
                self.session.packets().for_each(|packet| graph.add(packet));
                let mut lines = Vec::new();
                for kind in [
                    GraphKind::Sequence,
                    GraphKind::Throughput,
                    GraphKind::Window,
                ] {
                    lines.extend(graph.render(kind, 72, 12));
                    lines.push(String::new());
                }
                self.open_text(" STREAM GRAPHS · retained packets ", lines);
            }
            Action::FlowDiagram => {
                let mut flow = Flow::default();
                self.session
                    .visible_packets()
                    .for_each(|packet| flow.add(packet));
                self.open_text(" FLOW DIAGRAM · displayed packets ", flow.report());
            }
            Action::Voip => {
                let mut voip = Voip::default();
                self.session.packets().for_each(|packet| voip.add(packet));
                self.open_text(" VOIP CALLS AND RTP STREAMS ", voip.report());
            }
            Action::Theme => self.theme = self.theme.next(),
            Action::Help => {
                self.editing_filter = false;
                self.dialog = Some(if self.ingest.status.permission_denied {
                    Dialog::Help
                } else {
                    Dialog::Text {
                        title: " HELP ".into(),
                        lines: HELP.iter().map(|line| line.to_string()).collect(),
                        offset: 0,
                        view: View::Help,
                    }
                });
            }
            Action::Focus(pane) => {
                self.pane = pane;
                self.editing_filter = false;
            }
            Action::Filter => {
                self.editing_filter = true;
                self.dialog = None;
            }
            Action::ApplyFilter => match self.session.set_filter(&self.filter.value) {
                Ok(()) => {
                    self.editing_filter = false;
                    self.filter_error = None;
                    self.packet_offset = 0;
                    self.notice = "Display filter applied to retained packets".into();
                }
                Err(error) => self.filter_error = Some(error),
            },
            Action::Bpf => {
                let value = match &self.source {
                    Some(SourceSpec::Live(spec)) => spec.filter.clone(),
                    _ => String::new(),
                };
                self.editing_filter = false;
                self.dialog = Some(Dialog::Bpf(TextInput::new(value)));
            }
            Action::SelectPacket(index) => {
                self.pane = Pane::Packets;
                self.session.select_index(index);
            }
            Action::SelectDetail(index) => {
                self.pane = Pane::Details;
                let rows = self.detail_rows();
                if let Some(&(_, field)) = rows.get(index) {
                    self.detail_selected = index;
                    if field.is_none() {
                        self.apply(Action::Toggle);
                    }
                    self.byte_offset = self.selected_range().start / self.bytes_per_line();
                }
            }
            Action::SelectInterface(index) => {
                if let Some(Dialog::Interfaces {
                    entries,
                    selected,
                    checked,
                }) = &mut self.dialog
                {
                    if index < entries.len() {
                        *selected = index;
                        if !checked.remove(&index) {
                            checked.insert(index);
                        }
                    }
                }
            }
            Action::Move(delta) => match self.pane {
                Pane::Packets => {
                    self.session.move_selection(delta);
                    self.reveal_packet();
                }
                Pane::Details => {
                    self.detail_selected = self
                        .detail_selected
                        .saturating_add_signed(delta)
                        .min(self.detail_rows().len().saturating_sub(1));
                    reveal(
                        &mut self.detail_offset,
                        self.detail_selected,
                        self.regions.details.height as usize,
                    );
                    self.byte_offset = self.selected_range().start / self.bytes_per_line();
                }
                Pane::Bytes => {
                    self.set_offset(Pane::Bytes, self.byte_offset.saturating_add_signed(delta))
                }
            },
            Action::Home => {
                self.apply(Action::Move(-(isize::MAX / 2)));
            }
            Action::End => {
                self.apply(Action::Move(isize::MAX / 2));
            }
            Action::Toggle => {
                if let Some(&(layer, _)) = self.detail_rows().get(self.detail_selected) {
                    if !self.collapsed.remove(&layer) {
                        self.collapsed.insert(layer);
                    }
                    self.detail_selected = self
                        .detail_rows()
                        .iter()
                        .position(|&(l, f)| l == layer && f.is_none())
                        .unwrap_or(0);
                }
            }
            Action::Scroll(pane, delta) => {
                self.pane = pane;
                self.set_offset(pane, self.offset(pane).saturating_add_signed(delta));
            }
            Action::CloseDialog => self.dialog = None,
            Action::ApplyDialog => self.apply_dialog(),
        }
    }
    fn apply_dialog(&mut self) {
        match self.dialog.take() {
            Some(Dialog::Open(input)) => {
                if input.value.is_empty() {
                    self.notice = "Enter a capture file path".into();
                } else {
                    self.source = Some(SourceSpec::File(input.value.into()));
                    self.start();
                }
            }
            Some(Dialog::Bpf(input)) => {
                if let Some(SourceSpec::Live(spec)) = &mut self.source {
                    spec.filter = input.value;
                    self.notice = "Capture filter saved; click Start to begin a new capture".into();
                } else {
                    self.notice = "Choose an interface before setting a capture filter".into();
                }
            }
            Some(Dialog::Interfaces {
                entries,
                selected,
                mut checked,
            }) => {
                if checked.is_empty() {
                    checked.insert(selected);
                }
                let interfaces: Vec<String> = checked
                    .iter()
                    .filter_map(|index| entries.get(*index).cloned())
                    .collect();
                if !interfaces.is_empty() {
                    self.ingest.detach();
                    self.notice = format!(
                        "Selected {} · click Start to capture",
                        interfaces.join(" + ")
                    );
                    self.source = Some(SourceSpec::Live(LiveSpec {
                        interfaces,
                        ..LiveSpec::default()
                    }));
                }
            }
            Some(Dialog::Export(input, selected)) => {
                self.notice = match self.export(Path::new(&input.value), selected) {
                    Ok(notice) => notice,
                    Err(error) => format!("Export failed: {error}"),
                };
            }
            Some(Dialog::Find(input)) => {
                let needle = match input.value.strip_prefix("hex:") {
                    Some(hex) => filter::hex(hex.trim()),
                    None => Ok(input.value.into_bytes()),
                };
                match needle {
                    Ok(needle) if !needle.is_empty() => {
                        self.find = Some(Filter::containing(&needle));
                        self.find_next(true);
                    }
                    Ok(_) => self.notice = "Enter text, or hex:… bytes, to search for".into(),
                    Err(error) => self.notice = error,
                }
            }
            Some(Dialog::Comment(input)) => {
                let comment = Some(input.value.trim().to_string()).filter(|c| !c.is_empty());
                self.session.annotate(None, Some(comment));
                self.cached_id = None;
            }
            Some(Dialog::Goto(input)) => match input.value.trim().parse::<u64>() {
                Ok(id) if id > 0 && self.session.select_id(id) => self.reveal_packet(),
                Ok(id) if id > 0 && matches!(self.source, Some(SourceSpec::File(_))) => {
                    self.window_starts.push(self.window_first);
                    self.seek(id, None, true);
                }
                _ => self.notice = "That packet is not displayed (enter its number)".into(),
            },
            Some(Dialog::KeyLog(input)) => {
                if input.value.trim().is_empty() {
                    (self.keylog, self.keylog_path) = (None, None);
                    self.notice = "TLS key log cleared".into();
                } else {
                    self.load_keylog(PathBuf::from(input.value.trim()));
                }
            }
            _ => {}
        }
    }

    /// A display filter for the selected field, or the selected packet's
    /// conversation when the packet list has focus.
    fn selection_filter(&self) -> Option<String> {
        let packet = self.session.selected_packet()?;
        if self.pane == Pane::Packets {
            let summary = &packet.summary;
            return summary
                .stream
                .map(|stream| format!("stream={stream}"))
                .or_else(|| summary.src.map(|src| format!("addr={src}")));
        }
        let &(layer, field) = self.detail_rows().get(self.detail_selected)?;
        let label = match field {
            Some(field) => &self.layers[layer].fields[field].label,
            None => &self.layers[layer].label,
        };
        if !label.contains('"') && !label.chars().any(char::is_control) {
            return Some(format!("field contains \"{label}\""));
        }
        // The filter language has no quote escape: match the field's bytes.
        let bytes = packet.view().0.get(self.selected_range())?;
        let hex: Vec<_> = bytes.iter().take(32).map(|b| format!("{b:02x}")).collect();
        (!hex.is_empty()).then(|| format!("bytes contains {}", hex.join(":")))
    }

    fn open_input(&mut self, dialog: Dialog) {
        self.editing_filter = false;
        self.dialog = Some(dialog);
    }

    pub fn load_keylog(&mut self, path: PathBuf) {
        match KeyLog::load(&path) {
            Ok(log) => {
                let secrets = log.len();
                (self.keylog, self.keylog_path) = (Some(Arc::new(log)), Some(path));
                // Decryption happens while packets are analyzed: reload a file.
                if matches!(self.source, Some(SourceSpec::File(_))) && self.ingest.has_worker() {
                    self.seek(self.window_first, None, false);
                }
                self.notice = format!(
                    "Loaded {secrets} TLS secrets · decrypted data shows in Info and with F"
                );
            }
            Err(error) => self.notice = format!("Cannot read key log {}: {error}", path.display()),
        }
    }

    // ponytail: exports run on the UI thread; move to a worker if saving a
    // full 1M-packet window as JSON ever stalls input noticeably.
    fn export(&self, path: &Path, selected: bool) -> std::io::Result<String> {
        let mut writer = Writer::create(path)?;
        if selected {
            if let Some(packet) = self.session.selected_packet() {
                writer.write(packet)?;
            }
        } else {
            for packet in self.session.visible_packets() {
                writer.write(packet)?;
            }
        }
        let writer = writer.finish()?;
        Ok(format!(
            "Saved {} packets to {}{}",
            writer.written,
            path.display(),
            if writer.skipped > 0 {
                format!(
                    " · {} skipped: PCAP holds one link type, use .pcapng",
                    writer.skipped
                )
            } else {
                String::new()
            }
        ))
    }

    fn find_next(&mut self, forward: bool) {
        let Some(find) = self.find.clone() else {
            self.apply(Action::Find);
            return;
        };
        let found = "Match found · F3 or . next · , previous";
        if self.session.find(&find, forward, false) {
            self.reveal_packet();
            self.notice = found.into();
        } else if forward && self.ingest.window_full {
            // The rest of the file is not in memory: let the worker scan it.
            let from = self
                .session
                .last_id()
                .map_or(self.window_first, |id| id + 1);
            self.window_starts.push(self.window_first);
            let find = find.and(self.session.filter());
            self.seek(from, Some(find), true);
            self.notice = "Searching the rest of the capture… (s stops)".into();
        } else if self.session.find(&find, forward, true) {
            self.reveal_packet();
            self.notice = format!("{found} · search wrapped around");
        } else {
            self.notice = "No match".into();
        }
    }

    // ponytail: recomputed over the displayed packets each time it opens.
    fn open_stats(&mut self) {
        let mut stats = Stats::new(self.stats_interval);
        self.session
            .visible_packets()
            .for_each(|packet| stats.add(packet));
        self.editing_filter = false;
        self.dialog = Some(Dialog::Text {
            title: " STATISTICS · displayed packets ".into(),
            lines: stats.report(15, self.stats_unit),
            offset: 0,
            view: View::Stats,
        });
    }

    fn open_follow(&mut self) {
        let Some(id) = self
            .session
            .selected_packet()
            .and_then(|p| p.summary.stream)
        else {
            self.notice = "Select a TCP or UDP packet to follow its stream".into();
            return;
        };
        let mut follower = Follower::new(id, FOLLOW_LIMIT);
        self.session
            .packets()
            .for_each(|packet| follower.push(packet));
        let mut stream = follower.finish();
        let mut lines = Vec::new();
        let tls = stream
            .chunks
            .first()
            .is_some_and(|chunk| is_record(&chunk.data));
        match (
            &KeyLog::or_private_keys(self.keylog.clone()),
            tls && self.follow_decrypt,
        ) {
            (Some(log), true) => match decrypt(&stream, log) {
                Ok(plain) => {
                    stream = plain;
                    lines.push("[TLS decrypted with the key log]".to_string());
                }
                Err(error) => lines.push(format!("[TLS not decrypted: {error}]")),
            },
            (None, true) => lines.push("[TLS stream · press K to load a key log]".into()),
            _ => {}
        }
        lines.extend(stream.lines(self.follow_hex));
        self.editing_filter = false;
        self.dialog = Some(Dialog::Text {
            title: format!(" {} ", stream.title()),
            lines,
            offset: 0,
            view: View::Follow,
        });
    }
    pub fn reveal_packet(&mut self) {
        if let Some(index) = self.session.selected_index() {
            reveal(
                &mut self.packet_offset,
                index,
                self.regions.packets.height as usize,
            );
        }
    }
    pub fn validate_filter(&mut self) {
        self.filter_error = Filter::parse(&self.filter.value).err();
    }
}

pub fn reveal(offset: &mut usize, index: usize, height: usize) {
    if index < *offset {
        *offset = index;
    } else if index >= offset.saturating_add(height.max(1)) {
        *offset = index.saturating_sub(height.saturating_sub(1));
    }
}
