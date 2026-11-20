//! Statistics tabs over the displayed packets, recounted as packets arrive.
use crate::{
    decode::diag,
    session::Session,
    stats::{Direction, Stats, Unit},
};
use std::net::{IpAddr, SocketAddr};

const TOP: usize = 50;
const TALKERS: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Ips,
    Conversations,
    Protocols,
    Issues,
}

impl Tab {
    pub const ALL: [Self; 5] = [
        Self::Overview,
        Self::Ips,
        Self::Conversations,
        Self::Protocols,
        Self::Issues,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Ips => "IPs",
            Self::Conversations => "Conversations",
            Self::Protocols => "Protocols",
            Self::Issues => "Issues",
        }
    }

    /// Title for a tab row too narrow for the full names.
    pub fn short(self) -> &'static str {
        match self {
            Self::Conversations => "Conv",
            Self::Protocols => "Proto",
            other => other.title(),
        }
    }
}

/// What a row stands for, and so what opening it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(IpAddr),
    /// The Overview link to the full address ranking.
    AllIps,
    Stream(u32),
    Protocol(&'static str),
    /// Index into `diag::NAMES`.
    Issue(usize),
}

#[derive(Clone, Copy, Debug)]
pub enum Command {
    Tab(Tab),
    /// The next tab, or the previous one.
    NextTab(bool),
    Back,
    /// Show the conversations of every address again.
    Unscope,
    Report,
    Refresh,
    Unit,
    Direction,
    Move(isize),
    /// Move by this many screenfuls.
    Page(isize),
    /// Select a row and open it.
    Open(usize),
    /// Open the selected row.
    Activate,
    /// List the packets behind the selected row.
    Packets,
}

pub struct Column {
    pub title: &'static str,
    pub right: bool,
    /// Zero keeps the column at any width; otherwise higher values go first.
    pub drop: u8,
}

const fn column(title: &'static str, right: bool, drop: u8) -> Column {
    Column { title, right, drop }
}

pub struct Row {
    pub target: Target,
    /// One cell per column.
    pub cells: Vec<String>,
    /// Fraction of the tab's total, drawn as a bar.
    pub share: Option<f64>,
}

pub struct Dashboard {
    pub stats: Stats,
    pub filter: String,
    pub scope: &'static str,
    pub last_id: u64,
    pub tab: Tab,
    pub unit: Unit,
    pub direction: Direction,
    /// Address the Conversations tab is limited to.
    pub address: Option<IpAddr>,
    pub columns: Vec<Column>,
    /// Column the share bar follows.
    pub bar_after: Option<usize>,
    pub rows: Vec<Row>,
    /// Leading Overview rows that belong to the top-talkers panel.
    pub talkers: usize,
    /// Rows the tab could list; more than `rows` when only the top ones are kept.
    pub available: usize,
    pub selected: usize,
    /// First row drawn and rows per screenful; the renderer maintains both.
    pub offset: usize,
    pub page_rows: usize,
    pub message: String,
    history: Vec<(Tab, usize, Option<IpAddr>)>,
}

fn share(value: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| value as f64 / total as f64)
}

fn percent(share: Option<f64>) -> String {
    match share {
        None => "—".into(),
        Some(s) if s > 0.0 && s < 0.0005 => "<0.1%".into(),
        Some(s) => format!("{:.1}%", 100.0 * s),
    }
}

/// `zero-window` as `Zero window`.
fn issue_name(index: usize) -> String {
    let name = diag::NAMES[index].1.replace('-', " ");
    let mut chars = name.chars();
    chars
        .next()
        .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
        .unwrap_or_default()
}

fn issue_rows(stats: &Stats, detailed: bool) -> Vec<Row> {
    let mut rows = Vec::new();
    for (index, (example, count)) in stats.events.iter().enumerate() {
        let Some(e) = example else { continue };
        let cells = if detailed {
            vec![
                issue_name(index),
                count.to_string(),
                format!("#{}", e.packet),
                e.stream.to_string(),
                format!("{} → {}", e.source, e.destination),
            ]
        } else {
            vec![
                issue_name(index),
                count.to_string(),
                format!("first #{}", e.packet),
            ]
        };
        rows.push(Row {
            target: Target::Issue(index),
            cells,
            share: None,
        });
    }
    rows
}

impl Dashboard {
    pub fn new(session: &Session, interval: f64, scope: &'static str) -> Self {
        let mut dashboard = Self {
            stats: Stats::new(interval),
            filter: String::new(),
            scope,
            last_id: 0,
            tab: Tab::Overview,
            unit: Unit::Bytes,
            direction: Direction::Both,
            address: None,
            columns: Vec::new(),
            bar_after: None,
            rows: Vec::new(),
            talkers: 0,
            available: 0,
            selected: 0,
            offset: 0,
            page_rows: 0,
            message: String::new(),
            history: Vec::new(),
        };
        dashboard.refresh(session, interval, scope);
        dashboard
    }

    /// Counts the displayed packets again; the tab and the selected row stay.
    pub fn refresh(&mut self, session: &Session, interval: f64, scope: &'static str) {
        let mut stats = Stats::new(interval);
        session
            .visible_packets()
            .for_each(|packet| stats.add(packet));
        self.stats = stats;
        self.filter = session.filter_text().into();
        self.scope = scope;
        self.last_id = session.last_id().unwrap_or(0);
        self.rebuild_keeping_selection();
    }

    /// Switches tab without recording a step for `back`.
    pub fn show(&mut self, tab: Tab) {
        if tab != self.tab {
            self.tab = tab;
            self.rebuild();
        }
    }

    /// Opens a tab from a row, so `back` returns to that row.
    pub fn drill(&mut self, tab: Tab, address: Option<IpAddr>) {
        self.history.push((self.tab, self.selected, self.address));
        self.tab = tab;
        self.address = address;
        self.rebuild();
    }

    pub fn back(&mut self) {
        if let Some((tab, selected, address)) = self.history.pop() {
            self.tab = tab;
            self.address = address;
            self.rebuild();
            self.select(selected);
        }
    }

    pub fn unscope(&mut self) {
        if self.address.take().is_some() {
            self.rebuild();
        }
    }

    pub fn select(&mut self, index: usize) {
        self.selected = index.min(self.rows.len().saturating_sub(1));
    }

    pub fn move_by(&mut self, delta: isize) {
        self.select(self.selected.saturating_add_signed(delta));
    }

    pub fn rebuild_keeping_selection(&mut self) {
        let target = self.rows.get(self.selected).map(|row| row.target);
        let (selected, offset) = (self.selected, self.offset);
        self.rebuild();
        self.offset = offset;
        // The selection follows its row when the ranking moves it.
        let moved = target.and_then(|target| self.rows.iter().position(|row| row.target == target));
        self.select(moved.unwrap_or(selected));
    }

    pub fn rebuild(&mut self) {
        let stats = &self.stats;
        let (unit, direction) = (self.unit, self.direction);
        let mut rows = Vec::new();
        let mut message = String::new();
        let mut talkers = 0;
        let mut available = 0;
        let (columns, bar_after) = match self.tab {
            Tab::Overview => {
                let total = Direction::Both.value(stats.endpoint_totals, unit);
                for (ip, counts) in stats.ranked_endpoints(unit, Direction::Both, TALKERS) {
                    let value = Direction::Both.value(counts, unit);
                    let share = share(value, total);
                    rows.push(Row {
                        target: Target::Ip(ip),
                        cells: vec![ip.to_string(), unit.format(value), percent(share)],
                        share,
                    });
                }
                if !rows.is_empty() {
                    rows.push(Row {
                        target: Target::AllIps,
                        cells: vec![
                            format!("All {} addresses →", stats.endpoints.len()),
                            String::new(),
                            String::new(),
                        ],
                        share: None,
                    });
                }
                talkers = rows.len();
                rows.extend(issue_rows(stats, false));
                (
                    vec![
                        column("Item", false, 0),
                        column("Amount", true, 0),
                        column("Detail", false, 1),
                    ],
                    None,
                )
            }
            Tab::Ips => {
                let total = direction.value(stats.endpoint_totals, unit);
                let ranked = stats.ranked_endpoints(unit, direction, TOP);
                available = stats.endpoints.len();
                for (rank, (ip, counts)) in ranked.into_iter().enumerate() {
                    let value = direction.value(counts, unit);
                    let share = share(value, total);
                    rows.push(Row {
                        target: Target::Ip(ip),
                        cells: vec![
                            (rank + 1).to_string(),
                            ip.to_string(),
                            unit.format(value),
                            percent(share),
                            unit.format(unit.value(counts[0])),
                            unit.format(unit.value(counts[1])),
                        ],
                        share,
                    });
                }
                (
                    vec![
                        column("#", true, 0),
                        column("Address", false, 0),
                        column("Total", true, 0),
                        column("Share", true, 2),
                        column("Sent", true, 1),
                        column("Received", true, 1),
                    ],
                    Some(3),
                )
            }
            Tab::Conversations => {
                let address = self.address;
                let mut total = 0;
                for c in stats.conversations.values() {
                    if address.is_none_or(|ip| c.ends.iter().any(|e| e.0 == ip)) {
                        total += c.sent[0].bytes + c.sent[1].bytes;
                        available += 1;
                    }
                }
                for (stream, c) in stats.ranked_conversations(address, TOP) {
                    let protocol = c.application.map(|p| p.name()).unwrap_or(if c.tcp {
                        "TCP"
                    } else {
                        "UDP"
                    });
                    let ends = match address {
                        Some(ip) => {
                            SocketAddr::from(c.ends[usize::from(c.ends[0].0 == ip)]).to_string()
                        }
                        None => format!(
                            "{} ↔ {}",
                            SocketAddr::from(c.ends[0]),
                            SocketAddr::from(c.ends[1])
                        ),
                    };
                    let bytes = c.sent[0].bytes + c.sent[1].bytes;
                    let share = share(bytes, total);
                    let problems: u64 = c.problems.iter().sum();
                    rows.push(Row {
                        target: Target::Stream(stream),
                        cells: vec![
                            format!("#{stream}"),
                            protocol.into(),
                            Unit::Bytes.format(bytes),
                            percent(share),
                            (c.sent[0].packets + c.sent[1].packets).to_string(),
                            if problems == 0 {
                                String::new()
                            } else {
                                problems.to_string()
                            },
                            ends,
                        ],
                        share,
                    });
                }
                if rows.is_empty() {
                    message = if address.is_some() {
                        "No tracked TCP or UDP conversations for this IP".into()
                    } else {
                        "No tracked TCP or UDP conversations".into()
                    };
                }
                (
                    // Addresses come last: they are the column a narrow
                    // terminal can clip without hiding a number.
                    vec![
                        column("Stream", true, 0),
                        column("Proto", false, 0),
                        column("Bytes", true, 0),
                        column("Share", true, 3),
                        column("Packets", true, 2),
                        column("Issues", true, 4),
                        column(
                            if address.is_some() {
                                "Peer"
                            } else {
                                "Endpoints"
                            },
                            false,
                            0,
                        ),
                    ],
                    Some(3),
                )
            }
            Tab::Protocols => {
                let total = unit.value(stats.total);
                for (name, counter) in stats.ranked_protocols(unit) {
                    let share = share(unit.value(counter), total);
                    rows.push(Row {
                        target: Target::Protocol(name),
                        cells: vec![
                            name.into(),
                            Unit::Bytes.format(counter.bytes),
                            counter.packets.to_string(),
                            percent(share),
                        ],
                        share,
                    });
                }
                (
                    vec![
                        column("Protocol", false, 0),
                        column("Bytes", true, 0),
                        column("Packets", true, 1),
                        column("Share", true, 0),
                    ],
                    Some(3),
                )
            }
            Tab::Issues => {
                rows = issue_rows(stats, true);
                if rows.is_empty() && stats.total.packets > 0 {
                    message = "No TCP problems observed in these packets".into();
                }
                (
                    vec![
                        column("Event", false, 0),
                        column("Count", true, 0),
                        column("First", true, 0),
                        column("Stream", true, 1),
                        column("Flow", false, 2),
                    ],
                    None,
                )
            }
        };
        if stats.total.packets == 0 {
            message = "No packets match".into();
        } else if matches!(self.tab, Tab::Overview | Tab::Ips) {
            if stats.endpoints.is_empty() {
                message = "Matching packets have no decoded IP addresses".into();
            } else if stats.omitted_endpoints.iter().any(|c| c.packets > 0) {
                message = format!(
                    "Top tracked IPs · omitted {} sent / {} received",
                    unit.format(unit.value(stats.omitted_endpoints[0])),
                    unit.format(unit.value(stats.omitted_endpoints[1]))
                );
            }
        }
        self.columns = columns;
        self.bar_after = bar_after;
        self.rows = rows;
        self.talkers = talkers;
        self.available = available.max(self.rows.len());
        self.message = message;
        self.selected = 0;
        self.offset = 0;
    }
}
