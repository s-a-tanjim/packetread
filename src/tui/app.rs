use super::theme::Theme;
use crate::{
    decode::{details, Layer, Packet},
    filter::Filter,
    session::Session,
    source::{SourceSpec, Status, Worker},
};
use ratatui::layout::Rect;
use std::{
    collections::{BTreeSet, VecDeque},
    ops::Range,
    time::{Duration, Instant},
};

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

#[derive(Clone)]
pub enum Dialog {
    Help,
    Open(TextInput),
    Bpf(TextInput),
    Interfaces {
        entries: Vec<String>,
        selected: usize,
    },
}

pub struct App {
    pub session: Session,
    pub source: Option<SourceSpec>,
    pub worker: Option<Worker>,
    pub status: Status,
    pub pending: VecDeque<Packet>,
    pub window_full: bool,
    pub theme: Theme,
    pub pane: Pane,
    pub filter: TextInput,
    active_filter: String,
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
    pub packet_rate: u64,
    pub byte_rate: u64,
    pub packet_history: VecDeque<u64>,
    pub byte_history: VecDeque<u64>,
    rate_time: Instant,
    rate_packets: u64,
    rate_bytes: u64,
}

impl App {
    pub fn new(source: Option<SourceSpec>, memory: usize, max_packets: usize, theme: &str) -> Self {
        Self {
            session: Session::new(memory, max_packets),
            source,
            worker: None,
            status: Status::default(),
            pending: VecDeque::new(),
            window_full: false,
            theme: Theme::named(theme),
            pane: Pane::Packets,
            filter: TextInput::default(),
            active_filter: String::new(),
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
            packet_rate: 0,
            byte_rate: 0,
            packet_history: VecDeque::from(vec![0; 60]),
            byte_history: VecDeque::from(vec![0; 60]),
            rate_time: Instant::now(),
            rate_packets: 0,
            rate_bytes: 0,
        }
    }
    pub fn start(&mut self) {
        let Some(spec) = self.source.clone() else {
            self.apply(Action::Interfaces);
            return;
        };
        // Dropping a worker cancels it, including a blocked offline producer.
        self.worker.take();
        self.session = Session::new(self.session.byte_limit, self.session.packet_limit);
        let _ = self.session.set_filter(&self.active_filter);
        self.pending.clear();
        self.window_full = false;
        self.cached_id = None;
        self.layers.clear();
        self.packet_offset = 0;
        self.status = Status::default();
        self.rate_packets = 0;
        self.rate_bytes = 0;
        self.rate_time = Instant::now();
        self.packet_history.make_contiguous().fill(0);
        self.byte_history.make_contiguous().fill(0);
        match Worker::start(spec) {
            Ok(worker) => {
                self.worker = Some(worker);
                self.notice = "Opening source…".into();
            }
            Err(error) => self.notice = format!("Cannot start capture: {error}"),
        }
    }

    pub fn tick(&mut self) -> bool {
        let previous_status = self.status.clone();
        let previous_selection = self.session.selected;
        let previous_len = self.session.len();
        let previous_evicted = self.session.evicted;
        let was_filtering = self.session.filtering;
        let mut rate_changed = false;
        let live = self.source.as_ref().is_some_and(SourceSpec::is_live);
        let started = Instant::now();
        if let Some(worker) = &self.worker {
            self.status = worker.status();
            while !self.window_full && started.elapsed() < Duration::from_millis(3) {
                if self.pending.is_empty() {
                    match worker.packets.try_recv() {
                        Ok(batch) => self.pending = batch.into(),
                        Err(_) => break,
                    }
                }
                let Some(packet) = self.pending.front() else {
                    break;
                };
                if !live && !self.session.has_room(packet) {
                    self.window_full = true;
                    self.notice =
                        "File window full · click Next to continue; earlier packets leave memory"
                            .into();
                    break;
                }
                if let Some(packet) = self.pending.pop_front() {
                    self.session.insert(packet);
                }
            }
        }
        self.session.filter_step(Duration::from_millis(2));
        if self.cached_id != self.session.selected {
            self.layers = self
                .session
                .selected_packet()
                .map(|p| details(&p.bytes, p.link))
                .unwrap_or_default();
            self.cached_id = self.session.selected;
            self.collapsed.clear();
            self.detail_selected = 0;
            self.detail_offset = 0;
            self.byte_offset = 0;
        }
        if let Some(notice) = self.session.notice.take() {
            self.notice = notice;
        }
        if self.needs_capture_permission() {
            self.notice =
                "Live capture needs CAP_NET_RAW · click Help for setup instructions".into();
            if previous_status.error != self.status.error && self.dialog.is_none() {
                self.dialog = Some(Dialog::Help);
            }
        } else if let Some(error) = &self.status.error {
            self.notice = format!("Source error: {error}");
        } else if self.notice == "Opening source…" && (self.status.packets > 0 || self.status.done)
        {
            self.notice = "Select packets and protocol fields to inspect their bytes".into();
        }
        let elapsed = self.rate_time.elapsed().as_secs_f64();
        if elapsed >= 1.0 {
            rate_changed = true;
            self.packet_rate =
                ((self.status.packets.saturating_sub(self.rate_packets)) as f64 / elapsed) as u64;
            self.byte_rate =
                ((self.status.bytes.saturating_sub(self.rate_bytes)) as f64 / elapsed) as u64;
            self.packet_history.pop_front();
            self.packet_history.push_back(self.packet_rate);
            self.byte_history.pop_front();
            self.byte_history.push_back(self.byte_rate);
            self.rate_packets = self.status.packets;
            self.rate_bytes = self.status.bytes;
            self.rate_time = Instant::now();
        }
        rate_changed
            || was_filtering
            || self.status != previous_status
            || self.session.selected != previous_selection
            || self.session.len() != previous_len
            || self.session.evicted != previous_evicted
    }

    pub fn needs_capture_permission(&self) -> bool {
        self.source.as_ref().is_some_and(SourceSpec::is_live)
            && self
                .status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("CAP_NET_RAW"))
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
                .visible
                .len()
                .saturating_sub(self.regions.packets.height as usize),
            Pane::Details => self
                .detail_rows()
                .len()
                .saturating_sub(self.regions.details.height as usize),
            Pane::Bytes => self
                .session
                .selected_packet()
                .map_or(0, |p| p.bytes.len().div_ceil(self.bytes_per_line()))
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
                self.session.follow = false;
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
                match pcap::Device::list() {
                    Ok(entries) => {
                        self.dialog = Some(Dialog::Interfaces {
                            entries: entries.into_iter().map(|d| d.name).collect(),
                            selected: 0,
                        })
                    }
                    Err(error) => self.notice = format!("Cannot list interfaces: {error}"),
                }
            }
            Action::Start => self.start(),
            Action::Stop => {
                if let Some(worker) = &self.worker {
                    worker.stop();
                }
                self.notice = "Capture stopped; retained packets remain available".into();
            }
            Action::Follow => self.session.toggle_follow(),
            Action::NextWindow => {
                if self.window_full {
                    self.session.next_window();
                    self.window_full = false;
                    self.packet_offset = 0;
                }
            }
            Action::Theme => self.theme = self.theme.next(),
            Action::Help => {
                self.editing_filter = false;
                self.dialog = Some(Dialog::Help);
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
                    self.active_filter = self.filter.value.clone();
                    self.editing_filter = false;
                    self.filter_error = None;
                    self.packet_offset = 0;
                    self.notice = "Display filter applied to retained packets".into();
                }
                Err(error) => self.filter_error = Some(error),
            },
            Action::Bpf => {
                let value = match &self.source {
                    Some(SourceSpec::Live { filter, .. }) => filter.clone(),
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
                if let Some(Dialog::Interfaces { entries, selected }) = &mut self.dialog {
                    if index < entries.len() {
                        *selected = index;
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
                if let Some(SourceSpec::Live { filter, .. }) = &mut self.source {
                    *filter = input.value;
                    self.notice = "Capture filter saved; click Start to begin a new capture".into();
                } else {
                    self.notice = "Choose an interface before setting a capture filter".into();
                }
            }
            Some(Dialog::Interfaces { entries, selected }) => {
                if let Some(interface) = entries.get(selected) {
                    self.worker.take();
                    self.pending.clear();
                    self.status.done = true;
                    self.source = Some(SourceSpec::Live {
                        interface: interface.clone(),
                        filter: String::new(),
                        snaplen: 65535,
                        promiscuous: false,
                    });
                    self.notice =
                        format!("Interface {interface} selected · click Start to capture");
                }
            }
            _ => {}
        }
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
