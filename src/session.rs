use crate::{
    decode::{Packet, Protocol},
    filter::Filter,
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::IpAddr,
    time::{Duration, Instant},
};

pub struct Session {
    // IDs increase monotonically, so the first key is always the oldest packet.
    packets: BTreeMap<u64, Packet>,
    // Sorted subset of `packets` matching the filter; `selected` is a member.
    visible: VecDeque<u64>,
    selected: Option<u64>,
    follow: bool,
    bytes: usize,
    evicted: u64,
    notice: Option<String>,
    byte_limit: usize,
    packet_limit: usize,
    filter: Filter,
    filter_text: String,
    scan_after: Option<u64>,
    filtering: bool,
    // Marks and comments by packet ID; they survive file-window changes.
    annotations: BTreeMap<u64, (bool, Option<String>)>,
    // Host names learned from DNS answers in the capture.
    names: HashMap<IpAddr, String>,
}

/// The queried name and the addresses it resolved to, from a DNS response
/// summary such as `Response A example.com → www.example.com, 192.0.2.7`.
fn dns_answers(info: &str) -> Option<(&str, Vec<IpAddr>)> {
    let (question, answers) = info.split_once("Response ")?.1.split_once(" → ")?;
    let answers = answers.split(" · ").next()?;
    let addresses: Vec<_> = answers.split(", ").filter_map(|a| a.parse().ok()).collect();
    Some((question.rsplit(' ').next()?, addresses)).filter(|(_, a)| !a.is_empty())
}

const MAX_ANNOTATIONS: usize = 10_000;

impl Session {
    pub fn new(byte_limit: usize, packet_limit: usize) -> Self {
        Self {
            packets: BTreeMap::new(),
            visible: VecDeque::new(),
            selected: None,
            follow: true,
            bytes: 0,
            evicted: 0,
            notice: None,
            byte_limit,
            packet_limit,
            filter: Filter::default(),
            filter_text: String::new(),
            scan_after: None,
            filtering: false,
            annotations: BTreeMap::new(),
            names: HashMap::new(),
        }
    }
    /// Forgets every packet and counter; keeps the limits and the filter.
    pub fn restart(&mut self) {
        let filter = std::mem::take(&mut self.filter);
        let filter_text = std::mem::take(&mut self.filter_text);
        *self = Self {
            filter,
            filter_text,
            ..Self::new(self.byte_limit, self.packet_limit)
        };
    }
    pub fn len(&self) -> usize {
        self.packets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
    pub fn visible(&self) -> &VecDeque<u64> {
        &self.visible
    }
    pub fn selected(&self) -> Option<u64> {
        self.selected
    }
    pub fn follow(&self) -> bool {
        self.follow
    }
    pub fn unfollow(&mut self) {
        self.follow = false;
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn byte_limit(&self) -> usize {
        self.byte_limit
    }
    pub fn packet_limit(&self) -> usize {
        self.packet_limit
    }
    pub fn filter_text(&self) -> &str {
        &self.filter_text
    }
    pub fn filter(&self) -> &Filter {
        &self.filter
    }
    /// Selects a displayed packet by ID.
    pub fn select_id(&mut self, id: u64) -> bool {
        let found = self.visible.binary_search(&id).is_ok();
        if found {
            self.selected = Some(id);
            self.follow = false;
        }
        found
    }
    pub fn evicted(&self) -> u64 {
        self.evicted
    }
    pub fn filtering(&self) -> bool {
        self.filtering
    }
    pub fn take_notice(&mut self) -> Option<String> {
        self.notice.take()
    }
    pub fn packet(&self, id: u64) -> Option<&Packet> {
        self.packets.get(&id)
    }
    pub fn selected_packet(&self) -> Option<&Packet> {
        self.selected.and_then(|id| self.packet(id))
    }
    pub fn has_room(&self, packet: &Packet) -> bool {
        self.len() < self.packet_limit
            && self.bytes.saturating_add(packet.memory_size()) <= self.byte_limit
    }
    /// Host name a DNS answer in this session gave for `address`.
    pub fn name(&self, address: &IpAddr) -> Option<&str> {
        self.names.get(address).map(String::as_str)
    }
    pub fn insert(&mut self, mut packet: Packet) {
        if packet.summary.protocol == Protocol::Dns {
            if let Some((name, addresses)) = dns_answers(&packet.summary.info) {
                for address in addresses {
                    if self.names.len() < 10_000 || self.names.contains_key(&address) {
                        self.names.insert(address, name.to_string());
                    }
                }
            }
        }
        if let Some((mark, comment)) = self.annotations.get(&packet.id) {
            packet.mark = *mark;
            if comment.is_some() {
                packet.comment.clone_from(comment);
            }
        }
        if packet.memory_size() > self.byte_limit {
            self.notice = Some("Packet exceeds storage budget".into());
            return;
        }
        while !self.has_room(&packet) && !self.packets.is_empty() {
            self.evict_one();
        }
        let id = packet.id;
        self.bytes += packet.memory_size();
        // During a filter rebuild the incremental scanner also handles new arrivals.
        if !self.filtering && self.filter.matches(&packet) {
            self.visible.push_back(id);
            if self.follow || self.selected.is_none() {
                self.selected = Some(id);
            }
        }
        self.packets.insert(id, packet);
    }
    fn evict_one(&mut self) {
        if let Some((id, packet)) = self.packets.pop_first() {
            self.bytes -= packet.memory_size();
            if self.visible.front() == Some(&id) {
                self.visible.pop_front();
            }
            if self.selected == Some(id) {
                self.selected = self.visible.front().copied();
                self.notice = Some("Selected packet was evicted from history".into());
            }
            self.evicted += 1;
        }
    }
    /// Empties the retained window; counters, filter and annotations stay.
    pub fn next_window(&mut self) {
        self.packets.clear();
        self.visible.clear();
        self.bytes = 0;
        self.selected = None;
        self.scan_after = None;
        self.filtering = false;
        self.notice = Some("Loading file window".into());
    }
    /// Retained packets, oldest first.
    pub fn packets(&self) -> impl Iterator<Item = &Packet> {
        self.packets.values()
    }
    /// Packets matching the display filter, oldest first.
    pub fn visible_packets(&self) -> impl Iterator<Item = &Packet> {
        self.visible.iter().filter_map(|id| self.packets.get(id))
    }
    pub fn last_id(&self) -> Option<u64> {
        self.packets.keys().next_back().copied()
    }
    /// Changes the selected packet's mark and/or comment. A changed packet
    /// stays in the view until the filter is applied again.
    pub fn annotate(&mut self, mark: Option<bool>, comment: Option<Option<String>>) -> bool {
        let Some(packet) = self.selected.and_then(|id| self.packets.get_mut(&id)) else {
            return false;
        };
        self.bytes -= packet.memory_size();
        if let Some(mark) = mark {
            packet.mark = mark;
        }
        if let Some(comment) = comment {
            packet.comment = comment;
        }
        self.bytes += packet.memory_size();
        if packet.mark || packet.comment.is_some() {
            if self.annotations.len() < MAX_ANNOTATIONS || self.annotations.contains_key(&packet.id)
            {
                self.annotations
                    .insert(packet.id, (packet.mark, packet.comment.clone()));
            } else {
                self.notice = Some(
                    "Annotation limit reached; this one is lost when the window changes".into(),
                );
            }
        } else {
            self.annotations.remove(&packet.id);
        }
        true
    }
    /// Selects the next (or previous) displayed packet after the selection
    /// that matches `filter`; with `wrap`, continues from the other end.
    pub fn find(&mut self, filter: &Filter, forward: bool, wrap: bool) -> bool {
        let count = self.visible.len();
        let start = self.selected_index();
        let matches = |index: &usize| {
            let packet = self.visible.get(*index).and_then(|id| self.packets.get(id));
            packet.is_some_and(|packet| filter.matches(packet))
        };
        let after = start.map_or(0, |index| index + 1)..count;
        let before = 0..start.unwrap_or(count);
        let found = match (forward, wrap) {
            (true, false) => after.into_iter().find(matches),
            (true, true) => after
                .chain(0..start.map_or(0, |index| index + 1))
                .find(matches),
            (false, false) => before.rev().find(matches),
            (false, true) => before
                .rev()
                .chain((start.unwrap_or(count)..count).rev())
                .find(matches),
        };
        found.map(|index| self.select_index(index)).is_some()
    }
    pub fn set_filter(&mut self, text: &str) -> Result<(), String> {
        let filter = Filter::parse(text)?;
        self.filter = filter;
        self.filter_text = text.to_string();
        self.visible.clear();
        self.scan_after = None;
        self.filtering = true;
        Ok(())
    }
    pub fn filter_step(&mut self, budget: Duration) {
        if !self.filtering {
            return;
        }
        let started = Instant::now();
        let start = self
            .scan_after
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut exhausted = true;
        for (&id, packet) in self.packets.range((start, std::ops::Bound::Unbounded)) {
            self.scan_after = Some(id);
            if self.filter.matches(packet) {
                self.visible.push_back(id);
            }
            if started.elapsed() >= budget {
                exhausted = false;
                break;
            }
        }
        if exhausted {
            self.filtering = false;
            if self.follow {
                self.selected = self.visible.back().copied();
            } else if !self.visible.iter().any(|id| Some(*id) == self.selected) {
                self.selected = self.visible.front().copied();
            }
        }
    }
    pub fn selected_index(&self) -> Option<usize> {
        let id = self.selected?;
        // IDs remain sorted even when capture batches were dropped.
        let mut low = 0;
        let mut high = self.visible.len();
        while low < high {
            let mid = (low + high) / 2;
            if self.visible[mid] < id {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        (self.visible.get(low) == Some(&id)).then_some(low)
    }
    pub fn select_index(&mut self, index: usize) {
        if let Some(id) = self.visible.get(index) {
            self.selected = Some(*id);
            self.follow = false;
        }
    }
    pub fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let index = self
            .selected_index()
            .unwrap_or(0)
            .saturating_add_signed(delta)
            .min(self.visible.len() - 1);
        self.select_index(index);
    }
    pub fn toggle_follow(&mut self) {
        self.follow = !self.follow;
        if self.follow {
            self.selected = self.visible.back().copied();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(id: u64) -> Packet {
        Packet::new(id, 0, 1, 999, vec![0].into_boxed_slice())
    }
    #[test]
    fn eviction_keeps_ids_stable_and_memory_bounded() {
        let mut session = Session::new(4096, 2);
        session.insert(packet(1));
        session.insert(packet(2));
        session.select_index(0);
        session.insert(packet(5));
        assert_eq!(
            session.visible.iter().copied().collect::<Vec<_>>(),
            vec![2, 5]
        );
        assert_eq!(session.selected, Some(2));
        assert_eq!(session.evicted, 1);
        assert!(session.bytes <= 4096);
    }
    #[test]
    fn filtering_accepts_arrivals_during_rebuild() {
        let mut session = Session::new(4096, 10);
        session.insert(packet(1));
        session.set_filter("proto=unknown").unwrap();
        session.insert(packet(2));
        session.filter_step(Duration::from_secs(1));
        assert_eq!(session.visible.len(), 2);
        assert!(!session.filtering);
        assert!(session.set_filter("bogus").is_err());
        assert_eq!(session.visible.len(), 2);
    }
    #[test]
    fn learns_names_from_dns_response_summaries() {
        let (name, addresses) =
            dns_answers("Response A example.com → www.example.com, 192.0.2.7, 2001:db8::7 · [x]")
                .unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(addresses.len(), 2);
        for other in [
            "Query A example.com",
            "Response A example.com",
            "Response A x → cname.only",
        ] {
            assert!(dns_answers(other).is_none());
        }
    }
    #[test]
    fn annotations_survive_window_changes_and_search_moves_the_selection() {
        let mut session = Session::new(1 << 20, 10);
        (1..=4).for_each(|id| session.insert(packet(id)));
        session.select_index(1);
        let before = session.bytes;
        assert!(session.annotate(Some(true), Some(Some("odd".into()))));
        assert_eq!(session.bytes, before + 3);
        session.set_filter("marked comment~odd").unwrap();
        session.filter_step(Duration::from_secs(1));
        assert_eq!(session.visible, [2]);
        session.next_window();
        session.insert(packet(2));
        assert!(session.packet(2).unwrap().mark);
        assert_eq!(session.packet(2).unwrap().comment.as_deref(), Some("odd"));
        session.annotate(Some(false), Some(None));
        assert!(session.annotations.is_empty());

        session.set_filter("").unwrap();
        (5..=8).for_each(|id| session.insert(packet(id)));
        session.filter_step(Duration::from_secs(1));
        session.select_index(0);
        let any = Filter::containing(&[0]);
        assert!(session.find(&any, true, false));
        assert_eq!(session.selected, Some(5));
        assert!(session.find(&any, false, false));
        assert_eq!(session.selected, Some(2));
        assert!(!session.find(&any, false, false));
        assert!(session.find(&any, false, true));
        assert_eq!(session.selected, Some(8));
        assert!(session.find(&any, true, true));
        assert_eq!(session.selected, Some(2));
        assert!(!session.find(&Filter::containing(b"absent"), true, true));
    }
}
