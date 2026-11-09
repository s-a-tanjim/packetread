use crate::{decode::Packet, filter::Filter};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

pub struct Session {
    packets: BTreeMap<u64, Packet>,
    order: VecDeque<u64>,
    pub visible: VecDeque<u64>,
    pub selected: Option<u64>,
    pub follow: bool,
    pub bytes: usize,
    pub evicted: u64,
    pub notice: Option<String>,
    pub byte_limit: usize,
    pub packet_limit: usize,
    filter: Filter,
    scan_after: Option<u64>,
    pub filtering: bool,
}

impl Session {
    pub fn new(byte_limit: usize, packet_limit: usize) -> Self {
        Self {
            packets: BTreeMap::new(),
            order: VecDeque::new(),
            visible: VecDeque::new(),
            selected: None,
            follow: true,
            bytes: 0,
            evicted: 0,
            notice: None,
            byte_limit,
            packet_limit,
            filter: Filter::default(),
            scan_after: None,
            filtering: false,
        }
    }
    pub fn len(&self) -> usize {
        self.order.len()
    }
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
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
    pub fn insert(&mut self, packet: Packet) {
        if packet.memory_size() > self.byte_limit {
            self.notice = Some("Packet exceeds storage budget".into());
            return;
        }
        while !self.has_room(&packet) && !self.order.is_empty() {
            self.evict_one();
        }
        let id = packet.id;
        self.bytes += packet.memory_size();
        // During a filter rebuild the incremental scanner also handles new arrivals.
        if !self.filtering && self.filter.matches(&packet.summary) {
            self.visible.push_back(id);
            if self.follow || self.selected.is_none() {
                self.selected = Some(id);
            }
        }
        self.order.push_back(id);
        self.packets.insert(id, packet);
    }
    fn evict_one(&mut self) {
        if let Some(id) = self.order.pop_front() {
            if let Some(packet) = self.packets.remove(&id) {
                self.bytes -= packet.memory_size();
            }
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
    pub fn next_window(&mut self) {
        self.packets.clear();
        self.order.clear();
        self.visible.clear();
        self.bytes = 0;
        self.selected = None;
        self.scan_after = None;
        self.filtering = false;
        self.notice = Some("Loading next file window".into());
    }
    pub fn set_filter(&mut self, text: &str) -> Result<(), String> {
        let filter = Filter::parse(text)?;
        self.filter = filter;
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
            if self.filter.matches(&packet.summary) {
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
}
