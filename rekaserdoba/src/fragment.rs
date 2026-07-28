use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};

const MAX_REASSEMBLIES: usize = 64;
const MAX_REASSEMBLY_MEMORY: usize = 8 * 1024 * 1024;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(3);

pub struct FragmentReassembler {
    assemblies: HashMap<u32, Assembly>,
    memory: usize,
}

struct Assembly {
    total_len: usize,
    created_at: Instant,
    fragments: BTreeMap<usize, Vec<u8>>,
    received: usize,
}

struct ParsedFragment<'a> {
    packet_id: u32,
    total_len: usize,
    offset: usize,
    data: &'a [u8],
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            assemblies: HashMap::new(),
            memory: 0,
        }
    }

    pub fn push(&mut self, body: &[u8], now: Instant) -> Result<Option<Vec<u8>>> {
        self.expire(now);
        let fragment = ParsedFragment::parse(body)?;
        if !self.assemblies.contains_key(&fragment.packet_id)
            && self.assemblies.len() >= MAX_REASSEMBLIES
        {
            bail!("fragment reassembly limit reached");
        }
        let assembly = self
            .assemblies
            .entry(fragment.packet_id)
            .or_insert_with(|| Assembly {
                total_len: fragment.total_len,
                created_at: now,
                fragments: BTreeMap::new(),
                received: 0,
            });
        if assembly.total_len != fragment.total_len {
            self.remove(fragment.packet_id);
            bail!("fragment total length changed");
        }
        if let Some(existing) = assembly.fragments.get(&fragment.offset) {
            if existing.as_slice() == fragment.data {
                return Ok(None);
            }
            self.remove(fragment.packet_id);
            bail!("conflicting duplicate fragment");
        }
        let start = fragment.offset;
        let end = start + fragment.data.len();
        if assembly.fragments.iter().any(|(other_start, data)| {
            let other_end = *other_start + data.len();
            start < other_end && *other_start < end
        }) {
            self.remove(fragment.packet_id);
            bail!("overlapping fragment");
        }
        if self.memory + fragment.data.len() > MAX_REASSEMBLY_MEMORY {
            bail!("fragment memory limit reached");
        }
        assembly.received += fragment.data.len();
        assembly
            .fragments
            .insert(fragment.offset, fragment.data.to_vec());
        self.memory += fragment.data.len();
        if assembly.received != assembly.total_len {
            return Ok(None);
        }
        let mut expected = 0usize;
        let mut packet = Vec::with_capacity(assembly.total_len);
        for (offset, data) in &assembly.fragments {
            if *offset != expected {
                return Ok(None);
            }
            packet.extend_from_slice(data);
            expected += data.len();
        }
        if expected != assembly.total_len {
            return Ok(None);
        }
        self.remove(fragment.packet_id);
        Ok(Some(packet))
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<u32> = self
            .assemblies
            .iter()
            .filter_map(|(packet_id, assembly)| {
                (now.saturating_duration_since(assembly.created_at) >= REASSEMBLY_TIMEOUT)
                    .then_some(*packet_id)
            })
            .collect();
        for packet_id in expired {
            self.remove(packet_id);
        }
    }

    fn remove(&mut self, packet_id: u32) {
        if let Some(assembly) = self.assemblies.remove(&packet_id) {
            self.memory = self.memory.saturating_sub(assembly.received);
        }
    }
}

impl ParsedFragment<'_> {
    fn parse(body: &[u8]) -> Result<ParsedFragment<'_>> {
        if body.len() < 10 {
            bail!("truncated fragment");
        }
        let packet_id = u32::from_be_bytes(body[0..4].try_into()?);
        let total_len = u16::from_be_bytes(body[4..6].try_into()?) as usize;
        let offset = u16::from_be_bytes(body[6..8].try_into()?) as usize;
        let fragment_len = u16::from_be_bytes(body[8..10].try_into()?) as usize;
        if total_len == 0 || fragment_len == 0 || body.len() != 10 + fragment_len {
            bail!("invalid fragment length");
        }
        let end = offset
            .checked_add(fragment_len)
            .ok_or_else(|| anyhow!("fragment range overflow"))?;
        if end > total_len {
            bail!("fragment exceeds packet");
        }
        Ok(ParsedFragment {
            packet_id,
            total_len,
            offset,
            data: &body[10..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(packet_id: u32, total: u16, offset: u16, data: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&packet_id.to_be_bytes());
        output.extend_from_slice(&total.to_be_bytes());
        output.extend_from_slice(&offset.to_be_bytes());
        output.extend_from_slice(&(data.len() as u16).to_be_bytes());
        output.extend_from_slice(data);
        output
    }

    #[test]
    fn reassembles_out_of_order() {
        let now = Instant::now();
        let mut reassembler = FragmentReassembler::new();
        assert_eq!(reassembler.push(&body(1, 6, 3, b"def"), now).unwrap(), None);
        assert_eq!(
            reassembler.push(&body(1, 6, 0, b"abc"), now).unwrap(),
            Some(b"abcdef".to_vec())
        );
    }

    #[test]
    fn ignores_identical_duplicate() {
        let now = Instant::now();
        let mut reassembler = FragmentReassembler::new();
        assert_eq!(reassembler.push(&body(2, 6, 0, b"abc"), now).unwrap(), None);
        assert_eq!(reassembler.push(&body(2, 6, 0, b"abc"), now).unwrap(), None);
        assert_eq!(
            reassembler.push(&body(2, 6, 3, b"def"), now).unwrap(),
            Some(b"abcdef".to_vec())
        );
    }

    #[test]
    fn destroys_overlapping_assembly() {
        let now = Instant::now();
        let mut reassembler = FragmentReassembler::new();
        reassembler.push(&body(3, 8, 0, b"abcd"), now).unwrap();
        assert!(reassembler.push(&body(3, 8, 2, b"wxyz"), now).is_err());
        assert_eq!(
            reassembler.push(&body(3, 4, 0, b"done"), now).unwrap(),
            Some(b"done".to_vec())
        );
    }

    #[test]
    fn expires_incomplete_assembly() {
        let now = Instant::now();
        let mut reassembler = FragmentReassembler::new();
        reassembler.push(&body(4, 6, 0, b"abc"), now).unwrap();
        assert_eq!(
            reassembler
                .push(&body(4, 6, 3, b"def"), now + Duration::from_secs(4))
                .unwrap(),
            None
        );
    }
}
