use anyhow::{Context, Result, anyhow};
use rand_core::{OsRng, RngCore};

use crate::record::Frame;

pub fn batch_packets<I>(packets: I, capacity: usize) -> Result<Vec<Vec<u8>>>
where
    I: IntoIterator<Item = Vec<u8>>,
{
    let mut records = Vec::new();
    let mut plaintext = Vec::with_capacity(capacity);
    for packet in packets {
        for frame in encode_packet(packet, capacity)? {
            if !plaintext.is_empty() && plaintext.len() + frame.len() > capacity {
                records.push(std::mem::take(&mut plaintext));
                plaintext = Vec::with_capacity(capacity);
            }
            plaintext.extend_from_slice(&frame);
        }
    }
    if !plaintext.is_empty() {
        records.push(plaintext);
    }
    Ok(records)
}

fn encode_packet(packet: Vec<u8>, capacity: usize) -> Result<Vec<Vec<u8>>> {
    if packet.len() + 4 <= capacity {
        return Ok(vec![
            Frame {
                frame_type: 0x01,
                flags: 0,
                body: packet,
            }
            .encode()?,
        ]);
    }
    let chunk_size = capacity
        .checked_sub(14)
        .ok_or_else(|| anyhow!("record capacity too small"))?;
    let total = u16::try_from(packet.len()).context("packet exceeds fragment limit")?;
    let mut packet_id = [0u8; 4];
    OsRng.fill_bytes(&mut packet_id);
    let mut frames = Vec::new();
    for (index, value) in packet.chunks(chunk_size).enumerate() {
        let offset = index
            .checked_mul(chunk_size)
            .ok_or_else(|| anyhow!("fragment offset overflow"))?;
        let mut body = Vec::with_capacity(10 + value.len());
        body.extend_from_slice(&packet_id);
        body.extend_from_slice(&total.to_be_bytes());
        body.extend_from_slice(&u16::try_from(offset)?.to_be_bytes());
        body.extend_from_slice(&u16::try_from(value.len())?.to_be_bytes());
        body.extend_from_slice(value);
        frames.push(
            Frame {
                frame_type: 0x03,
                flags: 0,
                body,
            }
            .encode()?,
        );
    }
    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fragment::FragmentReassembler, record::parse_frames};
    use std::time::Instant;

    #[test]
    fn packs_three_mtu_packets_into_one_record() {
        let packets = vec![vec![1; 1280], vec![2; 1280], vec![3; 1280]];
        let records = batch_packets(packets.clone(), 4080).unwrap();
        assert_eq!(records.len(), 1);
        let frames = parse_frames(&records[0], crate::record::RecordKind::Data).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].body, packets[0]);
        assert_eq!(frames[1].body, packets[1]);
        assert_eq!(frames[2].body, packets[2]);
    }

    #[test]
    fn fragments_and_reassembles_jumbo_packet() {
        let packet = vec![7; 9000];
        let records = batch_packets(vec![packet.clone()], 4080).unwrap();
        let mut reassembler = FragmentReassembler::new();
        let mut restored = None;
        for record in records {
            for frame in parse_frames(&record, crate::record::RecordKind::Data).unwrap() {
                restored = reassembler
                    .push(&frame.body, Instant::now())
                    .unwrap()
                    .or(restored);
            }
        }
        assert_eq!(restored, Some(packet));
    }
}
