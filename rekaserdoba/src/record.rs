use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const RECORD_HEADER_LEN: usize = 31;
pub const MAX_CIPHERTEXT_LEN: usize = 4096;
pub const MAX_RECORDS_PER_EPOCH: u64 = 1 << 32;
pub const DEFAULT_REPLAY_WINDOW: usize = 4096;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TrafficKey {
    key: [u8; 32],
    iv: [u8; 12],
}

pub struct EpochKeys {
    pub c2s_data: TrafficKey,
    pub s2c_data: TrafficKey,
    pub c2s_control: TrafficKey,
    pub s2c_control: TrafficKey,
}

pub struct ApplicationSecrets {
    pub epoch_secret: Zeroizing<[u8; 32]>,
    pub migration: Zeroizing<[u8; 32]>,
    pub resumption: Zeroizing<[u8; 32]>,
    pub exporter: Zeroizing<[u8; 32]>,
    pub epoch: EpochKeys,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    Data,
    Control,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordHeader {
    pub kind: RecordKind,
    pub key_phase: bool,
    pub padded: bool,
    pub session_id: [u8; 16],
    pub epoch: u32,
    pub number: u64,
    pub ciphertext_len: u16,
}

pub struct RecordSender {
    kind: RecordKind,
    session_id: [u8; 16],
    epoch: u32,
    key: TrafficKey,
    next_number: AtomicU64,
}

pub struct RecordReceiver {
    kind: RecordKind,
    session_id: [u8; 16],
    epoch: u32,
    key: TrafficKey,
    replay: ReplayWindow,
}

#[derive(Debug)]
pub struct ReplayWindow {
    width: u64,
    initialized: bool,
    highest: u64,
    bits: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub frame_type: u8,
    pub flags: u8,
    pub body: Vec<u8>,
}

pub struct SessionRecordLayer {
    pub c2s_data: RecordReceiver,
    pub s2c_data: RecordSender,
    pub c2s_control: RecordReceiver,
    pub s2c_control: RecordSender,
}

impl ApplicationSecrets {
    pub fn derive(
        handshake_kdf: &Hkdf<Sha256>,
        transcript: &[u8; 32],
        session_id: [u8; 16],
    ) -> Result<Self> {
        let master = expand(handshake_kdf, "master secret", transcript, 32)?;
        let master_kdf =
            Hkdf::<Sha256>::from_prk(&master).map_err(|_| anyhow!("invalid master secret"))?;
        let epoch_secret = fixed(expand(&master_kdf, "epoch root", transcript, 32)?)?;
        let migration = Zeroizing::new(fixed(expand(&master_kdf, "migration", transcript, 32)?)?);
        let resumption = Zeroizing::new(fixed(expand(&master_kdf, "resumption", transcript, 32)?)?);
        let exporter = Zeroizing::new(fixed(expand(&master_kdf, "exporter", transcript, 32)?)?);
        let epoch = EpochKeys::derive(epoch_secret, session_id, 0)?;
        Ok(Self {
            epoch_secret: Zeroizing::new(epoch_secret),
            migration,
            resumption,
            exporter,
            epoch,
        })
    }
}

impl EpochKeys {
    pub fn derive(epoch_secret: [u8; 32], session_id: [u8; 16], epoch: u32) -> Result<Self> {
        let kdf =
            Hkdf::<Sha256>::from_prk(&epoch_secret).map_err(|_| anyhow!("invalid epoch secret"))?;
        let mut context = Vec::with_capacity(20);
        context.extend_from_slice(&session_id);
        context.extend_from_slice(&epoch.to_be_bytes());
        Ok(Self {
            c2s_data: TrafficKey::derive(&kdf, "data c2s", &context)?,
            s2c_data: TrafficKey::derive(&kdf, "data s2c", &context)?,
            c2s_control: TrafficKey::derive(&kdf, "control c2s", &context)?,
            s2c_control: TrafficKey::derive(&kdf, "control s2c", &context)?,
        })
    }
}

impl TrafficKey {
    fn derive(kdf: &Hkdf<Sha256>, purpose: &str, context: &[u8]) -> Result<Self> {
        let key = fixed(expand(kdf, &format!("{purpose} key"), context, 32)?)?;
        let iv = fixed(expand(kdf, &format!("{purpose} iv"), context, 12)?)?;
        Ok(Self { key, iv })
    }

    fn seal(&self, number: u64, header: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = nonce(&self.iv, number);
        cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: header,
                },
            )
            .map_err(|_| anyhow!("record encryption failed"))
    }

    fn open(&self, number: u64, header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = nonce(&self.iv, number);
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| anyhow!("record authentication failed"))
    }
}

impl RecordHeader {
    pub fn encode(&self) -> [u8; RECORD_HEADER_LEN] {
        let mut output = [0u8; RECORD_HEADER_LEN];
        output[0] =
            0x10 | match self.kind {
                RecordKind::Data => 0,
                RecordKind::Control => 0x08,
            } | u8::from(self.key_phase) << 2
                | u8::from(self.padded) << 1;
        output[1..17].copy_from_slice(&self.session_id);
        output[17..21].copy_from_slice(&self.epoch.to_be_bytes());
        output[21..29].copy_from_slice(&self.number.to_be_bytes());
        output[29..31].copy_from_slice(&self.ciphertext_len.to_be_bytes());
        output
    }

    pub fn parse(encoded: &[u8]) -> Result<Self> {
        if encoded.len() < RECORD_HEADER_LEN {
            bail!("truncated record header");
        }
        let version_flags = encoded[0];
        if version_flags >> 4 != 1 || version_flags & 0x01 != 0 {
            bail!("invalid record version or flags");
        }
        let ciphertext_len = u16::from_be_bytes(encoded[29..31].try_into()?);
        if !(16..=MAX_CIPHERTEXT_LEN as u16).contains(&ciphertext_len) {
            bail!("invalid ciphertext length");
        }
        Ok(Self {
            kind: if version_flags & 0x08 != 0 {
                RecordKind::Control
            } else {
                RecordKind::Data
            },
            key_phase: version_flags & 0x04 != 0,
            padded: version_flags & 0x02 != 0,
            session_id: encoded[1..17].try_into()?,
            epoch: u32::from_be_bytes(encoded[17..21].try_into()?),
            number: u64::from_be_bytes(encoded[21..29].try_into()?),
            ciphertext_len,
        })
    }
}

impl RecordSender {
    pub fn new(kind: RecordKind, session_id: [u8; 16], epoch: u32, key: TrafficKey) -> Self {
        Self {
            kind,
            session_id,
            epoch,
            key,
            next_number: AtomicU64::new(0),
        }
    }

    pub fn seal(&self, plaintext: &[u8], padded: bool) -> Result<Vec<u8>> {
        if plaintext.len() + 16 > MAX_CIPHERTEXT_LEN {
            bail!("record plaintext too large");
        }
        let number = self.next_number.fetch_add(1, Ordering::Relaxed);
        if number >= MAX_RECORDS_PER_EPOCH {
            self.next_number
                .store(MAX_RECORDS_PER_EPOCH, Ordering::Relaxed);
            bail!("record hard limit reached");
        }
        let header = RecordHeader {
            kind: self.kind,
            key_phase: self.epoch & 1 != 0,
            padded,
            session_id: self.session_id,
            epoch: self.epoch,
            number,
            ciphertext_len: (plaintext.len() + 16) as u16,
        };
        let encoded_header = header.encode();
        let ciphertext = self.key.seal(number, &encoded_header, plaintext)?;
        let mut output = Vec::with_capacity(RECORD_HEADER_LEN + ciphertext.len());
        output.extend_from_slice(&encoded_header);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }
}

impl RecordReceiver {
    pub fn new(
        kind: RecordKind,
        session_id: [u8; 16],
        epoch: u32,
        key: TrafficKey,
        replay_window: usize,
    ) -> Result<Self> {
        Ok(Self {
            kind,
            session_id,
            epoch,
            key,
            replay: ReplayWindow::new(replay_window)?,
        })
    }

    pub fn open(&mut self, encoded: &[u8]) -> Result<Vec<u8>> {
        let header = RecordHeader::parse(encoded)?;
        if header.kind != self.kind
            || header.session_id.ct_eq(&self.session_id).unwrap_u8() != 1
            || header.epoch != self.epoch
            || header.key_phase != (self.epoch & 1 != 0)
        {
            bail!("record context mismatch");
        }
        let expected_len = RECORD_HEADER_LEN + header.ciphertext_len as usize;
        if encoded.len() != expected_len {
            bail!("record length mismatch");
        }
        if !self.replay.plausible(header.number) {
            bail!("record rejected by replay precheck");
        }
        let plaintext = self.key.open(
            header.number,
            &encoded[..RECORD_HEADER_LEN],
            &encoded[RECORD_HEADER_LEN..],
        )?;
        if !self.replay.commit_authenticated(header.number) {
            bail!("record replayed");
        }
        Ok(plaintext)
    }
}

impl ReplayWindow {
    pub fn new(width: usize) -> Result<Self> {
        if !(256..=16384).contains(&width) || !width.is_multiple_of(64) {
            bail!("invalid replay window width");
        }
        Ok(Self {
            width: width as u64,
            initialized: false,
            highest: 0,
            bits: vec![0; width / 64],
        })
    }

    pub fn plausible(&self, number: u64) -> bool {
        if !self.initialized {
            return true;
        }
        if number.saturating_add(self.width) <= self.highest {
            return false;
        }
        if number > self.highest {
            return true;
        }
        let (word, mask) = self.slot(number);
        self.bits[word] & mask == 0
    }

    pub fn commit_authenticated(&mut self, number: u64) -> bool {
        if !self.plausible(number) {
            return false;
        }
        if !self.initialized {
            self.initialized = true;
            self.highest = number;
        } else if number > self.highest {
            let distance = number - self.highest;
            if distance >= self.width {
                self.bits.fill(0);
            } else {
                for cleared in self.highest + 1..=number {
                    let (word, mask) = self.slot(cleared);
                    self.bits[word] &= !mask;
                }
            }
            self.highest = number;
        }
        let (word, mask) = self.slot(number);
        if self.bits[word] & mask != 0 {
            return false;
        }
        self.bits[word] |= mask;
        true
    }

    fn slot(&self, number: u64) -> (usize, u64) {
        let offset = number % self.width;
        ((offset / 64) as usize, 1u64 << (offset % 64))
    }
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.body.len() > u16::MAX as usize {
            bail!("frame body too large");
        }
        let mut output = Vec::with_capacity(4 + self.body.len());
        output.push(self.frame_type);
        output.push(self.flags);
        output.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        output.extend_from_slice(&self.body);
        Ok(output)
    }
}

impl SessionRecordLayer {
    pub fn new(
        session_id: [u8; 16],
        epoch: u32,
        keys: EpochKeys,
        replay_window: usize,
    ) -> Result<Self> {
        Ok(Self {
            c2s_data: RecordReceiver::new(
                RecordKind::Data,
                session_id,
                epoch,
                keys.c2s_data,
                replay_window,
            )?,
            s2c_data: RecordSender::new(RecordKind::Data, session_id, epoch, keys.s2c_data),
            c2s_control: RecordReceiver::new(
                RecordKind::Control,
                session_id,
                epoch,
                keys.c2s_control,
                replay_window,
            )?,
            s2c_control: RecordSender::new(
                RecordKind::Control,
                session_id,
                epoch,
                keys.s2c_control,
            ),
        })
    }
}

pub fn parse_frames(plaintext: &[u8], kind: RecordKind) -> Result<Vec<Frame>> {
    let mut frames = Vec::new();
    let mut offset = 0usize;
    while offset < plaintext.len() {
        if plaintext.len() - offset < 4 {
            bail!("truncated frame header");
        }
        let frame_type = plaintext[offset];
        let flags = plaintext[offset + 1];
        let frame_len = u16::from_be_bytes(plaintext[offset + 2..offset + 4].try_into()?) as usize;
        offset += 4;
        let end = offset
            .checked_add(frame_len)
            .ok_or_else(|| anyhow!("frame length overflow"))?;
        let body = plaintext
            .get(offset..end)
            .ok_or_else(|| anyhow!("truncated frame body"))?;
        offset = end;
        let known = match kind {
            RecordKind::Data => frame_type <= 0x06,
            RecordKind::Control => (0x01..=0x13).contains(&frame_type),
        };
        if !known && frame_type >= 0x80 {
            bail!("unsupported critical frame");
        }
        if known {
            frames.push(Frame {
                frame_type,
                flags,
                body: body.to_vec(),
            });
        }
    }
    Ok(frames)
}

fn expand(kdf: &Hkdf<Sha256>, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
    let full_label = format!("RekaSerdoba/1 {label}");
    if length > u16::MAX as usize
        || full_label.len() > u8::MAX as usize
        || context.len() > u16::MAX as usize
    {
        bail!("HKDF label, context or output too large");
    }
    let mut info = Vec::with_capacity(5 + full_label.len() + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.extend_from_slice(&(context.len() as u16).to_be_bytes());
    info.extend_from_slice(context);
    let mut output = vec![0u8; length];
    kdf.expand(&info, &mut output)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(output)
}

fn nonce(iv: &[u8; 12], number: u64) -> [u8; 12] {
    let mut output = *iv;
    for (slot, byte) in output[4..].iter_mut().zip(number.to_be_bytes()) {
        *slot ^= byte;
    }
    output
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N]> {
    value
        .try_into()
        .map_err(|_| anyhow!("invalid fixed-size value"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hkdf::Hkdf;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ApplicationVector {
        epoch_secret_b64: String,
        session_id_b64: String,
        epoch: u32,
        data_c2s_key_b64: String,
        data_c2s_iv_b64: String,
        control_s2c_key_b64: String,
        control_s2c_iv_b64: String,
        packet_number: u64,
        nonce_b64: String,
    }

    fn layers() -> (SessionRecordLayer, SessionRecordLayer) {
        let secret = [9u8; 32];
        let session = [4u8; 16];
        let first = EpochKeys::derive(secret, session, 0).unwrap();
        let second = EpochKeys::derive(secret, session, 0).unwrap();
        (
            SessionRecordLayer::new(session, 0, first, 4096).unwrap(),
            SessionRecordLayer::new(session, 0, second, 4096).unwrap(),
        )
    }

    #[test]
    fn application_keys_are_separated() {
        let handshake = Hkdf::<Sha256>::new(Some(b"salt"), b"shared secret");
        let secrets = ApplicationSecrets::derive(&handshake, &[3u8; 32], [5u8; 16]).unwrap();
        assert_ne!(*secrets.migration, *secrets.resumption);
        assert_ne!(*secrets.resumption, *secrets.exporter);
        assert_ne!(secrets.epoch.c2s_data.key, secrets.epoch.s2c_data.key);
        assert_ne!(secrets.epoch.c2s_control.key, secrets.epoch.c2s_data.key);
    }

    #[test]
    fn data_and_control_round_trip() {
        let (client, mut server) = layers();
        let data = client.s2c_data.seal(b"packet", false).unwrap();
        assert_eq!(
            server.c2s_data.open(&data).unwrap_err().to_string(),
            "record authentication failed"
        );

        let secret = [9u8; 32];
        let session = [4u8; 16];
        let client_keys = EpochKeys::derive(secret, session, 0).unwrap();
        let server_keys = EpochKeys::derive(secret, session, 0).unwrap();
        let client_sender = RecordSender::new(RecordKind::Data, session, 0, client_keys.c2s_data);
        let mut server_receiver =
            RecordReceiver::new(RecordKind::Data, session, 0, server_keys.c2s_data, 4096).unwrap();
        let encoded = client_sender.seal(b"packet", false).unwrap();
        assert_eq!(server_receiver.open(&encoded).unwrap(), b"packet");

        let client_keys = EpochKeys::derive(secret, session, 0).unwrap();
        let server_keys = EpochKeys::derive(secret, session, 0).unwrap();
        let client_sender =
            RecordSender::new(RecordKind::Control, session, 0, client_keys.c2s_control);
        let mut server_receiver = RecordReceiver::new(
            RecordKind::Control,
            session,
            0,
            server_keys.c2s_control,
            4096,
        )
        .unwrap();
        let encoded = client_sender.seal(b"control", false).unwrap();
        assert_eq!(server_receiver.open(&encoded).unwrap(), b"control");
    }

    #[test]
    fn authentication_failure_does_not_advance_replay() {
        let secret = [8u8; 32];
        let session = [2u8; 16];
        let sender_keys = EpochKeys::derive(secret, session, 0).unwrap();
        let receiver_keys = EpochKeys::derive(secret, session, 0).unwrap();
        let sender = RecordSender::new(RecordKind::Data, session, 0, sender_keys.c2s_data);
        let mut receiver =
            RecordReceiver::new(RecordKind::Data, session, 0, receiver_keys.c2s_data, 4096)
                .unwrap();
        let encoded = sender.seal(b"valid", false).unwrap();
        let mut forged = encoded.clone();
        forged[RECORD_HEADER_LEN] ^= 1;
        assert!(receiver.open(&forged).is_err());
        assert_eq!(receiver.open(&encoded).unwrap(), b"valid");
        assert!(receiver.open(&encoded).is_err());
    }

    #[test]
    fn replay_window_handles_reorder_and_large_jumps() {
        let mut replay = ReplayWindow::new(256).unwrap();
        assert!(replay.commit_authenticated(300));
        assert!(replay.commit_authenticated(299));
        assert!(!replay.commit_authenticated(299));
        assert!(!replay.plausible(44));
        assert!(replay.commit_authenticated(800));
        assert!(!replay.plausible(300));
    }

    #[test]
    fn frame_parser_ignores_optional_and_rejects_critical_unknowns() {
        let known = Frame {
            frame_type: 0x01,
            flags: 0,
            body: vec![1, 2, 3],
        }
        .encode()
        .unwrap();
        let optional = Frame {
            frame_type: 0x40,
            flags: 0,
            body: vec![4],
        }
        .encode()
        .unwrap();
        let parsed = parse_frames(&[known.clone(), optional].concat(), RecordKind::Data).unwrap();
        assert_eq!(parsed.len(), 1);
        let critical = Frame {
            frame_type: 0x80,
            flags: 0,
            body: vec![],
        }
        .encode()
        .unwrap();
        assert!(parse_frames(&critical, RecordKind::Data).is_err());
    }

    #[test]
    fn malformed_inputs_never_panic() {
        let mut state = 0x9e3779b97f4a7c15u64;
        for length in 0..512usize {
            let mut input = vec![0u8; length];
            for byte in &mut input {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let _ = RecordHeader::parse(&input);
            let _ = parse_frames(&input, RecordKind::Data);
            let _ = parse_frames(&input, RecordKind::Control);
        }
    }

    #[test]
    fn matches_application_conformance_vector() {
        let vector: ApplicationVector =
            serde_json::from_str(include_str!("../tests/vectors/application.json")).unwrap();
        let secret: [u8; 32] = URL_SAFE_NO_PAD
            .decode(vector.epoch_secret_b64)
            .unwrap()
            .try_into()
            .unwrap();
        let session: [u8; 16] = URL_SAFE_NO_PAD
            .decode(vector.session_id_b64)
            .unwrap()
            .try_into()
            .unwrap();
        let keys = EpochKeys::derive(secret, session, vector.epoch).unwrap();
        assert_eq!(
            keys.c2s_data.key.as_slice(),
            URL_SAFE_NO_PAD.decode(vector.data_c2s_key_b64).unwrap()
        );
        assert_eq!(
            keys.c2s_data.iv.as_slice(),
            URL_SAFE_NO_PAD.decode(vector.data_c2s_iv_b64).unwrap()
        );
        assert_eq!(
            keys.s2c_control.key.as_slice(),
            URL_SAFE_NO_PAD.decode(vector.control_s2c_key_b64).unwrap()
        );
        assert_eq!(
            keys.s2c_control.iv.as_slice(),
            URL_SAFE_NO_PAD.decode(vector.control_s2c_iv_b64).unwrap()
        );
        assert_eq!(
            nonce(&keys.c2s_data.iv, vector.packet_number).as_slice(),
            URL_SAFE_NO_PAD.decode(vector.nonce_b64).unwrap()
        );
    }
}
