use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::record::{
    DEFAULT_REPLAY_WINDOW, EpochKeys, Frame, RecordHeader, RecordKind, SessionRecordLayer,
};

type HmacSha256 = Hmac<Sha256>;

const UPDATE_INTERVAL: Duration = Duration::from_secs(600);
const UPDATE_RECORD_LIMIT: u64 = 1 << 20;
const UPDATE_BYTE_LIMIT: u64 = 1 << 30;
const UPDATE_TIMEOUT: Duration = Duration::from_secs(10);
const OLD_EPOCH_GRACE: Duration = Duration::from_secs(3);
const OLD_EPOCH_RECORDS: u16 = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochPosition {
    Current,
    Pending,
    Previous,
}

pub struct OpenedRecord {
    pub header: RecordHeader,
    pub plaintext: Vec<u8>,
    pub position: EpochPosition,
}

struct EpochState {
    epoch: u32,
    secret: Zeroizing<[u8; 32]>,
    records: SessionRecordLayer,
}

struct PendingEpoch {
    state: EpochState,
    proof: PendingProof,
}

enum PendingProof {
    Routine {
        context: [u8; 32],
        confirm_key: Zeroizing<[u8; 32]>,
    },
    Full {
        context: [u8; 32],
        confirm_key: Zeroizing<[u8; 32]>,
    },
}

struct PreviousEpoch {
    state: EpochState,
    expires_at: Instant,
    remaining_records: u16,
}

pub struct RekeySession {
    session_id: [u8; 16],
    transcript: [u8; 32],
    current: EpochState,
    pending: Option<PendingEpoch>,
    previous: Option<PreviousEpoch>,
    epoch_started: Instant,
    data_records: u64,
    plaintext_bytes: u64,
    update_requested: bool,
    update_deadline: Option<Instant>,
}

impl RekeySession {
    pub fn new(
        session_id: [u8; 16],
        epoch_secret: Zeroizing<[u8; 32]>,
        keys: EpochKeys,
        handshake_transcript: [u8; 32],
        now: Instant,
    ) -> Result<Self> {
        let transcript = hash_parts(&[
            b"RekaSerdoba/1 control transcript",
            &handshake_transcript,
            &session_id,
        ]);
        Ok(Self {
            session_id,
            transcript,
            current: EpochState {
                epoch: 0,
                secret: epoch_secret,
                records: SessionRecordLayer::new(session_id, 0, keys, DEFAULT_REPLAY_WINDOW)?,
            },
            pending: None,
            previous: None,
            epoch_started: now,
            data_records: 0,
            plaintext_bytes: 0,
            update_requested: false,
            update_deadline: None,
        })
    }

    pub fn seal_data(&mut self, plaintext: &[u8], padded: bool) -> Result<Vec<u8>> {
        self.count_data(plaintext.len())?;
        self.current.records.s2c_data.seal(plaintext, padded)
    }

    pub fn seal_control(&self, plaintext: &[u8], padded: bool) -> Result<Vec<u8>> {
        self.current.records.s2c_control.seal(plaintext, padded)
    }

    pub fn open(&mut self, encoded: &[u8], now: Instant) -> Result<OpenedRecord> {
        self.expire_previous(now);
        let header = RecordHeader::parse(encoded)?;
        let position = if header.epoch == self.current.epoch {
            let plaintext = open_from(&mut self.current, header.kind, encoded)?;
            if header.kind == RecordKind::Data {
                self.count_data(plaintext.len())?;
            }
            return Ok(OpenedRecord {
                header,
                plaintext,
                position: EpochPosition::Current,
            });
        } else if self
            .pending
            .as_ref()
            .is_some_and(|pending| header.epoch == pending.state.epoch)
        {
            if header.kind != RecordKind::Control {
                bail!("pending epoch accepts only control records");
            }
            let pending = self.pending.as_mut().expect("pending epoch exists");
            let plaintext = open_from(&mut pending.state, header.kind, encoded)?;
            (EpochPosition::Pending, plaintext)
        } else if self
            .previous
            .as_ref()
            .is_some_and(|previous| header.epoch == previous.state.epoch)
        {
            let previous = self.previous.as_mut().expect("previous epoch exists");
            if previous.remaining_records == 0 || now >= previous.expires_at {
                bail!("previous epoch grace expired");
            }
            let plaintext = open_from(&mut previous.state, header.kind, encoded)?;
            previous.remaining_records -= 1;
            (EpochPosition::Previous, plaintext)
        } else {
            bail!("unknown record epoch");
        };
        Ok(OpenedRecord {
            header,
            plaintext: position.1,
            position: position.0,
        })
    }

    pub fn accept_update_init(
        &mut self,
        encoded: &[u8],
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>> {
        if body.len() != 72 || self.pending.is_some() {
            bail!("invalid or concurrent key update");
        }
        let current_epoch = u32::from_be_bytes(body[0..4].try_into()?);
        let next_epoch = u32::from_be_bytes(body[4..8].try_into()?);
        let update_nonce: [u8; 32] = body[8..40].try_into()?;
        let received_tag: [u8; 32] = body[40..72].try_into()?;
        if current_epoch != self.current.epoch
            || next_epoch
                != current_epoch
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("epoch overflow"))?
        {
            bail!("invalid key update epoch");
        }
        let update_input = update_input(
            self.session_id,
            current_epoch,
            next_epoch,
            update_nonce,
            self.transcript,
        );
        let expected_tag = hmac_bytes(&*self.current.secret, &update_input)?;
        if received_tag.ct_eq(&expected_tag).unwrap_u8() != 1 {
            bail!("invalid key update transcript tag");
        }
        let update_context: [u8; 32] = Sha256::digest(&update_input).into();
        let next_secret = hmac_bytes(&*self.current.secret, &update_context)?;
        let keys = EpochKeys::derive(next_secret, self.session_id, next_epoch)?;
        let confirm_key = confirmation_key(next_secret, self.session_id, next_epoch)?;
        self.transcript = transcript_next(self.transcript, encoded);
        let ack = hmac_label(&confirm_key, b"server ack", &update_context)?;
        let mut ack_body = Vec::with_capacity(36);
        ack_body.extend_from_slice(&next_epoch.to_be_bytes());
        ack_body.extend_from_slice(&ack);
        let ack_record = self.current.records.s2c_control.seal(
            &Frame {
                frame_type: 0x06,
                flags: 0,
                body: ack_body,
            }
            .encode()?,
            false,
        )?;
        self.transcript = transcript_next(self.transcript, &ack_record);
        self.pending = Some(PendingEpoch {
            state: EpochState {
                epoch: next_epoch,
                secret: Zeroizing::new(next_secret),
                records: SessionRecordLayer::new(
                    self.session_id,
                    next_epoch,
                    keys,
                    DEFAULT_REPLAY_WINDOW,
                )?,
            },
            proof: PendingProof::Routine {
                context: update_context,
                confirm_key: Zeroizing::new(confirm_key),
            },
        });
        self.update_requested = true;
        self.update_deadline = Some(now + UPDATE_TIMEOUT);
        self.expire_previous(now);
        Ok(ack_record)
    }

    pub fn accept_update_commit(
        &mut self,
        encoded: &[u8],
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>> {
        if body.len() != 36 {
            bail!("invalid key update commit");
        }
        let next_epoch = u32::from_be_bytes(body[0..4].try_into()?);
        let received_tag: [u8; 32] = body[4..36].try_into()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| anyhow!("key update is not pending"))?;
        if next_epoch != pending.state.epoch {
            bail!("key update commit epoch mismatch");
        }
        let PendingProof::Routine {
            context,
            confirm_key,
        } = &pending.proof
        else {
            bail!("routine key update is not pending");
        };
        let expected = hmac_label(&**confirm_key, b"client commit", context)?;
        if received_tag.ct_eq(&expected).unwrap_u8() != 1 {
            bail!("invalid key update commit tag");
        }
        self.transcript = transcript_next(self.transcript, encoded);
        let pending = self.pending.take().expect("pending epoch exists");
        let PendingProof::Routine {
            context,
            confirm_key,
        } = &pending.proof
        else {
            unreachable!();
        };
        let done = hmac_label(&**confirm_key, b"server done", context)?;
        let old = std::mem::replace(&mut self.current, pending.state);
        self.previous = Some(PreviousEpoch {
            state: old,
            expires_at: now + OLD_EPOCH_GRACE,
            remaining_records: OLD_EPOCH_RECORDS,
        });
        let mut done_body = Vec::with_capacity(36);
        done_body.extend_from_slice(&next_epoch.to_be_bytes());
        done_body.extend_from_slice(&done);
        let done_record = self.current.records.s2c_control.seal(
            &Frame {
                frame_type: 0x08,
                flags: 0,
                body: done_body,
            }
            .encode()?,
            false,
        )?;
        self.transcript = transcript_next(self.transcript, &done_record);
        self.epoch_started = now;
        self.data_records = 0;
        self.plaintext_bytes = 0;
        self.update_requested = false;
        self.update_deadline = None;
        Ok(done_record)
    }

    pub fn accept_full_rekey_init(
        &mut self,
        encoded: &[u8],
        body: &[u8],
        client_key: &VerifyingKey,
        server_key: &SigningKey,
        now: Instant,
    ) -> Result<Vec<u8>> {
        if body.len() != 120 || self.pending.is_some() {
            bail!("invalid or concurrent full rekey");
        }
        let current_epoch = u32::from_be_bytes(body[0..4].try_into()?);
        let target_epoch = u32::from_be_bytes(body[4..8].try_into()?);
        let rekey_id: [u8; 16] = body[8..24].try_into()?;
        let client_ephemeral: [u8; 32] = body[24..56].try_into()?;
        let client_signature: [u8; 64] = body[56..120].try_into()?;
        if current_epoch != self.current.epoch
            || target_epoch
                != current_epoch
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("epoch overflow"))?
        {
            bail!("invalid full rekey epoch");
        }
        let client_input = hash_parts(&[
            b"RekaSerdoba/1 full rekey client",
            &self.session_id,
            &current_epoch.to_be_bytes(),
            &target_epoch.to_be_bytes(),
            &rekey_id,
            &client_ephemeral,
            &self.transcript,
        ]);
        client_key
            .verify(&client_input, &Signature::from_bytes(&client_signature))
            .map_err(|_| anyhow!("invalid full rekey client signature"))?;
        self.transcript = transcript_next(self.transcript, encoded);
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_ephemeral = X25519PublicKey::from(&server_secret);
        let server_input = hash_parts(&[
            b"RekaSerdoba/1 full rekey server",
            &self.session_id,
            &current_epoch.to_be_bytes(),
            &target_epoch.to_be_bytes(),
            &rekey_id,
            &client_ephemeral,
            server_ephemeral.as_bytes(),
            &self.transcript,
        ]);
        let server_signature = server_key.sign(&server_input).to_bytes();
        let mut reply_body = Vec::with_capacity(120);
        reply_body.extend_from_slice(&current_epoch.to_be_bytes());
        reply_body.extend_from_slice(&target_epoch.to_be_bytes());
        reply_body.extend_from_slice(&rekey_id);
        reply_body.extend_from_slice(server_ephemeral.as_bytes());
        reply_body.extend_from_slice(&server_signature);
        let reply = self.current.records.s2c_control.seal(
            &Frame {
                frame_type: 0x0A,
                flags: 0,
                body: reply_body,
            }
            .encode()?,
            false,
        )?;
        self.transcript = transcript_next(self.transcript, &reply);
        let shared = server_secret.diffie_hellman(&X25519PublicKey::from(client_ephemeral));
        if shared.as_bytes().ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            bail!("all-zero full rekey shared secret");
        }
        let context = hash_parts(&[
            b"RekaSerdoba/1 full rekey",
            &self.session_id,
            &current_epoch.to_be_bytes(),
            &target_epoch.to_be_bytes(),
            &rekey_id,
            &client_ephemeral,
            server_ephemeral.as_bytes(),
            &client_signature,
            &server_signature,
            &self.transcript,
        ]);
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(shared.as_bytes());
        ikm.extend_from_slice(&context);
        let next_secret = hmac_bytes(&*self.current.secret, &ikm)?;
        let keys = EpochKeys::derive(next_secret, self.session_id, target_epoch)?;
        let kdf =
            Hkdf::<Sha256>::from_prk(&next_secret).map_err(|_| anyhow!("invalid epoch secret"))?;
        let confirm_key = fixed(expand_label(&kdf, "full rekey confirm", &context, 32)?)?;
        self.pending = Some(PendingEpoch {
            state: EpochState {
                epoch: target_epoch,
                secret: Zeroizing::new(next_secret),
                records: SessionRecordLayer::new(
                    self.session_id,
                    target_epoch,
                    keys,
                    DEFAULT_REPLAY_WINDOW,
                )?,
            },
            proof: PendingProof::Full {
                context,
                confirm_key: Zeroizing::new(confirm_key),
            },
        });
        self.update_requested = true;
        self.update_deadline = Some(now + UPDATE_TIMEOUT);
        Ok(reply)
    }

    pub fn accept_full_rekey_confirm(
        &mut self,
        encoded: &[u8],
        body: &[u8],
        now: Instant,
    ) -> Result<Vec<u8>> {
        if body.len() != 36 {
            bail!("invalid full rekey confirmation");
        }
        let target_epoch = u32::from_be_bytes(body[0..4].try_into()?);
        let received: [u8; 32] = body[4..36].try_into()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| anyhow!("full rekey is not pending"))?;
        if target_epoch != pending.state.epoch {
            bail!("full rekey confirmation epoch mismatch");
        }
        let PendingProof::Full {
            context,
            confirm_key,
        } = &pending.proof
        else {
            bail!("full rekey is not pending");
        };
        let expected = hmac_label(&**confirm_key, b"client confirm", context)?;
        if received.ct_eq(&expected).unwrap_u8() != 1 {
            bail!("invalid full rekey confirmation tag");
        }
        self.transcript = transcript_next(self.transcript, encoded);
        let pending = self.pending.take().expect("pending epoch exists");
        let PendingProof::Full {
            context,
            confirm_key,
        } = &pending.proof
        else {
            unreachable!();
        };
        let done = hmac_label(&**confirm_key, b"server done", context)?;
        let old = std::mem::replace(&mut self.current, pending.state);
        self.previous = Some(PreviousEpoch {
            state: old,
            expires_at: now + OLD_EPOCH_GRACE,
            remaining_records: OLD_EPOCH_RECORDS,
        });
        let mut done_body = target_epoch.to_be_bytes().to_vec();
        done_body.extend_from_slice(&done);
        let done_record = self.current.records.s2c_control.seal(
            &Frame {
                frame_type: 0x08,
                flags: 0,
                body: done_body,
            }
            .encode()?,
            false,
        )?;
        self.transcript = transcript_next(self.transcript, &done_record);
        self.epoch_started = now;
        self.data_records = 0;
        self.plaintext_bytes = 0;
        self.update_requested = false;
        self.update_deadline = None;
        Ok(done_record)
    }

    pub fn request_update_if_due(&mut self, now: Instant) -> Result<Option<Vec<u8>>> {
        if self.update_deadline.is_some_and(|deadline| now >= deadline) {
            bail!("key update timed out");
        }
        if self.pending.is_some() || self.update_requested {
            return Ok(None);
        }
        if now < self.epoch_started + UPDATE_INTERVAL
            && self.data_records < UPDATE_RECORD_LIMIT
            && self.plaintext_bytes < UPDATE_BYTE_LIMIT
        {
            return Ok(None);
        }
        let record = self.current.records.s2c_control.seal(
            &Frame {
                frame_type: 0x04,
                flags: 0,
                body: self.current.epoch.to_be_bytes().to_vec(),
            }
            .encode()?,
            false,
        )?;
        self.transcript = transcript_next(self.transcript, &record);
        self.update_requested = true;
        self.update_deadline = Some(now + UPDATE_TIMEOUT);
        Ok(Some(record))
    }

    pub fn path_challenge(
        &mut self,
        migration_secret: &[u8; 32],
        carrier_id: [u8; 16],
        challenge: [u8; 32],
    ) -> Result<(Vec<u8>, [u8; 32])> {
        if self.pending.is_some() {
            bail!("migration during rekey is not allowed");
        }
        let mut body = Vec::with_capacity(48);
        body.extend_from_slice(&carrier_id);
        body.extend_from_slice(&challenge);
        let record = self.current.records.s2c_control.seal(
            &Frame {
                frame_type: 0x0C,
                flags: 0,
                body,
            }
            .encode()?,
            false,
        )?;
        self.transcript = transcript_next(self.transcript, &record);
        let mut proof = Vec::with_capacity(128);
        proof.extend_from_slice(b"RekaSerdoba/1 path response");
        proof.extend_from_slice(&self.session_id);
        proof.extend_from_slice(&carrier_id);
        proof.extend_from_slice(&challenge);
        proof.extend_from_slice(&self.transcript);
        let expected = hmac_bytes(migration_secret, &proof)?;
        Ok((record, expected))
    }

    pub fn accept_path_response(
        &mut self,
        encoded: &[u8],
        body: &[u8],
        carrier_id: [u8; 16],
        expected: [u8; 32],
    ) -> Result<()> {
        if body.len() != 48
            || body[..16].ct_eq(&carrier_id).unwrap_u8() != 1
            || body[16..].ct_eq(&expected).unwrap_u8() != 1
        {
            bail!("invalid migration path response");
        }
        self.transcript = transcript_next(self.transcript, encoded);
        Ok(())
    }

    pub fn next_update_check(&self, now: Instant) -> Instant {
        if let Some(deadline) = self.update_deadline {
            deadline
        } else if self.pending.is_some() || self.update_requested {
            now + UPDATE_TIMEOUT
        } else {
            self.epoch_started + UPDATE_INTERVAL
        }
    }

    fn count_data(&mut self, plaintext_len: usize) -> Result<()> {
        self.data_records = self
            .data_records
            .checked_add(1)
            .ok_or_else(|| anyhow!("data record counter overflow"))?;
        self.plaintext_bytes = self
            .plaintext_bytes
            .checked_add(u64::try_from(plaintext_len)?)
            .ok_or_else(|| anyhow!("plaintext byte counter overflow"))?;
        Ok(())
    }

    fn expire_previous(&mut self, now: Instant) {
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| previous.remaining_records == 0 || now >= previous.expires_at)
        {
            self.previous = None;
        }
    }
}

fn open_from(state: &mut EpochState, kind: RecordKind, encoded: &[u8]) -> Result<Vec<u8>> {
    match kind {
        RecordKind::Data => state.records.c2s_data.open(encoded),
        RecordKind::Control => state.records.c2s_control.open(encoded),
    }
}

fn update_input(
    session_id: [u8; 16],
    current_epoch: u32,
    next_epoch: u32,
    nonce: [u8; 32],
    transcript: [u8; 32],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(113);
    input.extend_from_slice(b"RekaSerdoba/1 epoch update");
    input.extend_from_slice(&session_id);
    input.extend_from_slice(&current_epoch.to_be_bytes());
    input.extend_from_slice(&next_epoch.to_be_bytes());
    input.extend_from_slice(&nonce);
    input.extend_from_slice(&transcript);
    input
}

fn confirmation_key(secret: [u8; 32], session_id: [u8; 16], epoch: u32) -> Result<[u8; 32]> {
    let kdf = Hkdf::<Sha256>::from_prk(&secret).map_err(|_| anyhow!("invalid epoch secret"))?;
    let mut context = Vec::with_capacity(20);
    context.extend_from_slice(&session_id);
    context.extend_from_slice(&epoch.to_be_bytes());
    fixed(expand_label(&kdf, "epoch confirmation", &context, 32)?)
}

fn hmac_label(key: &[u8], label: &[u8], context: &[u8]) -> Result<[u8; 32]> {
    let mut input = Vec::with_capacity(label.len() + context.len());
    input.extend_from_slice(label);
    input.extend_from_slice(context);
    hmac_bytes(key, &input)
}

fn hmac_bytes(key: &[u8], message: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key)
        .map_err(|_| anyhow!("invalid HMAC key"))?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn transcript_next(previous: [u8; 32], record: &[u8]) -> [u8; 32] {
    hash_parts(&[&previous, record])
}

fn expand_label(kdf: &Hkdf<Sha256>, label: &str, context: &[u8], length: usize) -> Result<Vec<u8>> {
    let full_label = format!("RekaSerdoba/1 {label}");
    let mut info = Vec::with_capacity(5 + full_label.len() + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(u8::try_from(full_label.len())?);
    info.extend_from_slice(full_label.as_bytes());
    info.extend_from_slice(&u16::try_from(context.len())?.to_be_bytes());
    info.extend_from_slice(context);
    let mut output = vec![0u8; length];
    kdf.expand(&info, &mut output)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(output)
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N]> {
    value
        .try_into()
        .map_err(|_| anyhow!("invalid fixed-size value"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{RecordReceiver, RecordSender};

    #[test]
    fn completes_routine_key_update() {
        let session_id = [7u8; 16];
        let secret = [9u8; 32];
        let t5 = [3u8; 32];
        let now = Instant::now();
        let server_keys = EpochKeys::derive(secret, session_id, 0).unwrap();
        let client_keys = EpochKeys::derive(secret, session_id, 0).unwrap();
        let client_control =
            RecordSender::new(RecordKind::Control, session_id, 0, client_keys.c2s_control);
        let mut server =
            RekeySession::new(session_id, Zeroizing::new(secret), server_keys, t5, now).unwrap();
        let nonce = [5u8; 32];
        let input = update_input(session_id, 0, 1, nonce, server.transcript);
        let tag = hmac_bytes(&secret, &input).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&nonce);
        body.extend_from_slice(&tag);
        let init = client_control
            .seal(
                &Frame {
                    frame_type: 0x05,
                    flags: 0,
                    body: body.clone(),
                }
                .encode()
                .unwrap(),
                false,
            )
            .unwrap();
        let opened = server.open(&init, now).unwrap();
        assert_eq!(opened.position, EpochPosition::Current);
        let ack = server.accept_update_init(&init, &body, now).unwrap();
        let next_secret = hmac_bytes(&secret, &Sha256::digest(&input)).unwrap();
        let next_keys = EpochKeys::derive(next_secret, session_id, 1).unwrap();
        let confirm = confirmation_key(next_secret, session_id, 1).unwrap();
        let commit_tag = hmac_label(&confirm, b"client commit", &Sha256::digest(&input)).unwrap();
        let mut commit_body = 1u32.to_be_bytes().to_vec();
        commit_body.extend_from_slice(&commit_tag);
        let client_next_control =
            RecordSender::new(RecordKind::Control, session_id, 1, next_keys.c2s_control);
        let commit = client_next_control
            .seal(
                &Frame {
                    frame_type: 0x07,
                    flags: 0,
                    body: commit_body.clone(),
                }
                .encode()
                .unwrap(),
                false,
            )
            .unwrap();
        let opened = server.open(&commit, now).unwrap();
        assert_eq!(opened.position, EpochPosition::Pending);
        let done = server
            .accept_update_commit(&commit, &commit_body, now)
            .unwrap();
        let client_server_keys = EpochKeys::derive(next_secret, session_id, 1).unwrap();
        let mut receiver = RecordReceiver::new(
            RecordKind::Control,
            session_id,
            1,
            client_server_keys.s2c_control,
            DEFAULT_REPLAY_WINDOW,
        )
        .unwrap();
        assert_eq!(receiver.open(&done).unwrap()[0], 0x08);
        assert_eq!(ack[17..21], 0u32.to_be_bytes());
    }

    #[test]
    fn rejects_stalled_key_update() {
        let session_id = [7u8; 16];
        let secret = [9u8; 32];
        let now = Instant::now();
        let keys = EpochKeys::derive(secret, session_id, 0).unwrap();
        let mut session =
            RekeySession::new(session_id, Zeroizing::new(secret), keys, [3u8; 32], now).unwrap();
        assert!(
            session
                .request_update_if_due(now + UPDATE_INTERVAL)
                .unwrap()
                .is_some()
        );
        assert!(
            session
                .request_update_if_due(now + UPDATE_INTERVAL + UPDATE_TIMEOUT)
                .is_err()
        );
    }
}
