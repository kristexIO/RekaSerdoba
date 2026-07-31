use std::{
    fmt::Debug,
    net::SocketAddr,
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::time::{MissedTickBehavior, interval};
use wtransport::{
    ClientConfig, Endpoint,
    config::{DnsLookupFuture, DnsResolver},
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize)]
struct Bundle {
    client_id_b64: String,
    gate_key_b64: String,
}

#[derive(Debug)]
struct PinnedDnsResolver(SocketAddr);

impl DnsResolver for PinnedDnsResolver {
    fn resolve(&self, _host: &str) -> Pin<Box<dyn DnsLookupFuture>> {
        let address = self.0;
        Box::pin(async move { Ok(Some(address)) })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let bundle_path = args.next().context("missing bundle path")?;
    let url = args.next().context("missing WebTransport URL")?;
    let authority = args.next().context("missing authority")?;
    let path = args.next().context("missing path")?;
    let server_address: SocketAddr = args
        .next()
        .context("missing server address")?
        .parse()
        .context("invalid server address")?;
    if args.next().is_some() {
        bail!("unexpected argument");
    }
    let bundle: Bundle = serde_json::from_slice(&std::fs::read(bundle_path)?)?;
    let client_id = decode_fixed::<16>(&bundle.client_id_b64)?;
    let gate_key = decode_fixed::<32>(&bundle.gate_key_b64)?;
    let config = ClientConfig::builder()
        .with_bind_default()
        .with_native_certs()
        .max_idle_timeout(Some(Duration::from_secs(120)))?
        .keep_alive_interval(Some(Duration::from_secs(5)))
        .dns_resolver(PinnedDnsResolver(server_address))
        .build();
    let endpoint = Endpoint::client(config)?;
    let connection = endpoint.connect(url).await?;
    let exporter_context = hash_parts(&[authority.as_bytes(), &[0], path.as_bytes()]);
    let mut exporter = [0u8; 32];
    connection
        .export_keying_material(
            &mut exporter,
            b"EXPORTER-RekaSerdoba-gate",
            &exporter_context,
        )
        .map_err(|_| anyhow!("TLS exporter unavailable"))?;
    let token = gate_token(&client_id, &gate_key, &exporter, &authority, &path)?;
    let (mut send, mut recv) = connection.open_bi().await?.await?;
    send_stream_message(&mut send, token.as_bytes()).await?;

    let mut input = tokio::io::stdin();
    let mut output = BufWriter::with_capacity(256 * 1024, tokio::io::stdout());
    let mut output_flush = interval(Duration::from_millis(2));
    output_flush.set_missed_tick_behavior(MissedTickBehavior::Skip);
    output_flush.tick().await;
    let mut output_dirty = false;
    let mut local_buffered = Vec::new();
    let mut buffered = Vec::new();
    loop {
        let datagram_connection = connection.clone();
        tokio::select! {
            _ = output_flush.tick() => {
                if output_dirty {
                    output.flush().await?;
                    output_dirty = false;
                }
            }
            local = read_local_message(&mut input, &mut local_buffered) => {
                let Some(payload) = local? else {
                    break;
                };
                send_stream_message(&mut send, &payload).await?;
            }
            reliable = recv_stream_message(&mut recv, &mut buffered) => {
                match reliable {
                    Ok(Some(payload)) => {
                        write_local_message(&mut output, &payload).await?;
                        output_dirty = true;
                    }
                    Ok(None) | Err(_) => break,
                };
            }
            datagram = datagram_connection.receive_datagram() => {
                match datagram {
                    Ok(payload) => {
                        write_local_message(&mut output, &payload).await?;
                        output_dirty = true;
                    }
                    Err(_) => break,
                }
            }
        }
    }
    if output_dirty {
        output.flush().await?;
    }
    let _ = send.finish().await;
    Ok(())
}

fn gate_token(
    client_id: &[u8; 16],
    gate_key: &[u8; 32],
    exporter: &[u8; 32],
    authority: &str,
    path: &str,
) -> Result<String> {
    let unix_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let mut message = Vec::with_capacity(192);
    message.extend_from_slice(b"RekaSerdoba/1 gate");
    message.extend_from_slice(exporter);
    message.extend_from_slice(b"CONNECT");
    message.push(0);
    message.extend_from_slice(authority.as_bytes());
    message.push(0);
    message.extend_from_slice(path.as_bytes());
    message.push(0);
    message.extend_from_slice(client_id);
    message.extend_from_slice(&unix_time.to_be_bytes());
    message.extend_from_slice(&nonce);
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(gate_key)?;
    mac.update(&message);
    let mut token = Vec::with_capacity(72);
    token.extend_from_slice(client_id);
    token.extend_from_slice(&unix_time.to_be_bytes());
    token.extend_from_slice(&nonce);
    token.extend_from_slice(&mac.finalize().into_bytes());
    Ok(URL_SAFE_NO_PAD.encode(token))
}

async fn read_local_message<R: AsyncRead + Unpin>(
    input: &mut R,
    buffered: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    loop {
        if let Some(message) = take_local_message(buffered)? {
            return Ok(Some(message));
        }
        let mut chunk = [0u8; 8192];
        match input.read(&mut chunk).await? {
            0 if buffered.is_empty() => return Ok(None),
            0 => bail!("truncated local message"),
            length => buffered.extend_from_slice(&chunk[..length]),
        }
    }
}

fn take_local_message(buffered: &mut Vec<u8>) -> Result<Option<Vec<u8>>> {
    if buffered.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(buffered[..4].try_into()?) as usize;
    if length == 0 || length > 8192 {
        bail!("invalid local message length");
    }
    if buffered.len() < 4 + length {
        return Ok(None);
    }
    let message = buffered[4..4 + length].to_vec();
    buffered.drain(..4 + length);
    Ok(Some(message))
}

async fn write_local_message<W: AsyncWrite + Unpin>(output: &mut W, payload: &[u8]) -> Result<()> {
    output
        .write_all(&u32::try_from(payload.len())?.to_be_bytes())
        .await?;
    output.write_all(payload).await?;
    Ok(())
}

async fn send_stream_message(
    stream: &mut wtransport::stream::SendStream,
    payload: &[u8],
) -> Result<()> {
    stream
        .write_all(&u32::try_from(payload.len())?.to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn recv_stream_message(
    stream: &mut wtransport::stream::RecvStream,
    buffered: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>> {
    loop {
        if buffered.len() >= 4 {
            let length = u32::from_be_bytes(buffered[..4].try_into()?) as usize;
            if length == 0 || length > 8192 {
                bail!("invalid WebTransport message length");
            }
            if buffered.len() >= 4 + length {
                let message = buffered[4..4 + length].to_vec();
                buffered.drain(..4 + length);
                return Ok(Some(message));
            }
        }
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk).await? {
            Some(0) | None if buffered.is_empty() => return Ok(None),
            Some(0) | None => bail!("truncated WebTransport message"),
            Some(length) => buffered.extend_from_slice(&chunk[..length]),
        }
    }
}

fn decode_fixed<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(encoded)?
        .try_into()
        .map_err(|_| anyhow!("invalid key length"))
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::take_local_message;

    #[test]
    fn local_frame_survives_partial_reads() {
        let mut buffered = vec![0, 0];
        assert!(take_local_message(&mut buffered).unwrap().is_none());
        buffered.extend_from_slice(&[0, 3, b'a']);
        assert!(take_local_message(&mut buffered).unwrap().is_none());
        buffered.extend_from_slice(b"bc");
        assert_eq!(
            take_local_message(&mut buffered).unwrap(),
            Some(b"abc".to_vec())
        );
        assert!(buffered.is_empty());
    }
}
