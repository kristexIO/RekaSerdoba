use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Router,
    body::{Body, BodyDataStream, Bytes},
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{Message, WebSocket, rejection::WebSocketUpgradeRejection},
    },
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::BytesMut;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tracing::{info, warn};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

mod h3_edge;
mod network;

use network::{Network, TunSettings};
use rekaserdoba_server::{
    fragment::FragmentReassembler,
    record::{ApplicationSecrets, Frame, RecordKind, parse_frames},
    rekey::{EpochPosition, RekeySession},
    session::SessionPolicy,
};

type HmacSha256 = Hmac<Sha256>;
type GateReplayKey = ([u8; 16], [u8; 16]);
type GateReplayCache = HashMap<GateReplayKey, Instant>;
type AdmissionRate = HashMap<IpAddr, VecDeque<Instant>>;
type MigrationRegistry = HashMap<[u8; 16], Arc<MigrationEntry>>;
type MigrationReplayCache = HashMap<[u8; 16], Instant>;

const PROTOCOL_VERSION: u16 = 1;
const CIPHER_SUITE: u16 = 1;
const MAX_CLEAR_HANDSHAKE: usize = 1536;
const MAX_ENCRYPTED_HANDSHAKE: usize = 4096 + 16;
const MAX_CARRIER_MESSAGE: usize = MAX_ENCRYPTED_HANDSHAKE + 256;
const GATE_WINDOW_SECS: i64 = 90;
const GATE_REPLAY_SECS: u64 = 180;
const H2_PATH: &str = "/connect/v1/h2";
const H3_EXPORTER_LABEL: &[u8] = b"EXPORTER-RekaSerdoba-gate";
const BUILD_SHA: &str = env!("REKASERDOBA_BUILD_SHA");
const MAX_ACTIVE_CARRIERS: usize = 1024;
const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);
const H3_DATAGRAM_FRAGMENT_SIZE: usize = 900;

const DECOY_HTML: &str = r#"<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Река Сердоба — краеведческий архив</title>
  <style>
    :root{color-scheme:light;background:#f4f0e7;color:#20332c;font:18px/1.55 Georgia,serif}
    body{margin:0}.wrap{max-width:760px;margin:auto;padding:10vh 24px}
    h1{font-size:clamp(2.4rem,8vw,5rem);line-height:.95;margin:0 0 1.5rem;color:#174c3a}
    p{max-width:62ch}.rule{width:72px;border-top:3px solid #bd6b3a;margin:2rem 0}
    small{color:#61736b}
  </style>
</head>
<body><main class="wrap">
  <h1>Река<br>Сердоба</h1><div class="rule"></div>
  <p>Небольшой краеведческий архив о реке Сердобе, её берегах, поселениях и сезонных изменениях.</p>
  <p><small>Архив пополняется. Материалы проходят редакционную обработку.</small></p>
</main></body></html>"#;

#[derive(Clone, Deserialize)]
struct Config {
    listen: String,
    authority: String,
    tunnel_path: String,
    server_signing_seed_b64: String,
    tun: TunSettings,
    clients: Vec<ClientConfig>,
    #[serde(default)]
    h3: Option<H3Config>,
}

#[derive(Clone, Deserialize)]
struct H3Config {
    listen: String,
    authority: String,
    path: String,
    certificate_pem: String,
    private_key_pem: String,
    #[serde(default = "default_h3_decoy_root")]
    decoy_root: String,
}

fn default_h3_decoy_root() -> String {
    "/var/www/rekaserdoba".to_owned()
}

#[derive(Clone, Deserialize)]
struct ClientConfig {
    client_id_b64: String,
    client_public_key_b64: String,
    gate_key_b64: String,
    tunnel_ipv4: String,
    revoked: bool,
    #[serde(default = "default_session_lifetime")]
    session_lifetime_seconds: u32,
    #[serde(default = "default_bandwidth")]
    bandwidth_bytes_per_second: u64,
    #[serde(default)]
    session_quota_bytes: u64,
}

#[derive(Clone)]
struct Client {
    id: [u8; 16],
    public_key: VerifyingKey,
    gate_key: [u8; 32],
    tunnel_ipv4: [u8; 4],
    session_lifetime_seconds: u32,
    bandwidth_bytes_per_second: u64,
    session_quota_bytes: u64,
}

fn default_session_lifetime() -> u32 {
    3600
}

fn default_bandwidth() -> u64 {
    25 * 1024 * 1024
}

struct Runtime {
    authority: String,
    tunnel_path: String,
    server_signing: SigningKey,
    server_key_id: [u8; 16],
    clients: HashMap<[u8; 16], Client>,
    gate_replay: Mutex<GateReplayCache>,
    admission_rate: Mutex<AdmissionRate>,
    migrations: Mutex<MigrationRegistry>,
}

#[derive(Clone)]
struct AppState {
    runtime: Arc<Runtime>,
    network: Network,
    metrics: Arc<Metrics>,
    draining: Arc<AtomicBool>,
    h3_ready: Arc<AtomicBool>,
    carriers: Arc<Semaphore>,
}

#[derive(Default)]
struct Metrics {
    gate_rejected: AtomicU64,
    handshake_failed: AtomicU64,
    sessions_total: AtomicU64,
    sessions_active: AtomicU64,
    migrations_total: AtomicU64,
    overloaded_total: AtomicU64,
    disconnects_expected_total: AtomicU64,
    disconnects_error_total: AtomicU64,
    handshake_duration_micros_total: AtomicU64,
    handshake_attempts_total: AtomicU64,
    shaping_delay_micros_total: AtomicU64,
    wss_sessions_total: AtomicU64,
    h2_sessions_total: AtomicU64,
    h3_sessions_total: AtomicU64,
    routine_rekeys_total: AtomicU64,
    full_rekeys_total: AtomicU64,
    rekey_failed_total: AtomicU64,
    migration_failed_total: AtomicU64,
}

struct ActiveSession(Arc<Metrics>);

struct MigrationEntry {
    secret: Arc<Zeroizing<[u8; 32]>>,
    sender: mpsc::Sender<MigrationCandidate>,
    replay: Mutex<MigrationReplayCache>,
}

struct MigrationCandidate {
    carrier: Carrier,
}

enum Admission {
    Handshake(Box<Client>),
    Migration(mpsc::Sender<MigrationCandidate>),
}

struct MigrationRegistration {
    runtime: Arc<Runtime>,
    session_id: [u8; 16],
}

enum Carrier {
    WebSocket(Box<WebSocket>),
    H2(H2Carrier),
    H3(H3Carrier),
}

struct H2Carrier {
    input: BodyDataStream,
    output: mpsc::Sender<Result<Bytes, Infallible>>,
    buffered: BytesMut,
}

struct H3Carrier {
    session: h3_edge::Session,
    buffered: BytesMut,
    application_ready: bool,
}

enum CarrierEvent {
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Close,
    Ignore,
}

fn take_carrier_message(buffered: &mut BytesMut) -> Result<Option<Vec<u8>>> {
    if buffered.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(buffered[..4].try_into()?) as usize;
    if length == 0 || length > MAX_CARRIER_MESSAGE {
        bail!("invalid H2 carrier message length");
    }
    if buffered.len() < 4 + length {
        return Ok(None);
    }
    let encoded = buffered.split_to(4 + length);
    let message = encoded[4..].to_vec();
    Ok(Some(message))
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.0.sessions_active.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for MigrationRegistration {
    fn drop(&mut self) {
        if let Ok(mut migrations) = self.runtime.migrations.lock() {
            migrations.remove(&self.session_id);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let (config_path, check_only) = match arguments.as_slice() {
        [] => ("/etc/rekaserdoba/server.json".to_owned(), false),
        [argument] if argument == "--version" => {
            println!(
                "rekaserdoba-server {} {}",
                env!("CARGO_PKG_VERSION"),
                BUILD_SHA
            );
            return Ok(());
        }
        [argument] if argument == "--check-config" => {
            ("/etc/rekaserdoba/server.json".to_owned(), true)
        }
        [argument] => (argument.clone(), false),
        [argument, path] if argument == "--check-config" => (path.clone(), true),
        _ => bail!("usage: rekaserdoba-server [--version|--check-config [path]|path]"),
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rekaserdoba_server=info".into()),
        )
        .with_target(false)
        .compact()
        .init();

    let raw =
        std::fs::read(&config_path).with_context(|| format!("read configuration {config_path}"))?;
    let cfg: Config = serde_json::from_slice(&raw).context("parse configuration")?;
    let runtime = Arc::new(validate_config(&cfg)?);
    if check_only {
        println!("configuration valid");
        return Ok(());
    }
    let listen: SocketAddr = cfg.listen.parse().context("invalid listen address")?;
    let network = Network::create(&cfg.tun)?;
    let h3_endpoint = match cfg.h3.clone() {
        Some(h3) => Some((build_h3_endpoint(&h3)?, h3)),
        None => None,
    };
    drop_runtime_capabilities()?;
    let (critical_sender, mut critical_receiver) = mpsc::channel::<String>(4);
    let network_task = network.spawn_reader();
    let network_failure = critical_sender.clone();
    tokio::spawn(async move {
        let reason = match network_task.await {
            Ok(()) => "network reader stopped".to_owned(),
            Err(error) => format!("network reader failed: {error}"),
        };
        let _ = network_failure.send(reason).await;
    });
    let h3_ready = Arc::new(AtomicBool::new(h3_endpoint.is_none()));
    let state = AppState {
        runtime,
        network,
        metrics: Arc::new(Metrics::default()),
        draining: Arc::new(AtomicBool::new(false)),
        h3_ready,
        carriers: Arc::new(Semaphore::new(MAX_ACTIVE_CARRIERS)),
    };
    if let Some((endpoint, h3)) = h3_endpoint {
        let h3_state = state.clone();
        let h3_failure = critical_sender.clone();
        tokio::spawn(async move {
            serve_h3_endpoint(endpoint, h3_state, h3).await;
            let _ = h3_failure.send("H3 endpoint stopped".to_owned()).await;
        });
    }
    drop(critical_sender);

    let app = Router::new()
        .route("/", get(decoy))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route(H2_PATH, post(h2_tunnel))
        .fallback(get(maybe_tunnel))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(listen).await?;
    let (shutdown_sender, mut shutdown_receiver) = watch::channel(false);
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        loop {
            if *shutdown_receiver.borrow() {
                return;
            }
            if shutdown_receiver.changed().await.is_err() {
                return;
            }
        }
    })
    .into_future();
    tokio::pin!(server);
    info!(%listen, "RekaSerdoba edge ready");
    let critical_failure = tokio::select! {
        _ = shutdown() => None,
        failure = critical_receiver.recv() => failure,
        result = server.as_mut() => {
            result?;
            return Ok(());
        }
    };
    state.draining.store(true, Ordering::Release);
    state.h3_ready.store(false, Ordering::Release);
    let _ = shutdown_sender.send(true);
    let drain_deadline = Instant::now() + GRACEFUL_DRAIN_TIMEOUT;
    let remaining = drain_deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout(remaining, server.as_mut()).await {
        Ok(result) => result?,
        Err(_) => warn!(
            sessions_active = state.metrics.sessions_active.load(Ordering::Relaxed),
            "graceful drain timed out"
        ),
    }
    while state.metrics.sessions_active.load(Ordering::Acquire) != 0
        && Instant::now() < drain_deadline
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let active = state.metrics.sessions_active.load(Ordering::Relaxed);
    if active != 0 {
        warn!(sessions_active = active, "sessions remained after drain");
    }
    if let Some(failure) = critical_failure {
        bail!("{failure}");
    }
    Ok(())
}

fn drop_runtime_capabilities() -> Result<()> {
    use caps::CapSet;

    caps::clear(None, CapSet::Ambient).context("clear ambient capabilities")?;
    caps::clear(None, CapSet::Effective).context("clear effective capabilities")?;
    caps::clear(None, CapSet::Inheritable).context("clear inheritable capabilities")?;
    caps::clear(None, CapSet::Permitted).context("clear permitted capabilities")?;
    Ok(())
}

fn validate_config(cfg: &Config) -> Result<Runtime> {
    let _: SocketAddr = cfg.listen.parse().context("invalid listen address")?;
    Network::validate_settings(&cfg.tun)?;
    if cfg.clients.len() > 4096 {
        bail!("too many configured clients");
    }
    if let Some(h3) = &cfg.h3 {
        let _: SocketAddr = h3.listen.parse().context("invalid H3 listen address")?;
        if !h3.authority.ends_with(":443") || h3.authority.chars().any(char::is_whitespace) {
            bail!("H3 authority must contain explicit :443 port");
        }
        if !h3.path.starts_with('/') || h3.path.len() > 256 {
            bail!("invalid H3 path");
        }
        for (path, label) in [
            (&h3.certificate_pem, "H3 certificate"),
            (&h3.private_key_pem, "H3 private key"),
        ] {
            let metadata =
                std::fs::metadata(path).with_context(|| format!("read {label} metadata"))?;
            if !metadata.is_file() {
                bail!("{label} is not a regular file");
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(&h3.private_key_pem)?.permissions().mode();
            if mode & 0o027 != 0 {
                bail!("H3 private key permissions are too broad");
            }
        }
        h3_edge::Server::validate(
            Path::new(&h3.certificate_pem),
            Path::new(&h3.private_key_pem),
            Path::new(&h3.decoy_root),
        )?;
    }
    Runtime::from_config(cfg)
}

fn build_h3_endpoint(cfg: &H3Config) -> Result<h3_edge::Server> {
    let listen: SocketAddr = cfg.listen.parse().context("invalid H3 listen address")?;
    if !cfg.path.starts_with('/') {
        bail!("H3 path must start with /");
    }
    h3_edge::Server::bind(
        listen,
        cfg.authority.clone(),
        cfg.path.clone(),
        Path::new(&cfg.certificate_pem),
        Path::new(&cfg.private_key_pem),
        Path::new(&cfg.decoy_root),
    )
}

impl AppState {
    fn is_operational(&self) -> bool {
        !self.draining.load(Ordering::Acquire)
            && self.network.is_ready()
            && self.h3_ready.load(Ordering::Acquire)
    }

    fn is_accepting(&self) -> bool {
        self.is_operational() && self.carriers.available_permits() != 0
    }
}

async fn serve_h3_endpoint(endpoint: h3_edge::Server, state: AppState, cfg: H3Config) {
    state.h3_ready.store(true, Ordering::Release);
    info!(listen = %cfg.listen, "RekaSerdoba H3 edge ready");
    let (sender, mut sessions) = mpsc::channel(128);
    tokio::spawn(endpoint.serve(sender));
    while let Some(session) = sessions.recv().await {
        let connection_state = state.clone();
        let connection_config = cfg.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_h3_session(session, connection_state, connection_config).await
            {
                warn!(reason = %error, "H3 connection closed");
            }
        });
    }
    state.h3_ready.store(false, Ordering::Release);
}

async fn handle_h3_session(
    session: h3_edge::Session,
    state: AppState,
    cfg: H3Config,
) -> Result<()> {
    if !state.is_operational() {
        return Ok(());
    }
    let peer = session.peer();
    if state.runtime.check_admission_rate(peer).is_err() {
        state.metrics.gate_rejected.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    let mut exporter = [0u8; 32];
    let exporter_context = h3_exporter_context(&cfg.authority, &cfg.path);
    session
        .export_keying_material(&mut exporter, H3_EXPORTER_LABEL, &exporter_context)
        .map_err(|_| anyhow!("H3 TLS exporter unavailable"))?;
    let mut carrier = Carrier::H3(H3Carrier {
        session,
        buffered: BytesMut::new(),
        application_ready: false,
    });
    let token = match tokio::time::timeout(Duration::from_secs(10), recv_binary(&mut carrier)).await
    {
        Ok(Ok(token)) => token,
        _ => {
            state.metrics.gate_rejected.fetch_add(1, Ordering::Relaxed);
            carrier.close().await;
            return Ok(());
        }
    };
    let encoded = std::str::from_utf8(&token).context("invalid H3 gate token encoding")?;
    let admission =
        match state
            .runtime
            .validate_h3_gate(encoded, &exporter, &cfg.authority, &cfg.path)
        {
            Ok(client) => Admission::Handshake(Box::new(client)),
            Err(_) => match state.runtime.validate_migration_gate(encoded, &exporter, 1) {
                Ok(sender) => Admission::Migration(sender),
                Err(_) => {
                    state.metrics.gate_rejected.fetch_add(1, Ordering::Relaxed);
                    carrier.close().await;
                    return Ok(());
                }
            },
        };
    match admission {
        Admission::Handshake(client) => serve_session(carrier, state, *client, peer).await,
        Admission::Migration(sender) => submit_migration(carrier, sender).await,
    }
    Ok(())
}

fn h3_exporter_context(authority: &str, path: &str) -> [u8; 32] {
    hash_parts(&[authority.as_bytes(), &[0], path.as_bytes()])
}

impl Runtime {
    fn from_config(cfg: &Config) -> Result<Self> {
        Network::validate_settings(&cfg.tun)?;
        if !cfg.authority.ends_with(":443")
            || cfg.authority.chars().any(char::is_whitespace)
            || cfg.authority.len() > 255
        {
            bail!("authority must contain explicit :443 port");
        }
        if !cfg.tunnel_path.starts_with('/') || cfg.tunnel_path.len() > 256 {
            bail!("tunnel_path must start with /");
        }
        let seed = decode_fixed::<32>(&cfg.server_signing_seed_b64, "server signing seed")?;
        let server_signing = SigningKey::from_bytes(&seed);
        let server_key_id = key_id(
            b"RekaSerdoba server id",
            server_signing.verifying_key().as_bytes(),
        );
        let mut clients = HashMap::new();
        let mut configured_ids = std::collections::HashSet::new();
        let mut tunnel_addresses = std::collections::HashSet::new();
        let server_ip: Ipv4Addr = cfg
            .tun
            .address
            .parse()
            .context("invalid TUN IPv4 address")?;
        let mask = u32::MAX << (32 - cfg.tun.prefix_len);
        let network = u32::from(server_ip) & mask;
        let broadcast = network | !mask;
        for item in &cfg.clients {
            let id = decode_fixed::<16>(&item.client_id_b64, "client id")?;
            if !configured_ids.insert(id) {
                bail!("duplicate client id");
            }
            let public_bytes =
                decode_fixed::<32>(&item.client_public_key_b64, "client public key")?;
            let public_key =
                VerifyingKey::from_bytes(&public_bytes).context("invalid client public key")?;
            let gate_key = decode_fixed::<32>(&item.gate_key_b64, "gate key")?;
            let ip: IpAddr = item.tunnel_ipv4.parse().context("invalid tunnel IPv4")?;
            let IpAddr::V4(ip) = ip else {
                bail!("tunnel_ipv4 must be IPv4")
            };
            let numeric_ip = u32::from(ip);
            if numeric_ip & mask != network
                || numeric_ip == network
                || numeric_ip == broadcast
                || ip == server_ip
            {
                bail!("client tunnel IPv4 is outside the usable TUN subnet");
            }
            SessionPolicy::new(
                item.session_lifetime_seconds,
                item.bandwidth_bytes_per_second,
                item.session_quota_bytes,
                Instant::now(),
            )?;
            if item.revoked {
                continue;
            }
            if !tunnel_addresses.insert(ip) {
                bail!("duplicate active client tunnel IPv4");
            }
            clients.insert(
                id,
                Client {
                    id,
                    public_key,
                    gate_key,
                    tunnel_ipv4: ip.octets(),
                    session_lifetime_seconds: item.session_lifetime_seconds,
                    bandwidth_bytes_per_second: item.bandwidth_bytes_per_second,
                    session_quota_bytes: item.session_quota_bytes,
                },
            );
        }
        Ok(Self {
            authority: cfg.authority.clone(),
            tunnel_path: cfg.tunnel_path.clone(),
            server_signing,
            server_key_id,
            clients,
            gate_replay: Mutex::new(HashMap::new()),
            admission_rate: Mutex::new(HashMap::new()),
            migrations: Mutex::new(HashMap::new()),
        })
    }
}

async fn decoy() -> impl IntoResponse {
    ([("cache-control", "public, max-age=300")], Html(DECOY_HTML))
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let body = format!(
        "rekaserdoba_up 1\nrekaserdoba_build_info{{version=\"{}\",commit=\"{}\"}} 1\nrekaserdoba_gate_rejected_total {}\nrekaserdoba_handshake_failed_total {}\nrekaserdoba_sessions_total {}\nrekaserdoba_sessions_active {}\nrekaserdoba_sessions_by_carrier_total{{carrier=\"wss\"}} {}\nrekaserdoba_sessions_by_carrier_total{{carrier=\"h2\"}} {}\nrekaserdoba_sessions_by_carrier_total{{carrier=\"h3\"}} {}\nrekaserdoba_migrations_total {}\nrekaserdoba_migration_failed_total {}\nrekaserdoba_rekeys_total{{kind=\"routine\"}} {}\nrekaserdoba_rekeys_total{{kind=\"full\"}} {}\nrekaserdoba_rekey_failed_total {}\nrekaserdoba_overloaded_total {}\nrekaserdoba_disconnects_expected_total {}\nrekaserdoba_disconnects_error_total {}\nrekaserdoba_handshake_duration_seconds_sum {:.6}\nrekaserdoba_handshake_duration_seconds_count {}\nrekaserdoba_shaping_delay_seconds_total {:.6}\nrekaserdoba_network_ready {}\nrekaserdoba_h3_ready {}\nrekaserdoba_draining {}\nrekaserdoba_carrier_permits_available {}\nrekaserdoba_network_received_packets_total {}\nrekaserdoba_network_routed_packets_total {}\nrekaserdoba_network_unrouted_packets_total {}\nrekaserdoba_network_invalid_packets_total {}\nrekaserdoba_network_dropped_packets_total {}\n",
        env!("CARGO_PKG_VERSION"),
        BUILD_SHA,
        state.metrics.gate_rejected.load(Ordering::Relaxed),
        state.metrics.handshake_failed.load(Ordering::Relaxed),
        state.metrics.sessions_total.load(Ordering::Relaxed),
        state.metrics.sessions_active.load(Ordering::Relaxed),
        state.metrics.wss_sessions_total.load(Ordering::Relaxed),
        state.metrics.h2_sessions_total.load(Ordering::Relaxed),
        state.metrics.h3_sessions_total.load(Ordering::Relaxed),
        state.metrics.migrations_total.load(Ordering::Relaxed),
        state.metrics.migration_failed_total.load(Ordering::Relaxed),
        state.metrics.routine_rekeys_total.load(Ordering::Relaxed),
        state.metrics.full_rekeys_total.load(Ordering::Relaxed),
        state.metrics.rekey_failed_total.load(Ordering::Relaxed),
        state.metrics.overloaded_total.load(Ordering::Relaxed),
        state
            .metrics
            .disconnects_expected_total
            .load(Ordering::Relaxed),
        state
            .metrics
            .disconnects_error_total
            .load(Ordering::Relaxed),
        state
            .metrics
            .handshake_duration_micros_total
            .load(Ordering::Relaxed) as f64
            / 1_000_000.0,
        state
            .metrics
            .handshake_attempts_total
            .load(Ordering::Relaxed),
        state
            .metrics
            .shaping_delay_micros_total
            .load(Ordering::Relaxed) as f64
            / 1_000_000.0,
        u8::from(state.network.is_ready()),
        u8::from(state.h3_ready.load(Ordering::Acquire)),
        u8::from(state.draining.load(Ordering::Acquire)),
        state.carriers.available_permits(),
        state.network.received_packets(),
        state.network.routed_packets(),
        state.network.unrouted_packets(),
        state.network.invalid_packets(),
        state.network.dropped_packets(),
    );
    (
        StatusCode::OK,
        [
            ("cache-control", "no-store"),
            ("content-type", "text/plain; version=0.0.4"),
        ],
        body,
    )
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    let ready = state.is_accepting();
    let body = if ready { "ready\n" } else { "not ready\n" };
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        [("cache-control", "no-store")],
        body,
    )
}

async fn maybe_tunnel(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    uri: axum::http::Uri,
) -> Response {
    let path = uri.path();
    if path != state.runtime.tunnel_path || !state.is_operational() {
        return ordinary_not_found();
    }
    let Ok(upgrade) = upgrade else {
        return ordinary_not_found();
    };
    let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return ordinary_not_found();
    };
    let Some(encoded) = auth.strip_prefix("Bearer ") else {
        return ordinary_not_found();
    };
    let source = forwarded_source(&headers, peer.ip());
    if state.runtime.check_admission_rate(source).is_err() {
        state.metrics.gate_rejected.fetch_add(1, Ordering::Relaxed);
        return ordinary_not_found();
    }
    let admission = match state
        .runtime
        .validate_gate(encoded, b"GET", &state.runtime.tunnel_path)
    {
        Ok(client) => Admission::Handshake(Box::new(client)),
        Err(_) => match state
            .runtime
            .validate_migration_gate(encoded, &[0u8; 32], 1)
        {
            Ok(sender) => Admission::Migration(sender),
            Err(_) => {
                state.metrics.gate_rejected.fetch_add(1, Ordering::Relaxed);
                return ordinary_not_found();
            }
        },
    };
    match admission {
        Admission::Handshake(client) => upgrade
            .max_message_size(MAX_ENCRYPTED_HANDSHAKE + 256)
            .max_frame_size(MAX_ENCRYPTED_HANDSHAKE + 256)
            .on_upgrade(move |socket| {
                serve_session(Carrier::WebSocket(Box::new(socket)), state, *client, source)
            })
            .into_response(),
        Admission::Migration(sender) => upgrade
            .max_message_size(MAX_ENCRYPTED_HANDSHAKE + 256)
            .max_frame_size(MAX_ENCRYPTED_HANDSHAKE + 256)
            .on_upgrade(move |socket| {
                submit_migration(Carrier::WebSocket(Box::new(socket)), sender)
            })
            .into_response(),
    }
}

async fn h2_tunnel(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !state.is_operational() {
        return ordinary_not_found();
    }
    let Some(auth) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    else {
        return ordinary_not_found();
    };
    let Some(encoded) = auth.strip_prefix("Bearer ") else {
        return ordinary_not_found();
    };
    let source = forwarded_source(&headers, peer.ip());
    if state.runtime.check_admission_rate(source).is_err() {
        state.metrics.gate_rejected.fetch_add(1, Ordering::Relaxed);
        return ordinary_not_found();
    }
    let admission = match state.runtime.validate_gate(encoded, b"POST", H2_PATH) {
        Ok(client) => Admission::Handshake(Box::new(client)),
        Err(_) => match state
            .runtime
            .validate_migration_gate(encoded, &[0u8; 32], 1)
        {
            Ok(sender) => Admission::Migration(sender),
            Err(_) => {
                state.metrics.gate_rejected.fetch_add(1, Ordering::Relaxed);
                return ordinary_not_found();
            }
        },
    };
    let (output, receiver) = mpsc::channel::<Result<Bytes, Infallible>>(64);
    let carrier = Carrier::H2(H2Carrier {
        input: body.into_data_stream(),
        output,
        buffered: BytesMut::new(),
    });
    match admission {
        Admission::Handshake(client) => {
            tokio::spawn(serve_session(carrier, state, *client, source));
        }
        Admission::Migration(sender) => {
            tokio::spawn(submit_migration(carrier, sender));
        }
    }
    Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store")
        .header("content-type", "application/octet-stream")
        .body(Body::from_stream(ReceiverStream::new(receiver)))
        .expect("streaming response")
}

fn ordinary_not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .expect("static response")
}

impl Runtime {
    fn check_admission_rate(&self, source: IpAddr) -> Result<()> {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(60);
        let mut rates = self
            .admission_rate
            .lock()
            .map_err(|_| anyhow!("admission rate lock poisoned"))?;
        rates.retain(|_, attempts| attempts.back().is_some_and(|seen| *seen >= cutoff));
        if rates.len() >= 8192 && !rates.contains_key(&source) {
            bail!("admission rate table full");
        }
        let attempts = rates.entry(source).or_default();
        while attempts.front().is_some_and(|seen| *seen < cutoff) {
            attempts.pop_front();
        }
        if attempts.len() >= 60 {
            bail!("admission rate exceeded");
        }
        attempts.push_back(now);
        Ok(())
    }

    fn validate_gate(&self, encoded: &str, method: &[u8], path: &str) -> Result<Client> {
        self.validate_gate_token(
            encoded,
            b"RekaSerdoba/1 gate-lab",
            &[],
            method,
            &self.authority,
            path,
        )
    }

    fn validate_h3_gate(
        &self,
        encoded: &str,
        exporter: &[u8; 32],
        authority: &str,
        path: &str,
    ) -> Result<Client> {
        self.validate_gate_token(
            encoded,
            b"RekaSerdoba/1 gate",
            exporter,
            b"CONNECT",
            authority,
            path,
        )
    }

    fn validate_gate_token(
        &self,
        encoded: &str,
        label: &[u8],
        exporter: &[u8],
        method: &[u8],
        authority: &str,
        path: &str,
    ) -> Result<Client> {
        let token = URL_SAFE_NO_PAD.decode(encoded).context("invalid base64")?;
        if token.len() != 72 {
            bail!("invalid token length");
        }
        let client_id: [u8; 16] = token[0..16].try_into()?;
        let unix_time = u64::from_be_bytes(token[16..24].try_into()?);
        let nonce: [u8; 16] = token[24..40].try_into()?;
        let received_mac: [u8; 32] = token[40..72].try_into()?;
        let client = self
            .clients
            .get(&client_id)
            .ok_or_else(|| anyhow!("unknown client"))?;

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        if (now - unix_time as i64).abs() > GATE_WINDOW_SECS {
            bail!("expired token");
        }

        let mut message = Vec::with_capacity(160);
        message.extend_from_slice(label);
        message.extend_from_slice(exporter);
        message.extend_from_slice(method);
        message.push(0);
        message.extend_from_slice(authority.as_bytes());
        message.push(0);
        message.extend_from_slice(path.as_bytes());
        message.push(0);
        message.extend_from_slice(&client_id);
        message.extend_from_slice(&unix_time.to_be_bytes());
        message.extend_from_slice(&nonce);
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(&client.gate_key)?;
        mac.update(&message);
        let expected = mac.finalize().into_bytes();
        if expected.as_slice().ct_eq(&received_mac).unwrap_u8() != 1 {
            bail!("invalid gate MAC");
        }

        let mut replay = self
            .gate_replay
            .lock()
            .map_err(|_| anyhow!("replay lock poisoned"))?;
        let cutoff = Instant::now() - Duration::from_secs(GATE_REPLAY_SECS);
        replay.retain(|_, seen| *seen >= cutoff);
        if replay.insert((client_id, nonce), Instant::now()).is_some() {
            bail!("replayed gate token");
        }
        Ok(client.clone())
    }

    fn validate_migration_gate(
        &self,
        encoded: &str,
        exporter: &[u8; 32],
        endpoint_id: u32,
    ) -> Result<mpsc::Sender<MigrationCandidate>> {
        let token = URL_SAFE_NO_PAD.decode(encoded).context("invalid base64")?;
        if token.len() != 72 {
            bail!("invalid migration token length");
        }
        let session_id: [u8; 16] = token[0..16].try_into()?;
        let unix_time = u64::from_be_bytes(token[16..24].try_into()?);
        let nonce: [u8; 16] = token[24..40].try_into()?;
        let received_mac: [u8; 32] = token[40..72].try_into()?;
        let entry = self
            .migrations
            .lock()
            .map_err(|_| anyhow!("migration registry lock poisoned"))?
            .get(&session_id)
            .cloned()
            .ok_or_else(|| anyhow!("unknown migration session"))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        if (now - unix_time as i64).abs() > GATE_WINDOW_SECS {
            bail!("expired migration token");
        }
        let mut message = Vec::with_capacity(160);
        message.extend_from_slice(b"RekaSerdoba/1 migration gate");
        message.extend_from_slice(exporter);
        message.extend_from_slice(&session_id);
        message.extend_from_slice(&unix_time.to_be_bytes());
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&endpoint_id.to_be_bytes());
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(entry.secret.as_ref().as_ref())?;
        mac.update(&message);
        let expected = mac.finalize().into_bytes();
        if expected.as_slice().ct_eq(&received_mac).unwrap_u8() != 1 {
            bail!("invalid migration MAC");
        }
        let mut replay = entry
            .replay
            .lock()
            .map_err(|_| anyhow!("migration replay lock poisoned"))?;
        let cutoff = Instant::now() - Duration::from_secs(GATE_REPLAY_SECS);
        replay.retain(|_, seen| *seen >= cutoff);
        if replay.insert(nonce, Instant::now()).is_some() {
            bail!("replayed migration token");
        }
        Ok(entry.sender.clone())
    }

    fn register_migration(
        self: &Arc<Self>,
        session_id: [u8; 16],
        secret: Arc<Zeroizing<[u8; 32]>>,
    ) -> Result<(MigrationRegistration, mpsc::Receiver<MigrationCandidate>)> {
        let (sender, receiver) = mpsc::channel(1);
        let entry = Arc::new(MigrationEntry {
            secret,
            sender,
            replay: Mutex::new(HashMap::new()),
        });
        let mut migrations = self
            .migrations
            .lock()
            .map_err(|_| anyhow!("migration registry lock poisoned"))?;
        if migrations.insert(session_id, entry).is_some() {
            bail!("duplicate active session id");
        }
        Ok((
            MigrationRegistration {
                runtime: self.clone(),
                session_id,
            },
            receiver,
        ))
    }
}

fn forwarded_source(headers: &HeaderMap, fallback: IpAddr) -> IpAddr {
    if !fallback.is_loopback() {
        return fallback;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(fallback)
}

impl Carrier {
    fn kind(&self) -> &'static str {
        match self {
            Self::WebSocket(_) => "wss",
            Self::H2(_) => "h2",
            Self::H3(_) => "h3",
        }
    }

    async fn recv(&mut self) -> Result<CarrierEvent> {
        match self {
            Self::WebSocket(socket) => match socket.recv().await {
                Some(Ok(Message::Binary(value))) => Ok(CarrierEvent::Binary(value.to_vec())),
                Some(Ok(Message::Ping(value))) => Ok(CarrierEvent::Ping(value.to_vec())),
                Some(Ok(Message::Close(_))) | None => Ok(CarrierEvent::Close),
                Some(Ok(_)) => Ok(CarrierEvent::Ignore),
                Some(Err(error)) => Err(error.into()),
            },
            Self::H2(stream) => loop {
                if let Some(message) = take_carrier_message(&mut stream.buffered)? {
                    return Ok(CarrierEvent::Binary(message));
                }
                match stream.input.next().await {
                    Some(Ok(chunk)) => {
                        stream.buffered.extend_from_slice(&chunk);
                        if stream.buffered.len() > 1024 * 1024 {
                            bail!("H2 carrier buffer limit exceeded");
                        }
                    }
                    Some(Err(error)) => return Err(error.into()),
                    None if stream.buffered.is_empty() => return Ok(CarrierEvent::Close),
                    None => bail!("truncated H2 carrier message"),
                }
            },
            Self::H3(stream) => recv_h3_message(stream).await,
        }
    }

    async fn send_binary(&mut self, payload: Vec<u8>) -> Result<()> {
        match self {
            Self::WebSocket(socket) => {
                socket.send(Message::Binary(payload.into())).await?;
            }
            Self::H2(stream) => {
                let mut encoded = Vec::with_capacity(4 + payload.len());
                encoded.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
                encoded.extend_from_slice(&payload);
                stream
                    .output
                    .send(Ok(Bytes::from(encoded)))
                    .await
                    .map_err(|_| anyhow!("H2 carrier response closed"))?;
            }
            Self::H3(stream) => {
                if stream.application_ready && is_application_data_record(&payload) {
                    stream.session.send_datagram(Bytes::from(payload))?;
                } else {
                    send_h3_stream_message(stream, &payload).await?;
                }
            }
        }
        Ok(())
    }

    async fn send_pong(&mut self, payload: Vec<u8>) -> Result<()> {
        if let Self::WebSocket(socket) = self {
            socket.send(Message::Pong(payload.into())).await?;
        }
        Ok(())
    }

    async fn close(&mut self) {
        match self {
            Self::WebSocket(socket) => {
                let _ = socket.send(Message::Close(None)).await;
            }
            Self::H2(_) => {}
            Self::H3(stream) => {
                stream.session.close().await;
            }
        }
    }

    fn mark_application_ready(&mut self) {
        if let Self::H3(stream) = self {
            stream.application_ready = true;
        }
    }
}

async fn recv_h3_message(stream: &mut H3Carrier) -> Result<CarrierEvent> {
    loop {
        if let Some(message) = take_carrier_message(&mut stream.buffered)? {
            return Ok(CarrierEvent::Binary(message));
        }
        let mut chunk = [0u8; 8192];
        match stream
            .session
            .receive(&mut chunk, stream.application_ready)
            .await?
        {
            h3_edge::Receive::Reliable(None) if stream.buffered.is_empty() => {
                return Ok(CarrierEvent::Close);
            }
            h3_edge::Receive::Reliable(None) => bail!("truncated H3 carrier message"),
            h3_edge::Receive::Reliable(Some(length)) => {
                stream.buffered.extend_from_slice(&chunk[..length]);
                if stream.buffered.len() > 1024 * 1024 {
                    bail!("H3 carrier buffer limit exceeded");
                }
            }
            h3_edge::Receive::Datagram(datagram) => {
                if datagram.len() > MAX_CARRIER_MESSAGE {
                    bail!("H3 datagram exceeds carrier limit");
                }
                return Ok(CarrierEvent::Binary(datagram));
            }
        }
    }
}

async fn send_h3_stream_message(stream: &mut H3Carrier, payload: &[u8]) -> Result<()> {
    let mut encoded = Vec::with_capacity(4 + payload.len());
    encoded.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    encoded.extend_from_slice(payload);
    stream.session.write_reliable(&encoded).await?;
    Ok(())
}

async fn serve_session(mut carrier: Carrier, state: AppState, client: Client, peer: IpAddr) {
    let Ok(_carrier_permit) = state.carriers.clone().try_acquire_owned() else {
        state
            .metrics
            .overloaded_total
            .fetch_add(1, Ordering::Relaxed);
        carrier.close().await;
        return;
    };
    if state.draining.load(Ordering::Acquire) {
        carrier.close().await;
        return;
    }
    let carrier_kind = carrier.kind();
    let handshake_started = Instant::now();
    state
        .metrics
        .handshake_attempts_total
        .fetch_add(1, Ordering::Relaxed);
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        inner_handshake(&mut carrier, &state.runtime, &client),
    )
    .await;
    state.metrics.handshake_duration_micros_total.fetch_add(
        handshake_started
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64,
        Ordering::Relaxed,
    );
    match outcome {
        Ok(Ok(mut established)) => {
            state.metrics.sessions_total.fetch_add(1, Ordering::Relaxed);
            match carrier_kind {
                "wss" => &state.metrics.wss_sessions_total,
                "h2" => &state.metrics.h2_sessions_total,
                _ => &state.metrics.h3_sessions_total,
            }
            .fetch_add(1, Ordering::Relaxed);
            state
                .metrics
                .sessions_active
                .fetch_add(1, Ordering::Relaxed);
            let _active = ActiveSession(state.metrics.clone());
            let (migration_registration, migrations) = match state
                .runtime
                .register_migration(established.session_id, established.migration_secret.clone())
            {
                Ok(registration) => registration,
                Err(error) => {
                    warn!(reason = %error, "session migration registration failed");
                    carrier.close().await;
                    return;
                }
            };
            let _migration_registration = migration_registration;
            info!("session established");
            carrier.mark_application_ready();
            if let Err(error) = run_established_session(
                &mut carrier,
                &state.network,
                &state.runtime,
                &client,
                &mut established,
                migrations,
                &state.metrics,
            )
            .await
            {
                let (code, expected) = disconnect_reason(&error);
                if expected {
                    state
                        .metrics
                        .disconnects_expected_total
                        .fetch_add(1, Ordering::Relaxed);
                    info!(code, reason = %error, "session closed");
                } else {
                    state
                        .metrics
                        .disconnects_error_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(code, reason = %error, "session failed");
                }
            }
        }
        Ok(Err(error)) => {
            state
                .metrics
                .handshake_failed
                .fetch_add(1, Ordering::Relaxed);
            warn!(%peer, reason = %error, "authenticated handshake failed");
        }
        Err(_) => {
            state
                .metrics
                .handshake_failed
                .fetch_add(1, Ordering::Relaxed);
            warn!(%peer, "authenticated handshake timed out");
        }
    }
    carrier.close().await;
}

fn disconnect_reason(error: &anyhow::Error) -> (&'static str, bool) {
    let reason = error.to_string().to_ascii_lowercase();
    if reason.contains("lifetime expired") {
        ("session_lifetime", true)
    } else if reason.contains("quota exceeded") {
        ("session_quota", true)
    } else if reason.contains("carrier closed")
        || reason.contains("connection reset")
        || reason.contains("broken pipe")
        || reason.contains("error reading a body from connection")
    {
        ("peer_closed", true)
    } else if reason.contains("already has an active session") {
        ("duplicate_session", true)
    } else if reason.contains("timed out") || reason.contains("timeout") {
        ("transport_timeout", true)
    } else {
        ("protocol_error", false)
    }
}

async fn submit_migration(carrier: Carrier, sender: mpsc::Sender<MigrationCandidate>) {
    if let Err(error) = sender.send(MigrationCandidate { carrier }).await {
        let mut candidate = error.0;
        candidate.carrier.close().await;
    }
}

async fn run_established_session(
    carrier: &mut Carrier,
    network: &Network,
    runtime: &Runtime,
    client: &Client,
    session: &mut EstablishedSession,
    mut migrations: mpsc::Receiver<MigrationCandidate>,
    metrics: &Metrics,
) -> Result<()> {
    let (_lease, mut outbound) = network.register(client.tunnel_ipv4)?;
    let mut draining: Option<(Carrier, tokio::time::Instant)> = None;
    let deadline =
        tokio::time::sleep_until(tokio::time::Instant::from_std(session.policy.deadline()));
    tokio::pin!(deadline);
    let update_check = tokio::time::sleep_until(tokio::time::Instant::from_std(
        session.crypto.next_update_check(Instant::now()),
    ));
    tokio::pin!(update_check);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                bail!("session lifetime expired");
            }
            _ = &mut update_check => {}
            message = carrier.recv() => {
                match message? {
                    CarrierEvent::Binary(encoded) => {
                        if !process_record(
                            carrier,
                            network,
                            runtime,
                            session,
                            client,
                            &encoded,
                            metrics,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    CarrierEvent::Ping(value) => {
                        carrier.send_pong(value).await?;
                    }
                    CarrierEvent::Close => return Ok(()),
                    CarrierEvent::Ignore => {}
                }
            }
            old_message = recv_draining_carrier(&mut draining), if draining.is_some() => {
                match old_message? {
                    Some(CarrierEvent::Binary(encoded)) => {
                        let Some((old_carrier, _)) = draining.as_mut() else {
                            continue;
                        };
                        if !process_record(
                            old_carrier,
                            network,
                            runtime,
                            session,
                            client,
                            &encoded,
                            metrics,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    Some(CarrierEvent::Ping(value)) => {
                        if let Some((old_carrier, _)) = draining.as_mut() {
                            old_carrier.send_pong(value).await?;
                        }
                    }
                    Some(CarrierEvent::Close) | None => {
                        if let Some((mut old_carrier, _)) = draining.take() {
                            old_carrier.close().await;
                        }
                    }
                    Some(CarrierEvent::Ignore) => {}
                }
            }
            packet = outbound.recv() => {
                let Some(packet) = packet else {
                    return Ok(());
                };
                shape_traffic(&mut session.policy, packet.len(), metrics).await?;
                send_outbound_packet(carrier, session, packet).await?;
            }
            migration = migrations.recv() => {
                let Some(mut migration) = migration else {
                    continue;
                };
                match validate_migration_path(&mut migration.carrier, session).await {
                    Ok(()) => {
                        migration.carrier.mark_application_ready();
                        if let Some((mut previous_carrier, _)) = draining.take() {
                            previous_carrier.close().await;
                        }
                        std::mem::swap(carrier, &mut migration.carrier);
                        draining = Some((
                            migration.carrier,
                            tokio::time::Instant::now() + Duration::from_secs(3),
                        ));
                        metrics.migrations_total.fetch_add(1, Ordering::Relaxed);
                        info!("session carrier migrated");
                    }
                    Err(error) => {
                        metrics
                            .migration_failed_total
                            .fetch_add(1, Ordering::Relaxed);
                        warn!(reason = %error, "migration path validation failed");
                        migration.carrier.close().await;
                    }
                }
            }
        }
        if let Some(record) = session.crypto.request_update_if_due(Instant::now())? {
            metrics.routine_rekeys_total.fetch_add(1, Ordering::Relaxed);
            carrier.send_binary(record).await?;
        }
        update_check.as_mut().reset(tokio::time::Instant::from_std(
            session.crypto.next_update_check(Instant::now()),
        ));
    }
}

async fn recv_draining_carrier(
    draining: &mut Option<(Carrier, tokio::time::Instant)>,
) -> Result<Option<CarrierEvent>> {
    let Some((carrier, deadline)) = draining.as_mut() else {
        return Ok(None);
    };
    tokio::select! {
        message = carrier.recv() => message.map(Some),
        _ = tokio::time::sleep_until(*deadline) => Ok(None),
    }
}

async fn send_outbound_packet(
    carrier: &mut Carrier,
    session: &mut EstablishedSession,
    packet: Vec<u8>,
) -> Result<()> {
    let datagrams = matches!(
        carrier,
        Carrier::H3(H3Carrier {
            application_ready: true,
            ..
        })
    );
    for frame in outbound_frames(packet, datagrams, OsRng.next_u32())? {
        let plaintext = frame.encode()?;
        let record = session.crypto.seal_data(&plaintext, false)?;
        carrier.send_binary(record).await?;
    }
    Ok(())
}

fn outbound_frames(packet: Vec<u8>, datagrams: bool, packet_id: u32) -> Result<Vec<Frame>> {
    if !datagrams || packet.len() <= H3_DATAGRAM_FRAGMENT_SIZE {
        return Ok(vec![Frame {
            frame_type: 0x01,
            flags: 0,
            body: packet,
        }]);
    }
    let total = u16::try_from(packet.len())?;
    let mut frames = Vec::with_capacity(packet.len().div_ceil(H3_DATAGRAM_FRAGMENT_SIZE));
    for (index, fragment) in packet.chunks(H3_DATAGRAM_FRAGMENT_SIZE).enumerate() {
        let offset = u16::try_from(index * H3_DATAGRAM_FRAGMENT_SIZE)?;
        let length = u16::try_from(fragment.len())?;
        let mut body = Vec::with_capacity(10 + fragment.len());
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.extend_from_slice(&total.to_be_bytes());
        body.extend_from_slice(&offset.to_be_bytes());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(fragment);
        frames.push(Frame {
            frame_type: 0x03,
            flags: 0,
            body,
        });
    }
    Ok(frames)
}

fn is_application_data_record(payload: &[u8]) -> bool {
    payload.len() >= 31 && payload[0] >> 4 == 1 && payload[0] & 0x09 == 0
}

async fn validate_migration_path(
    carrier: &mut Carrier,
    session: &mut EstablishedSession,
) -> Result<()> {
    let mut carrier_id = [0u8; 16];
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut carrier_id);
    OsRng.fill_bytes(&mut challenge);
    let (record, expected) =
        session
            .crypto
            .path_challenge(session.migration_secret.as_ref(), carrier_id, challenge)?;
    carrier.send_binary(record).await?;
    let encoded = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match carrier.recv().await? {
                CarrierEvent::Binary(encoded) => return Ok(encoded),
                CarrierEvent::Ping(value) => carrier.send_pong(value).await?,
                CarrierEvent::Close => bail!("migration carrier closed"),
                CarrierEvent::Ignore => {}
            }
        }
    })
    .await
    .context("migration path response timeout")??;
    let opened = session.crypto.open(&encoded, Instant::now())?;
    if opened.header.kind != RecordKind::Control || opened.position != EpochPosition::Current {
        bail!("invalid migration response record");
    }
    let frames = parse_frames(&opened.plaintext, RecordKind::Control)?;
    if frames.len() != 1 || frames[0].frame_type != 0x0D || frames[0].flags != 0 {
        bail!("invalid migration response frame");
    }
    session
        .crypto
        .accept_path_response(&encoded, &frames[0].body, carrier_id, expected)
}

async fn inner_handshake(
    carrier: &mut Carrier,
    runtime: &Runtime,
    client: &Client,
) -> Result<EstablishedSession> {
    let client_hello = recv_binary(carrier).await?;
    if client_hello.len() > MAX_CLEAR_HANDSHAKE {
        bail!("client hello too large");
    }
    let ch = parse_client_hello(&client_hello)?;
    if ch.client_id != client.id {
        bail!("client selector mismatch");
    }
    let mut transcript = transcript_initial();
    transcript = transcript_next(&transcript, &client_hello);

    let server_secret = StaticSecret::random_from_rng(OsRng);
    let server_ephemeral = X25519PublicKey::from(&server_secret);
    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);
    let server_time = now_secs()? as u32;
    let mut sh0 = Vec::with_capacity(106);
    put_u16(&mut sh0, PROTOCOL_VERSION);
    put_u16(&mut sh0, CIPHER_SUITE);
    sh0.extend_from_slice(&ch.handshake_id);
    sh0.extend_from_slice(server_ephemeral.as_bytes());
    sh0.extend_from_slice(&server_nonce);
    sh0.extend_from_slice(&runtime.server_key_id);
    put_u32(&mut sh0, server_time);
    put_u16(&mut sh0, 0);
    let signature_input = hash_parts(&[
        b"RekaSerdoba/1 server signature",
        &transcript,
        &Sha256::digest(&sh0),
        &ch.client_id,
        &ch.handshake_id,
    ]);
    let signature = runtime.server_signing.sign(&signature_input);
    let mut sh_payload = sh0;
    sh_payload.extend_from_slice(&signature.to_bytes());
    let server_hello = encode_handshake(0x03, &sh_payload)?;
    carrier.send_binary(server_hello.clone()).await?;
    transcript = transcript_next(&transcript, &server_hello);

    let client_ephemeral = X25519PublicKey::from(ch.client_ephemeral);
    let dh = server_secret.diffie_hellman(&client_ephemeral);
    if dh.as_bytes().ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
        bail!("all-zero X25519 output");
    }
    let extract_salt = hash_parts(&[
        b"RekaSerdoba/1 handshake extract",
        &ch.client_nonce,
        &server_nonce,
        &transcript,
    ]);
    let hk = Hkdf::<Sha256>::new(Some(&extract_salt), dh.as_bytes());
    let c_hs_key = expand_label(&hk, "client handshake key", &transcript, 32)?;
    let s_hs_key = expand_label(&hk, "server handshake key", &transcript, 32)?;
    let c_hs_iv = expand_label(&hk, "client handshake iv", &transcript, 12)?;
    let s_hs_iv = expand_label(&hk, "server handshake iv", &transcript, 12)?;
    let c_finished = expand_label(&hk, "client finished", &transcript, 32)?;
    let s_finished = expand_label(&hk, "server finished", &transcript, 32)?;
    let t2 = transcript;

    let encrypted_auth = recv_binary(carrier).await?;
    let auth_plain = open_handshake(&c_hs_key, &c_hs_iv, 0x04, 0, &t2, &encrypted_auth)?;
    verify_client_auth(
        &auth_plain,
        client,
        &t2,
        signature.to_bytes(),
        runtime.server_signing.verifying_key().as_bytes(),
        &c_finished,
    )?;
    transcript = transcript_next(&t2, &encrypted_auth);

    let mut session_id = [0u8; 16];
    OsRng.fill_bytes(&mut session_id);
    let params = assigned_parameters(
        session_id,
        client.tunnel_ipv4,
        client.session_lifetime_seconds,
    );
    let params_hash = Sha256::digest(&params);
    let proof_input = hash_parts(&[b"RekaSerdoba/1 server finished", &transcript, &params_hash]);
    let server_proof = hmac_bytes(&s_finished, &proof_input)?;
    let mut finish_plain = params;
    finish_plain.extend_from_slice(&server_proof);
    let encrypted_finish =
        seal_handshake(&s_hs_key, &s_hs_iv, 0x05, 0, &transcript, &finish_plain)?;
    carrier.send_binary(encrypted_finish.clone()).await?;
    transcript = transcript_next(&transcript, &encrypted_finish);

    let encrypted_confirm = recv_binary(carrier).await?;
    let confirm_plain = open_handshake(
        &c_hs_key,
        &c_hs_iv,
        0x06,
        1,
        &transcript,
        &encrypted_confirm,
    )?;
    if confirm_plain.len() != 48 || confirm_plain[..16].ct_eq(&session_id).unwrap_u8() != 1 {
        bail!("invalid client finish");
    }
    let confirm_input = hash_parts(&[b"RekaSerdoba/1 client confirm", &transcript, &session_id]);
    let expected = hmac_bytes(&c_finished, &confirm_input)?;
    if confirm_plain[16..].ct_eq(&expected).unwrap_u8() != 1 {
        bail!("invalid client confirmation");
    }
    transcript = transcript_next(&transcript, &encrypted_confirm);
    let secrets = ApplicationSecrets::derive(&hk, &transcript, session_id)?;
    let ApplicationSecrets {
        epoch_secret,
        migration,
        resumption,
        exporter,
        epoch,
    } = secrets;
    let crypto = RekeySession::new(session_id, epoch_secret, epoch, transcript, Instant::now())?;
    Ok(EstablishedSession {
        session_id,
        crypto,
        fragments: FragmentReassembler::new(),
        policy: SessionPolicy::new(
            client.session_lifetime_seconds,
            client.bandwidth_bytes_per_second,
            client.session_quota_bytes,
            Instant::now(),
        )?,
        migration_secret: Arc::new(migration),
        _resumption_secret: resumption,
        _exporter_secret: exporter,
    })
}

struct EstablishedSession {
    session_id: [u8; 16],
    crypto: RekeySession,
    fragments: FragmentReassembler,
    policy: SessionPolicy,
    migration_secret: Arc<Zeroizing<[u8; 32]>>,
    _resumption_secret: Zeroizing<[u8; 32]>,
    _exporter_secret: Zeroizing<[u8; 32]>,
}

async fn process_record(
    carrier: &mut Carrier,
    network: &Network,
    runtime: &Runtime,
    session: &mut EstablishedSession,
    client: &Client,
    encoded: &[u8],
    metrics: &Metrics,
) -> Result<bool> {
    let opened = session.crypto.open(encoded, Instant::now())?;
    match opened.header.kind {
        RecordKind::Data => {
            let frames = parse_frames(&opened.plaintext, RecordKind::Data)?;
            for frame in frames {
                if frame.frame_type == 0x03 {
                    if let Some(packet) = session.fragments.push(&frame.body, Instant::now())? {
                        validate_ipv4_packet(&packet, client.tunnel_ipv4)?;
                        shape_traffic(&mut session.policy, packet.len(), metrics).await?;
                        network.send_to_kernel(&packet).await?;
                    }
                    continue;
                }
                if let Some(response) = validate_data_frame(&frame, client)? {
                    let plaintext = response.encode()?;
                    let record = session.crypto.seal_data(&plaintext, false)?;
                    carrier.send_binary(record).await?;
                }
                if frame.frame_type == 0x01 {
                    shape_traffic(&mut session.policy, frame.body.len(), metrics).await?;
                    network.send_to_kernel(&frame.body).await?;
                }
            }
            Ok(true)
        }
        RecordKind::Control => {
            let frames = parse_frames(&opened.plaintext, RecordKind::Control)?;
            if frames.len() != 1
                && frames
                    .iter()
                    .any(|frame| matches!(frame.frame_type, 0x04..=0x11))
            {
                bail!("security-critical control record must contain one frame");
            }
            for frame in frames {
                match frame.frame_type {
                    0x02 => {
                        let response = Frame {
                            frame_type: 0x03,
                            flags: 0,
                            body: frame.body,
                        }
                        .encode()?;
                        let record = session.crypto.seal_control(&response, false)?;
                        carrier.send_binary(record).await?;
                    }
                    0x05 => {
                        if opened.position != EpochPosition::Current || frame.flags != 0 {
                            bail!("invalid key update init epoch or flags");
                        }
                        let record = session
                            .crypto
                            .accept_update_init(encoded, &frame.body, Instant::now())
                            .inspect_err(|_| {
                                metrics.rekey_failed_total.fetch_add(1, Ordering::Relaxed);
                            })?;
                        metrics.routine_rekeys_total.fetch_add(1, Ordering::Relaxed);
                        carrier.send_binary(record).await?;
                    }
                    0x07 => {
                        if opened.position != EpochPosition::Pending || frame.flags != 0 {
                            bail!("invalid key update commit epoch or flags");
                        }
                        let record = session
                            .crypto
                            .accept_update_commit(encoded, &frame.body, Instant::now())
                            .inspect_err(|_| {
                                metrics.rekey_failed_total.fetch_add(1, Ordering::Relaxed);
                            })?;
                        carrier.send_binary(record).await?;
                    }
                    0x09 => {
                        if opened.position != EpochPosition::Current || frame.flags != 0 {
                            bail!("invalid full rekey init epoch or flags");
                        }
                        let record = session
                            .crypto
                            .accept_full_rekey_init(
                                encoded,
                                &frame.body,
                                &client.public_key,
                                &runtime.server_signing,
                            )
                            .inspect_err(|_| {
                                metrics.rekey_failed_total.fetch_add(1, Ordering::Relaxed);
                            })?;
                        metrics.full_rekeys_total.fetch_add(1, Ordering::Relaxed);
                        carrier.send_binary(record).await?;
                    }
                    0x0B => {
                        if opened.position != EpochPosition::Pending || frame.flags != 0 {
                            bail!("invalid full rekey confirmation epoch or flags");
                        }
                        let record = session
                            .crypto
                            .accept_full_rekey_confirm(encoded, &frame.body, Instant::now())
                            .inspect_err(|_| {
                                metrics.rekey_failed_total.fetch_add(1, Ordering::Relaxed);
                            })?;
                        carrier.send_binary(record).await?;
                    }
                    0x12 => return Ok(false),
                    _ => {}
                }
            }
            Ok(true)
        }
    }
}

async fn shape_traffic(policy: &mut SessionPolicy, bytes: usize, metrics: &Metrics) -> Result<()> {
    let delay = policy.reserve(bytes, Instant::now())?;
    if !delay.is_zero() {
        metrics.shaping_delay_micros_total.fetch_add(
            delay.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        tokio::time::sleep(delay).await;
    }
    Ok(())
}

fn validate_data_frame(frame: &Frame, client: &Client) -> Result<Option<Frame>> {
    if frame.flags != 0 {
        bail!("unsupported data frame flags");
    }
    match frame.frame_type {
        0x00 => Ok(None),
        0x01 => {
            validate_ipv4_packet(&frame.body, client.tunnel_ipv4)?;
            Ok(None)
        }
        0x02 => bail!("IPv6 is not enabled for this client"),
        0x03 => Ok(None),
        0x04 => {
            if !frame.body.is_empty() {
                bail!("keepalive frame must be empty");
            }
            Ok(Some(Frame {
                frame_type: 0x04,
                flags: 0,
                body: Vec::new(),
            }))
        }
        0x05 => {
            if frame.body.len() > 64 {
                bail!("path probe too large");
            }
            Ok(Some(Frame {
                frame_type: 0x06,
                flags: 0,
                body: frame.body.clone(),
            }))
        }
        0x06 => {
            if frame.body.len() > 64 {
                bail!("path probe reply too large");
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn validate_ipv4_packet(packet: &[u8], expected_source: [u8; 4]) -> Result<()> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        bail!("invalid IPv4 header");
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || header_len > packet.len() {
        bail!("invalid IPv4 header length");
    }
    let total_len = u16::from_be_bytes(packet[2..4].try_into()?) as usize;
    if total_len != packet.len() || total_len > 1280 {
        bail!("invalid IPv4 packet length");
    }
    if packet[12..16].ct_eq(&expected_source).unwrap_u8() != 1 {
        bail!("IPv4 source policy violation");
    }
    if ipv4_checksum(&packet[..header_len]) != 0 {
        bail!("invalid IPv4 header checksum");
    }
    Ok(())
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks_exact(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

struct ClientHello {
    handshake_id: [u8; 16],
    client_id: [u8; 16],
    client_ephemeral: [u8; 32],
    client_nonce: [u8; 32],
}

fn parse_client_hello(encoded: &[u8]) -> Result<ClientHello> {
    if encoded.len() < 5 || encoded[0] != 0x01 {
        bail!("expected CLIENT_HELLO");
    }
    let len = u32::from_be_bytes(encoded[1..5].try_into()?) as usize;
    if len != encoded.len() - 5 {
        bail!("bad CLIENT_HELLO length");
    }
    let mut c = Cursor::new(&encoded[5..]);
    if c.u16()? != PROTOCOL_VERSION || c.u16()? != CIPHER_SUITE {
        bail!("unsupported version or suite");
    }
    let handshake_id = c.fixed()?;
    let client_id = c.fixed()?;
    let client_ephemeral = c.fixed()?;
    let client_nonce = c.fixed()?;
    let client_time = c.u64()?;
    if (now_secs()? as i64 - client_time as i64).abs() > 300 {
        bail!("client clock outside allowed window");
    }
    let retry_len = c.u16()? as usize;
    if retry_len > 64 {
        bail!("retry cookie too large");
    }
    if retry_len != 0 {
        bail!("inner retry is disabled");
    }
    c.skip(retry_len)?;
    let extension_len = c.u16()? as usize;
    if extension_len > 1024 {
        bail!("extensions too large");
    }
    if extension_len != 0 {
        bail!("resumption and experimental extensions are disabled");
    }
    c.skip(extension_len)?;
    c.finish()?;
    Ok(ClientHello {
        handshake_id,
        client_id,
        client_ephemeral,
        client_nonce,
    })
}

fn verify_client_auth(
    plaintext: &[u8],
    client: &Client,
    t2: &[u8; 32],
    server_signature: [u8; 64],
    server_public: &[u8; 32],
    client_finished_key: &[u8],
) -> Result<()> {
    if plaintext.len() < 16 + 16 + 4 + 2 + 2 + 64 + 32 {
        bail!("short CLIENT_AUTH");
    }
    let mut c = Cursor::new(plaintext);
    let client_id: [u8; 16] = c.fixed()?;
    let client_key_id: [u8; 16] = c.fixed()?;
    let _features = c.u32()?;
    let mtu = c.u16()?;
    if !(1200..=1500).contains(&mtu) {
        bail!("invalid requested MTU");
    }
    let extension_len = c.u16()? as usize;
    if extension_len > 1024 {
        bail!("extensions too large");
    }
    c.skip(extension_len)?;
    let signature_offset = c.pos;
    let signature_bytes: [u8; 64] = c.fixed()?;
    let finished_offset = c.pos;
    let received_finished: [u8; 32] = c.fixed()?;
    c.finish()?;
    if client_id.ct_eq(&client.id).unwrap_u8() != 1 {
        bail!("client id mismatch");
    }
    let expected_key_id = key_id(b"RekaSerdoba client key", client.public_key.as_bytes());
    if client_key_id.ct_eq(&expected_key_id).unwrap_u8() != 1 {
        bail!("client key id mismatch");
    }
    let sig_input = hash_parts(&[
        b"RekaSerdoba/1 client signature",
        t2,
        &server_signature,
        server_public,
        &client.id,
        &client_key_id,
    ]);
    client
        .public_key
        .verify(&sig_input, &Signature::from_bytes(&signature_bytes))
        .context("invalid client signature")?;
    let auth_without_finished = &plaintext[..finished_offset];
    if signature_offset + 64 != finished_offset {
        bail!("invalid auth layout");
    }
    let proof_input = hash_parts(&[b"RekaSerdoba/1 client finished", t2, auth_without_finished]);
    let expected = hmac_bytes(client_finished_key, &proof_input)?;
    if received_finished.ct_eq(&expected).unwrap_u8() != 1 {
        bail!("invalid client finished");
    }
    Ok(())
}

fn assigned_parameters(
    session_id: [u8; 16],
    ipv4: [u8; 4],
    session_lifetime_seconds: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&session_id);
    put_u32(&mut out, session_lifetime_seconds);
    put_u16(&mut out, 1280);
    put_u16(&mut out, 4096);
    put_u32(&mut out, 1 << 24);
    put_u32(&mut out, 1800);
    out.push(24);
    out.extend_from_slice(&ipv4);
    out.push(0);
    out.extend_from_slice(&[0u8; 16]);
    out.push(0);
    put_u16(&mut out, 0);
    out
}

fn seal_handshake(
    key: &[u8],
    iv: &[u8],
    message_type: u8,
    sequence: u32,
    transcript: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > 4096 {
        bail!("handshake plaintext too large");
    }
    let ciphertext_len = plaintext.len() + 16;
    let mut header = Vec::with_capacity(8);
    header.push(message_type);
    header.push(0);
    put_u32(&mut header, sequence);
    put_u16(&mut header, ciphertext_len as u16);
    let mut aad = header.clone();
    aad.extend_from_slice(transcript);
    let nonce = packet_nonce(iv, sequence as u64)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("handshake encryption failed"))?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

fn open_handshake(
    key: &[u8],
    iv: &[u8],
    message_type: u8,
    sequence: u32,
    transcript: &[u8; 32],
    encoded: &[u8],
) -> Result<Vec<u8>> {
    if encoded.len() < 24
        || encoded[0] != message_type
        || encoded[1] != 0
        || u32::from_be_bytes(encoded[2..6].try_into()?) != sequence
    {
        bail!("invalid encrypted handshake header");
    }
    let ciphertext_len = u16::from_be_bytes(encoded[6..8].try_into()?) as usize;
    if ciphertext_len > MAX_ENCRYPTED_HANDSHAKE || ciphertext_len != encoded.len() - 8 {
        bail!("invalid encrypted handshake length");
    }
    let mut aad = encoded[..8].to_vec();
    aad.extend_from_slice(transcript);
    let nonce = packet_nonce(iv, sequence as u64)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encoded[8..],
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("handshake authentication failed"))
}

fn expand_label(hk: &Hkdf<Sha256>, label: &str, context: &[u8], len: usize) -> Result<Vec<u8>> {
    let full_label = format!("RekaSerdoba/1 {label}");
    if full_label.len() > u8::MAX as usize || context.len() > u16::MAX as usize {
        bail!("HKDF label or context too long");
    }
    let mut info = Vec::with_capacity(7 + full_label.len() + context.len());
    put_u16(&mut info, len as u16);
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    put_u16(&mut info, context.len() as u16);
    info.extend_from_slice(context);
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(out)
}

fn packet_nonce(iv: &[u8], packet_number: u64) -> Result<[u8; 12]> {
    let mut nonce: [u8; 12] = iv.try_into().context("invalid IV length")?;
    let encoded = packet_number.to_be_bytes();
    for (slot, byte) in nonce[4..].iter_mut().zip(encoded) {
        *slot ^= byte;
    }
    Ok(nonce)
}

fn encode_handshake(message_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > MAX_CLEAR_HANDSHAKE {
        bail!("handshake message too large");
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(message_type);
    put_u32(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    Ok(out)
}

fn transcript_initial() -> [u8; 32] {
    Sha256::digest(b"RekaSerdoba/1 transcript").into()
}

fn transcript_next(previous: &[u8; 32], encoded: &[u8]) -> [u8; 32] {
    hash_parts(&[previous, encoded])
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn hmac_bytes(key: &[u8], message: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(key)?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

fn key_id(label: &[u8], public_key: &[u8]) -> [u8; 16] {
    let hash = hash_parts(&[label, public_key]);
    hash[..16].try_into().expect("fixed slice")
}

fn decode_fixed<const N: usize>(encoded: &str, what: &str) -> Result<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .with_context(|| format!("decode {what}"))?
        .try_into()
        .map_err(|_| anyhow!("{what} must be {N} bytes"))
}

async fn recv_binary(carrier: &mut Carrier) -> Result<Vec<u8>> {
    match carrier.recv().await? {
        CarrierEvent::Binary(value) => Ok(value),
        CarrierEvent::Close => bail!("carrier closed"),
        _ => bail!("expected binary message"),
    }
}

fn now_secs() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("overflow"))?;
        let value = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| anyhow!("truncated input"))?;
        self.pos = end;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into()?)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn skip(&mut self, len: usize) -> Result<()> {
        self.take(len)?;
        Ok(())
    }
    fn finish(self) -> Result<()> {
        if self.pos != self.bytes.len() {
            bail!("trailing bytes");
        }
        Ok(())
    }
}

async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_config(id: u8, ip: &str) -> ClientConfig {
        let signing = SigningKey::from_bytes(&[id.wrapping_add(1); 32]);
        ClientConfig {
            client_id_b64: URL_SAFE_NO_PAD.encode([id; 16]),
            client_public_key_b64: URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes()),
            gate_key_b64: URL_SAFE_NO_PAD.encode([id.wrapping_add(2); 32]),
            tunnel_ipv4: ip.to_owned(),
            revoked: false,
            session_lifetime_seconds: 3600,
            bandwidth_bytes_per_second: 1024 * 1024,
            session_quota_bytes: 0,
        }
    }

    fn test_config(clients: Vec<ClientConfig>) -> Config {
        Config {
            listen: "127.0.0.1:9080".to_owned(),
            authority: "vpn.example:443".to_owned(),
            tunnel_path: "/connect".to_owned(),
            server_signing_seed_b64: URL_SAFE_NO_PAD.encode([9u8; 32]),
            tun: TunSettings {
                name: "reka0".to_owned(),
                address: "10.77.0.1".to_owned(),
                prefix_len: 24,
                mtu: 1280,
                session_queue: 64,
                helper_socket: None,
                helper_client_socket: None,
            },
            clients,
            h3: None,
        }
    }

    #[test]
    fn nonce_xors_packet_number_into_low_64_bits() {
        let iv = [0x55u8; 12];
        let nonce = packet_nonce(&iv, 0x0102_0304_0506_0708).unwrap();
        assert_eq!(&nonce[..4], &[0x55; 4]);
        assert_eq!(
            &nonce[4..],
            &[0x54, 0x57, 0x56, 0x51, 0x50, 0x53, 0x52, 0x5d]
        );
    }

    #[test]
    fn transcript_is_chained() {
        let t0 = transcript_initial();
        let t1 = transcript_next(&t0, b"message");
        assert_ne!(t0, t1);
        assert_eq!(t1, transcript_next(&t0, b"message"));
    }

    #[test]
    fn handshake_record_round_trip_and_aad_binding() {
        let hk = Hkdf::<Sha256>::new(Some(b"salt"), b"secret");
        let transcript = [7u8; 32];
        let key = expand_label(&hk, "client handshake key", &transcript, 32).unwrap();
        let iv = expand_label(&hk, "client handshake iv", &transcript, 12).unwrap();
        let encoded = seal_handshake(&key, &iv, 0x04, 0, &transcript, b"authenticated").unwrap();
        assert_eq!(
            open_handshake(&key, &iv, 0x04, 0, &transcript, &encoded).unwrap(),
            b"authenticated"
        );
        assert!(open_handshake(&key, &iv, 0x04, 0, &[8u8; 32], &encoded).is_err());
    }

    #[test]
    fn carrier_framing_handles_fragmented_and_coalesced_messages() {
        let mut buffered = BytesMut::from(&[0, 0, 0, 3, 1, 2][..]);
        assert!(take_carrier_message(&mut buffered).unwrap().is_none());
        buffered.extend_from_slice(&[3, 0, 0, 0, 2, 4, 5]);
        assert_eq!(
            take_carrier_message(&mut buffered).unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            take_carrier_message(&mut buffered).unwrap(),
            Some(vec![4, 5])
        );
        assert!(buffered.is_empty());
    }

    #[test]
    fn carrier_framing_rejects_invalid_lengths() {
        assert!(take_carrier_message(&mut BytesMut::from(&[0, 0, 0, 0][..])).is_err());
        let mut oversized = BytesMut::from(&(MAX_CARRIER_MESSAGE as u32 + 1).to_be_bytes()[..]);
        assert!(take_carrier_message(&mut oversized).is_err());
    }

    #[test]
    fn carrier_framing_survives_random_chunk_boundaries() {
        let messages = (0..128)
            .map(|index| vec![index as u8; index % 97 + 1])
            .collect::<Vec<_>>();
        let mut encoded = Vec::new();
        for message in &messages {
            encoded.extend_from_slice(&(message.len() as u32).to_be_bytes());
            encoded.extend_from_slice(message);
        }
        let mut state = 0x9e3779b97f4a7c15u64;
        let mut offset = 0;
        let mut buffered = BytesMut::new();
        let mut decoded = Vec::new();
        while offset < encoded.len() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = (state as usize % 31 + 1).min(encoded.len() - offset);
            buffered.extend_from_slice(&encoded[offset..offset + length]);
            offset += length;
            while let Some(message) = take_carrier_message(&mut buffered).unwrap() {
                decoded.push(message);
            }
        }
        assert_eq!(decoded, messages);
        assert!(buffered.is_empty());
    }

    #[test]
    fn h3_datagram_frames_reassemble_full_mtu_packets() {
        let packet = (0..1280).map(|index| index as u8).collect::<Vec<_>>();
        let frames = outbound_frames(packet.clone(), true, 7).unwrap();
        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|frame| {
            frame.frame_type == 0x03
                && frame.flags == 0
                && frame.body.len() <= H3_DATAGRAM_FRAGMENT_SIZE + 10
        }));
        let now = Instant::now();
        let mut reassembler = FragmentReassembler::new();
        let mut restored = None;
        for frame in frames {
            if let Some(value) = reassembler.push(&frame.body, now).unwrap() {
                restored = Some(value);
            }
        }
        assert_eq!(restored, Some(packet));
    }

    #[test]
    fn application_data_records_are_selected_for_datagrams() {
        let mut data = vec![0u8; 31];
        data[0] = 0x10;
        assert!(is_application_data_record(&data));
        data[0] = 0x18;
        assert!(!is_application_data_record(&data));
        assert!(!is_application_data_record(&data[..30]));
    }

    #[test]
    fn configuration_rejects_duplicate_tunnel_addresses() {
        let cfg = test_config(vec![
            client_config(1, "10.77.0.2"),
            client_config(2, "10.77.0.2"),
        ]);
        assert!(Runtime::from_config(&cfg).is_err());
    }

    #[test]
    fn configuration_rejects_unusable_tunnel_addresses() {
        for address in ["10.77.0.0", "10.77.0.1", "10.77.0.255", "10.78.0.2"] {
            let cfg = test_config(vec![client_config(1, address)]);
            assert!(Runtime::from_config(&cfg).is_err(), "{address}");
        }
    }

    #[test]
    fn configuration_accepts_distinct_clients_in_subnet() {
        let cfg = test_config(vec![
            client_config(1, "10.77.0.2"),
            client_config(2, "10.77.0.3"),
        ]);
        assert_eq!(Runtime::from_config(&cfg).unwrap().clients.len(), 2);
    }

    #[test]
    fn forwarded_source_is_only_trusted_from_loopback_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.8, 127.0.0.1".parse().unwrap(),
        );
        assert_eq!(
            forwarded_source(&headers, "127.0.0.1".parse().unwrap()),
            "198.51.100.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            forwarded_source(&headers, "203.0.113.9".parse().unwrap()),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
    }
}
