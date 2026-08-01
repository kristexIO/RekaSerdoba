use std::{
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use h3::ext::Protocol;
use h3_webtransport::{
    server::{AcceptedBi, WebTransportSession},
    stream::BidiStream as WebTransportBidiStream,
};
use http::{Method, Request, Response, StatusCode};
use quinn::{Endpoint, TransportConfig, VarInt, crypto::rustls::QuicServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{Semaphore, mpsc};
use tracing::{info, warn};

type Http3RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type WebTransportConnection = WebTransportSession<h3_quinn::Connection, Bytes>;
type WebTransportStream = WebTransportBidiStream<h3_quinn::BidiStream<Bytes>, Bytes>;
const MAX_H3_CONNECTIONS: usize = 256;
const MAX_H3_DECOY_REQUESTS: usize = 64;
const MAX_DECOY_FILE_SIZE: u64 = 1024 * 1024;

pub struct Server {
    endpoint: Endpoint,
    authority: String,
    path: String,
    decoy_root: Arc<PathBuf>,
}

pub struct Session {
    connection: quinn::Connection,
    webtransport: Arc<WebTransportConnection>,
    send: WriteHalf<WebTransportStream>,
    recv: ReadHalf<WebTransportStream>,
    peer: IpAddr,
}

pub enum Receive {
    Reliable(Option<usize>),
    Datagram(Vec<u8>),
}

impl Server {
    pub fn bind(
        listen: SocketAddr,
        authority: String,
        path: String,
        certificate: &Path,
        private_key: &Path,
        decoy_root: &Path,
    ) -> Result<Self> {
        let tls = load_tls_config(certificate, private_key)?;
        let crypto = QuicServerConfig::try_from(tls).context("configure H3 QUIC TLS")?;
        let mut transport = TransportConfig::default();
        transport.max_concurrent_bidi_streams(VarInt::from_u32(64));
        transport.max_concurrent_uni_streams(VarInt::from_u32(64));
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        transport.datagram_send_buffer_size(4 * 1024 * 1024);
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(Arc::new(transport));
        let endpoint = Endpoint::server(config, listen).context("bind H3 endpoint")?;
        let decoy_root = std::fs::canonicalize(decoy_root).context("resolve H3 decoy root")?;
        Ok(Self {
            endpoint,
            authority,
            path,
            decoy_root: Arc::new(decoy_root),
        })
    }

    pub fn validate(certificate: &Path, private_key: &Path, decoy_root: &Path) -> Result<()> {
        load_tls_config(certificate, private_key)?;
        let metadata = std::fs::metadata(decoy_root).context("read H3 decoy root metadata")?;
        if !metadata.is_dir() {
            bail!("H3 decoy root is not a directory");
        }
        std::fs::canonicalize(decoy_root).context("resolve H3 decoy root")?;
        Ok(())
    }

    pub async fn serve(self, sessions: mpsc::Sender<Session>) {
        let connections = Arc::new(Semaphore::new(MAX_H3_CONNECTIONS));
        while let Some(incoming) = self.endpoint.accept().await {
            if !incoming.remote_address_validated() {
                if let Err(error) = incoming.retry() {
                    warn!(reason = %error, "H3 QUIC retry failed");
                }
                continue;
            }
            let authority = self.authority.clone();
            let path = self.path.clone();
            let decoy_root = self.decoy_root.clone();
            let sessions = sessions.clone();
            let Ok(permit) = connections.clone().try_acquire_owned() else {
                drop(incoming);
                continue;
            };
            tokio::spawn(async move {
                let _permit = permit;
                match tokio::time::timeout(
                    Duration::from_secs(15),
                    accept_connection(incoming, &authority, &path, decoy_root),
                )
                .await
                {
                    Ok(Ok(Some(session))) => {
                        if let Err(error) = sessions.send(session).await {
                            let mut session = error.0;
                            session.close().await;
                        }
                    }
                    Ok(Ok(None)) => {}
                    Ok(Err(error)) => warn!(reason = %error, "H3 connection failed"),
                    Err(_) => warn!("H3 connection timed out"),
                }
            });
        }
    }
}

fn load_tls_config(certificate: &Path, private_key: &Path) -> Result<rustls::ServerConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificates = CertificateDer::pem_file_iter(certificate)
        .with_context(|| format!("open H3 certificate {}", certificate.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse H3 certificate")?;
    if certificates.is_empty() {
        bail!("H3 certificate chain is empty");
    }
    let key = PrivateKeyDer::from_pem_file(private_key)
        .with_context(|| format!("parse H3 private key {}", private_key.display()))?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("configure H3 certificate")?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.max_early_data_size = 0;
    Ok(tls)
}

impl Session {
    pub fn peer(&self) -> IpAddr {
        self.peer
    }

    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<()> {
        self.connection
            .export_keying_material(output, label, context)
            .map_err(|_| anyhow!("TLS exporter unavailable"))
    }

    pub async fn read_reliable(&mut self, output: &mut [u8]) -> Result<Option<usize>> {
        let length = self.recv.read(output).await?;
        Ok((length != 0).then_some(length))
    }

    pub async fn receive(&mut self, output: &mut [u8], datagrams: bool) -> Result<Receive> {
        if !datagrams {
            return Ok(Receive::Reliable(self.read_reliable(output).await?));
        }
        let webtransport = self.webtransport.clone();
        tokio::select! {
            length = self.recv.read(output) => {
                let length = length?;
                Ok(Receive::Reliable((length != 0).then_some(length)))
            }
            datagram = async move {
                let mut reader = webtransport.datagram_reader();
                reader.read_datagram().await
            } => {
                Ok(Receive::Datagram(datagram?.into_payload().to_vec()))
            }
        }
    }

    pub async fn write_reliable(&mut self, value: &[u8]) -> Result<()> {
        self.send.write_all(value).await?;
        Ok(())
    }

    pub async fn close(&mut self) {
        let _ = self.send.shutdown().await;
        self.connection
            .close(VarInt::from_u32(0), b"session closed");
    }
}

async fn accept_connection(
    incoming: quinn::Incoming,
    authority: &str,
    path: &str,
    decoy_root: Arc<PathBuf>,
) -> Result<Option<Session>> {
    let connection = incoming.await.context("accept H3 QUIC connection")?;
    let peer = connection.remote_address().ip();
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(true)
        .enable_webtransport(true)
        .max_webtransport_sessions(1);
    let mut http3 = builder
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .context("start H3 connection")?;
    loop {
        let Some(resolver) = http3.accept().await.context("accept H3 request")? else {
            return Ok(None);
        };
        let (request, stream) = resolver
            .resolve_request()
            .await
            .context("resolve H3 request")?;
        if is_tunnel_request(&request, authority, path) {
            let webtransport = Arc::new(
                WebTransportSession::accept(request, stream, http3)
                    .await
                    .context("accept WebTransport session")?,
            );
            let reliable = accept_reliable_stream(&webtransport, decoy_root.clone()).await?;
            let (recv, send) = tokio::io::split(reliable);
            let request_session = webtransport.clone();
            let request_connection = connection.clone();
            tokio::spawn(async move {
                serve_session_requests(request_session, decoy_root).await;
                request_connection.close(VarInt::from_u32(0), b"session request loop closed");
            });
            return Ok(Some(Session {
                connection,
                webtransport,
                send,
                recv,
                peer,
            }));
        }
        serve_decoy_request(request, stream, decoy_root.clone()).await?;
    }
}

async fn accept_reliable_stream(
    session: &Arc<WebTransportConnection>,
    decoy_root: Arc<PathBuf>,
) -> Result<WebTransportStream> {
    loop {
        match session.accept_bi().await? {
            Some(AcceptedBi::BidiStream(session_id, stream))
                if session_id == session.session_id() =>
            {
                return Ok(stream);
            }
            Some(AcceptedBi::BidiStream(_, mut stream)) => {
                let _ = stream.shutdown().await;
            }
            Some(AcceptedBi::Request(request, stream)) => {
                serve_decoy_request(request, stream, decoy_root.clone()).await?;
            }
            None => bail!("WebTransport session closed before reliable stream"),
        }
    }
}

async fn serve_session_requests(session: Arc<WebTransportConnection>, decoy_root: Arc<PathBuf>) {
    let requests = Arc::new(Semaphore::new(MAX_H3_DECOY_REQUESTS));
    loop {
        match session.accept_bi().await {
            Ok(Some(AcceptedBi::Request(request, stream))) => {
                let root = decoy_root.clone();
                let Ok(permit) = requests.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_decoy_request(request, stream, root).await {
                        warn!(reason = %error, "H3 decoy request failed");
                    }
                });
            }
            Ok(Some(AcceptedBi::BidiStream(_, mut stream))) => {
                let _ = stream.shutdown().await;
            }
            Ok(None) => return,
            Err(error) => {
                if error.to_string().to_ascii_lowercase().contains("closed") {
                    info!(reason = %error, "H3 session request loop closed");
                } else {
                    warn!(reason = %error, "H3 session request loop failed");
                }
                return;
            }
        }
    }
}

fn is_tunnel_request(request: &Request<()>, authority: &str, path: &str) -> bool {
    request.method() == Method::CONNECT
        && request
            .extensions()
            .get::<Protocol>()
            .is_some_and(|protocol| protocol == &Protocol::WEB_TRANSPORT)
        && request.uri().path() == path
        && request
            .uri()
            .authority()
            .is_some_and(|received| authority_matches(received.as_str(), authority))
}

fn authority_matches(received: &str, expected: &str) -> bool {
    received.eq_ignore_ascii_case(expected)
        || received
            .strip_suffix(":443")
            .is_some_and(|value| value.eq_ignore_ascii_case(expected))
        || expected
            .strip_suffix(":443")
            .is_some_and(|value| value.eq_ignore_ascii_case(received))
}

async fn serve_decoy_request(
    request: Request<()>,
    mut stream: Http3RequestStream,
    root: Arc<PathBuf>,
) -> Result<()> {
    let method = request.method().clone();
    let path = request.uri().path();
    let file = if method == Method::GET || method == Method::HEAD {
        read_decoy_file(&root, path).await?
    } else {
        None
    };
    let status = if method != Method::GET && method != Method::HEAD {
        StatusCode::METHOD_NOT_ALLOWED
    } else if file.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    let body = file
        .as_ref()
        .map_or_else(Bytes::new, |value| value.0.clone());
    let content_type = file
        .as_ref()
        .map_or("text/plain; charset=utf-8", |value| value.1);
    let response = Response::builder()
        .status(status)
        .header("alt-svc", "h3=\":443\"; ma=2592000")
        .header("content-length", body.len().to_string())
        .header("content-type", content_type)
        .header(
            "permissions-policy",
            "camera=(), geolocation=(), microphone=()",
        )
        .header("referrer-policy", "strict-origin-when-cross-origin")
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "DENY")
        .body(())?;
    stream.send_response(response).await?;
    if method != Method::HEAD && !body.is_empty() {
        stream.send_data(body).await?;
    }
    stream.finish().await?;
    Ok(())
}

async fn read_decoy_file(root: &Path, request_path: &str) -> Result<Option<(Bytes, &'static str)>> {
    let relative = request_path.trim_start_matches('/');
    let relative = if relative.is_empty() {
        Path::new("index.html")
    } else {
        Path::new(relative)
    };
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Ok(None);
    }
    let candidate = root.join(relative);
    let canonical = match tokio::fs::canonicalize(&candidate).await {
        Ok(value) if value.starts_with(root) => value,
        _ => return Ok(None),
    };
    let metadata = tokio::fs::metadata(&canonical).await?;
    let canonical = if metadata.is_dir() {
        canonical.join("index.html")
    } else {
        canonical
    };
    let canonical = match tokio::fs::canonicalize(&canonical).await {
        Ok(value) if value.starts_with(root) => value,
        _ => return Ok(None),
    };
    let metadata = tokio::fs::metadata(&canonical).await?;
    if !metadata.is_file() || metadata.len() > MAX_DECOY_FILE_SIZE {
        return Ok(None);
    }
    let body = match tokio::fs::read(&canonical).await {
        Ok(value) => Bytes::from(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    Ok(Some((body, content_type(&canonical))))
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|value| value.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("cbor") => "application/cose",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}
