use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, bail};
use bytes::Buf;
use h3_quinn::quinn::{self, crypto::rustls::QuicClientConfig};
use http::{Method, Request, Uri};
use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut args = std::env::args().skip(1);
    let uri: Uri = args.next().context("missing URI")?.parse()?;
    let address: SocketAddr = args.next().context("missing address")?.parse()?;
    if args.next().is_some() {
        bail!("unexpected argument");
    }
    let authority = uri.authority().context("URI authority is missing")?;
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        roots.add(certificate)?;
    }
    if roots.is_empty() {
        bail!("native certificate store is empty");
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.enable_early_data = false;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
    )));
    let connection = endpoint.connect(address, authority.host())?.await?;
    let (mut driver, mut requests) =
        h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
    let driver_task =
        tokio::spawn(
            async move { std::future::poll_fn(|context| driver.poll_close(context)).await },
        );
    let request = Request::builder().method(Method::GET).uri(uri).body(())?;
    let mut stream = requests.send_request(request).await?;
    stream.finish().await?;
    let response = stream.recv_response().await?;
    let status = response.status();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    println!(
        "status={} content_type={} bytes={} sha256={:x}",
        status.as_u16(),
        content_type,
        body.len(),
        Sha256::digest(&body)
    );
    drop(stream);
    drop(requests);
    connection.close(quinn::VarInt::from_u32(0), b"done");
    let _ = driver_task.await;
    endpoint.wait_idle().await;
    Ok(())
}
