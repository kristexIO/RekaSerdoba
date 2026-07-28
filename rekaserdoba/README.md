# RekaSerdoba server

Rust implementation of the `RekaSerdoba/1` research protocol for Ubuntu 22.04.

The server provides:

- WebTransport/HTTP/3 on UDP/443;
- streaming HTTP/2 and Secure WebSocket carriers behind Caddy on TCP/443;
- mutually authenticated X25519/Ed25519 handshake;
- ChaCha20-Poly1305 data and control records;
- per-epoch anti-replay windows;
- routine and full signed ephemeral rekey;
- carrier migration;
- IPv4 TUN routing through a privilege-separated network helper;
- signed deterministic CBOR/COSE manifests and identity rotation tools.

## Build and test

```bash
cargo fmt --check
cargo test --locked
cargo build --locked --release
```

The release build produces:

- `rekaserdoba-server`;
- `rekaserdoba-net-helper`;
- `h3_bridge`;
- `h3_get`.

## Tools

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r tools/requirements.txt

python tools/registry.py --help
python tools/manifest.py --help
python tools/identity.py --help
python tools/probe.py --help
```

`probe.py` exercises handshake, encrypted records, TUN forwarding, fragmentation, routine rekey, full rekey and optional carrier migration.

## Deployment

See [../docs/DEPLOYMENT.md](../docs/DEPLOYMENT.md) and the templates in [../deploy](../deploy).

Never commit a real `server.json`, manifest authority seed, registry, TLS private key or device bundle.

## Maturity

This is research software. Independent cryptographic audit, differential decoding and a long-running fuzz/chaos release gate are still pending.

Licensed under the [MIT License](../LICENSE).
