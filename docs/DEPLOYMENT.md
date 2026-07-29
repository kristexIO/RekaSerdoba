# Deployment guide

This guide describes the shape of a deployment, not a universal one-command production installer. Review interface names, firewall policy, certificate paths and secret handling for your environment.

## Prerequisites

- Ubuntu 22.04 server with TCP/80, TCP/443 and UDP/443 reachable;
- a domain pointing to the server;
- Rust stable toolchain;
- Python 3.12 for provisioning tools;
- Caddy with a valid WebPKI certificate;
- Windows 10/11 x64 for the client.

## 1. Build the server

```bash
git clone https://github.com/kristexIO/RekaSerdoba.git
cd RekaSerdoba/rekaserdoba
cargo test --locked
REKASERDOBA_BUILD_SHA="$(git rev-parse HEAD)" cargo build --locked --release
```

Install the two privileged components separately:

```bash
sudo install -m 0755 target/release/rekaserdoba-server /opt/rekaserdoba/bin/
sudo install -m 0755 target/release/rekaserdoba-net-helper /opt/rekaserdoba/bin/
```

## 2. Bootstrap the host

Read `deploy/bootstrap-ubuntu.sh` before running it. The reference firewall assumes:

- public interface `ens3`;
- tunnel network `10.77.0.0/24`;
- tunnel interface `reka0`.

Change these values before execution when your host differs.

```bash
sudo bash deploy/bootstrap-ubuntu.sh
```

## 3. Create identities and device bundles

Install tool dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r rekaserdoba/tools/requirements.txt
```

The provisioning commands are self-documenting:

```bash
python rekaserdoba/tools/registry.py --help
python rekaserdoba/tools/manifest.py --help
python rekaserdoba/tools/identity.py --help
```

Start from [examples/server.example.json](../examples/server.example.json). Generate fresh values with a cryptographically secure tool; never copy values from screenshots, logs or another deployment.

Store these files outside the Git checkout:

- `server.json`;
- manifest authority seed;
- registry;
- each client bundle;
- TLS private key;
- backup exports.

Recommended permissions:

```bash
sudo chown root:rekaserdoba /etc/rekaserdoba/server.json
sudo chmod 0640 /etc/rekaserdoba/server.json
```

## 4. Configure services

Review and install the templates:

```bash
sudo install -m 0644 deploy/rekaserdoba-net-helper.service /etc/systemd/system/
sudo install -m 0644 deploy/rekaserdoba.service /etc/systemd/system/
sudo install -m 0644 deploy/rekaserdoba-health.service /etc/systemd/system/
sudo install -m 0644 deploy/rekaserdoba-health.timer /etc/systemd/system/
sudo install -m 0755 deploy/rekaserdoba-health-check /usr/local/libexec/
sudo systemctl daemon-reload
sudo systemctl enable --now rekaserdoba-net-helper.service
sudo systemctl enable --now rekaserdoba.service
sudo systemctl enable --now rekaserdoba-health.timer
```

The network helper owns `RuntimeDirectory=rekaserdoba`. The edge service deliberately does not, so restarting the edge cannot unlink the helper socket.

## 5. Configure Caddy

Replace the reference domain in `deploy/Caddyfile` and certificate synchronization units. Validate before reload:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Publish the generated signed manifest at:

```text
https://your-domain.example/.well-known/rekaserdoba/manifest.cbor
```

## 6. Validate the server

```bash
systemctl is-active rekaserdoba
systemctl is-active rekaserdoba-net-helper
curl --fail http://127.0.0.1:9080/healthz
curl --fail http://127.0.0.1:9080/readyz
journalctl -u rekaserdoba -n 100 --no-pager
```

Run the protocol probe using a test-only bundle:

```bash
python rekaserdoba/tools/probe.py /secure/test-client-bundle.json \
  --carrier h3 \
  --h3-bridge rekaserdoba/target/release/h3_bridge \
  --ip YOUR_SERVER_IP
```

## 7. Build the Windows client

Place the official `wintun.dll` and a Windows `h3_bridge.exe` in `windows-client/`. Keep the personalized bundle outside the repository.

```powershell
.\windows-client\build.ps1 `
  -Bundle C:\secure\client-bundle.json `
  -Python C:\Python312\python.exe
```

The setup executable embeds the selected bundle. Treat every built installer as a secret-bearing personalized artifact.

## Rollback

Create a checksummed release directory and deploy it atomically:

```bash
bash deploy/package-release.sh rekaserdoba/target/release /secure/release "$(git rev-parse HEAD)"
sudo bash deploy/deploy-release.sh /secure/release
```

The deploy command prints the backup path. To verify and restore it:

```bash
sudo bash deploy/verify-backup.sh /var/backups/rekaserdoba/YYYYMMDDTHHMMSSZ
sudo bash deploy/rollback-release.sh /var/backups/rekaserdoba/YYYYMMDDTHHMMSSZ
```

Never roll back identity state or manifest sequence without also handling client anti-rollback state.
