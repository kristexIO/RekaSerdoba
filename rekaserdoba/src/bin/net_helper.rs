use std::{
    net::Ipv4Addr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use tokio::net::UnixDatagram;
use tun_rs::DeviceBuilder;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let name = args.next().context("missing TUN name")?;
    let address: Ipv4Addr = args.next().context("missing TUN address")?.parse()?;
    let prefix: u8 = args.next().context("missing TUN prefix")?.parse()?;
    let mtu: u16 = args.next().context("missing TUN MTU")?.parse()?;
    let server_path = PathBuf::from(args.next().context("missing helper socket")?);
    let client_path = PathBuf::from(args.next().context("missing edge socket")?);
    if args.next().is_some() {
        bail!("unexpected argument");
    }
    if name.is_empty() || name.len() > 15 || prefix > 32 || !(576..=9000).contains(&mtu) {
        bail!("invalid network helper configuration");
    }
    let device = DeviceBuilder::new()
        .name(name)
        .ipv4(address, prefix, None)
        .mtu(mtu)
        .build_async()
        .context("create helper TUN")?;
    remove_socket(&server_path)?;
    let socket = UnixDatagram::bind(&server_path).context("bind helper socket")?;
    std::fs::set_permissions(&server_path, std::fs::Permissions::from_mode(0o660))?;
    drop_capabilities()?;
    let network = u32::from(address) & prefix_mask(prefix);
    let mut edge_registered = false;
    let mut tun_buffer = vec![0u8; 65536];
    let mut edge_buffer = vec![0u8; 65536];
    loop {
        tokio::select! {
            received = device.recv(&mut tun_buffer) => {
                let length = received.context("read helper TUN")?;
                if edge_registered {
                    socket
                        .send_to(&tun_buffer[..length], &client_path)
                        .await
                        .context("send packet to edge")?;
                }
            }
            received = socket.recv_from(&mut edge_buffer) => {
                let (length, source) = received.context("receive packet from edge")?;
                if source.as_pathname() != Some(client_path.as_path()) {
                    continue;
                }
                if &edge_buffer[..length] == b"RSN1" {
                    edge_registered = true;
                    continue;
                }
                if !edge_registered
                    || !valid_ipv4(&edge_buffer[..length], network, prefix, mtu as usize)
                {
                    continue;
                }
                let written = device
                    .send(&edge_buffer[..length])
                    .await
                    .context("write helper TUN")?;
                if written != length {
                    bail!("partial helper TUN write");
                }
            }
        }
    }
}

fn remove_socket(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove stale helper socket"),
    }
}

fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn valid_ipv4(packet: &[u8], network: u32, prefix: u8, mtu: usize) -> bool {
    if packet.len() < 20 || packet.len() > mtu || packet[0] >> 4 != 4 {
        return false;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if header_len < 20 || header_len > packet.len() || total_len != packet.len() {
        return false;
    }
    let source = u32::from_be_bytes(packet[12..16].try_into().unwrap());
    source & prefix_mask(prefix) == network
}

fn drop_capabilities() -> Result<()> {
    use caps::CapSet;

    caps::clear(None, CapSet::Ambient).context("clear ambient capabilities")?;
    caps::clear(None, CapSet::Effective).context("clear effective capabilities")?;
    caps::clear(None, CapSet::Inheritable).context("clear inheritable capabilities")?;
    caps::clear(None, CapSet::Permitted).context("clear permitted capabilities")?;
    Ok(())
}
