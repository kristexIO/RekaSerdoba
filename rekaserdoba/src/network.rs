use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;
use tracing::warn;
use tun_rs::{AsyncDevice, DeviceBuilder};

#[derive(Clone, Deserialize)]
pub struct TunSettings {
    pub name: String,
    pub address: String,
    pub prefix_len: u8,
    pub mtu: u16,
    pub session_queue: usize,
    #[serde(default)]
    pub helper_socket: Option<String>,
    #[serde(default)]
    pub helper_client_socket: Option<String>,
}

#[derive(Clone)]
pub struct Network {
    device: Arc<PacketDevice>,
    registry: Arc<Registry>,
    session_queue: usize,
}

enum PacketDevice {
    Tun(AsyncDevice),
    Helper(HelperDevice),
}

struct HelperDevice {
    socket: UnixDatagram,
    client_path: PathBuf,
}

struct Registry {
    next_id: AtomicU64,
    sessions: RwLock<HashMap<[u8; 4], RegisteredSession>>,
}

struct RegisteredSession {
    id: u64,
    outbound: mpsc::Sender<Vec<u8>>,
}

pub struct SessionLease {
    ip: [u8; 4],
    id: u64,
    registry: Arc<Registry>,
}

impl Network {
    pub fn create(settings: &TunSettings) -> Result<Self> {
        if settings.name.is_empty() || settings.name.len() > 15 {
            bail!("invalid TUN interface name");
        }
        if !(576..=9000).contains(&settings.mtu) {
            bail!("invalid TUN MTU");
        }
        if !(8..=4096).contains(&settings.session_queue) {
            bail!("invalid session queue size");
        }
        let address: Ipv4Addr = settings
            .address
            .parse()
            .context("invalid TUN IPv4 address")?;
        let device = if let Some(helper_socket) = &settings.helper_socket {
            let client_socket = settings
                .helper_client_socket
                .as_ref()
                .context("helper_client_socket is required")?;
            let client_path = PathBuf::from(client_socket);
            match std::fs::remove_file(&client_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("remove stale helper client socket"),
            }
            let socket = UnixDatagram::bind(&client_path).context("bind helper client socket")?;
            socket
                .connect(helper_socket)
                .context("connect network helper socket")?;
            PacketDevice::Helper(HelperDevice {
                socket,
                client_path,
            })
        } else {
            let device = DeviceBuilder::new()
                .name(&settings.name)
                .ipv4(address, settings.prefix_len, None)
                .mtu(settings.mtu)
                .build_async()
                .context("create TUN interface")?;
            PacketDevice::Tun(device)
        };
        Ok(Self {
            device: Arc::new(device),
            registry: Arc::new(Registry {
                next_id: AtomicU64::new(1),
                sessions: RwLock::new(HashMap::new()),
            }),
            session_queue: settings.session_queue,
        })
    }

    pub fn spawn_reader(&self) {
        let network = self.clone();
        tokio::spawn(async move {
            if let PacketDevice::Helper(device) = network.device.as_ref()
                && let Err(error) = device.socket.send(b"RSN1").await
            {
                warn!(reason = %error, "network helper registration failed");
                return;
            }
            let mut buffer = vec![0u8; 65536];
            loop {
                let received = match network.device.as_ref() {
                    PacketDevice::Tun(device) => device.recv(&mut buffer).await,
                    PacketDevice::Helper(device) => device.socket.recv(&mut buffer).await,
                };
                match received {
                    Ok(length) => {
                        if let Some(destination) = ipv4_destination(&buffer[..length]) {
                            network.route_to_session(destination, &buffer[..length]);
                        }
                    }
                    Err(error) => {
                        warn!(reason = %error, "TUN receive failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
    }

    pub fn register(&self, ip: [u8; 4]) -> Result<(SessionLease, mpsc::Receiver<Vec<u8>>)> {
        let (sender, receiver) = mpsc::channel(self.session_queue);
        let id = self.registry.next_id.fetch_add(1, Ordering::Relaxed);
        let mut sessions = self
            .registry
            .sessions
            .write()
            .map_err(|_| anyhow!("session registry poisoned"))?;
        if sessions.contains_key(&ip) {
            bail!("client already has an active session");
        }
        sessions.insert(
            ip,
            RegisteredSession {
                id,
                outbound: sender,
            },
        );
        Ok((
            SessionLease {
                ip,
                id,
                registry: self.registry.clone(),
            },
            receiver,
        ))
    }

    pub async fn send_to_kernel(&self, packet: &[u8]) -> Result<()> {
        let written = match self.device.as_ref() {
            PacketDevice::Tun(device) => device.send(packet).await,
            PacketDevice::Helper(device) => device.socket.send(packet).await,
        }
        .context("network helper send failed")?;
        if written != packet.len() {
            bail!("partial network packet write");
        }
        Ok(())
    }

    fn route_to_session(&self, destination: [u8; 4], packet: &[u8]) {
        let Ok(sessions) = self.registry.sessions.read() else {
            return;
        };
        let Some(session) = sessions.get(&destination) else {
            return;
        };
        let _ = session.outbound.try_send(packet.to_vec());
    }
}

impl Drop for HelperDevice {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.client_path);
    }
}

impl Drop for SessionLease {
    fn drop(&mut self) {
        let Ok(mut sessions) = self.registry.sessions.write() else {
            return;
        };
        if sessions
            .get(&self.ip)
            .is_some_and(|session| session.id == self.id)
        {
            sessions.remove(&self.ip);
        }
    }
}

fn ipv4_destination(packet: &[u8]) -> Option<[u8; 4]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes(packet.get(2..4)?.try_into().ok()?) as usize;
    if header_len < 20 || header_len > packet.len() || total_len != packet.len() {
        return None;
    }
    packet.get(16..20)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_valid_ipv4_destination() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&20u16.to_be_bytes());
        packet[16..20].copy_from_slice(&[10, 77, 0, 2]);
        assert_eq!(ipv4_destination(&packet), Some([10, 77, 0, 2]));
    }

    #[test]
    fn rejects_malformed_ipv4_packet() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&21u16.to_be_bytes());
        assert_eq!(ipv4_destination(&packet), None);
    }
}
