use std::{
    collections::HashMap,
    io::ErrorKind,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;
use tracing::warn;
use tun_rs::{AsyncDevice, DeviceBuilder};

const HELPER_REGISTRATION: &[u8; 4] = b"RSN1";
const HELPER_ACKNOWLEDGEMENT: &[u8; 4] = b"RSA1";
const HELPER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HELPER_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const HELPER_REGISTRATION_INTERVAL: Duration = Duration::from_secs(1);

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
    ready: Arc<AtomicBool>,
    registration_pending: Arc<AtomicBool>,
    received_packets: Arc<AtomicU64>,
    routed_packets: Arc<AtomicU64>,
    unrouted_packets: Arc<AtomicU64>,
    invalid_packets: Arc<AtomicU64>,
    dropped_packets: Arc<AtomicU64>,
}

enum PacketDevice {
    Tun(AsyncDevice),
    Helper(HelperDevice),
}

struct HelperDevice {
    socket: UnixDatagram,
    client_path: PathBuf,
    server_path: PathBuf,
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
    pub fn validate_settings(settings: &TunSettings) -> Result<()> {
        if settings.name.is_empty() || settings.name.len() > 15 {
            bail!("invalid TUN interface name");
        }
        if !(576..=9000).contains(&settings.mtu) {
            bail!("invalid TUN MTU");
        }
        if !(8..=4096).contains(&settings.session_queue) {
            bail!("invalid session queue size");
        }
        let _: Ipv4Addr = settings
            .address
            .parse()
            .context("invalid TUN IPv4 address")?;
        if !(1..=30).contains(&settings.prefix_len) {
            bail!("invalid TUN prefix length");
        }
        match (&settings.helper_socket, &settings.helper_client_socket) {
            (Some(server), Some(client)) if server != client => {}
            (Some(_), Some(_)) => bail!("helper socket paths must be different"),
            (Some(_), None) => bail!("helper_client_socket is required"),
            (None, Some(_)) => bail!("helper_socket is required"),
            (None, None) => {}
        }
        Ok(())
    }

    pub fn create(settings: &TunSettings) -> Result<Self> {
        Self::validate_settings(settings)?;
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
            let server_path = PathBuf::from(helper_socket);
            match std::fs::remove_file(&client_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("remove stale helper client socket"),
            }
            let socket = UnixDatagram::bind(&client_path).context("bind helper client socket")?;
            if let Err(error) = connect_helper(&socket, &server_path) {
                drop(socket);
                let _ = std::fs::remove_file(&client_path);
                return Err(error);
            }
            PacketDevice::Helper(HelperDevice {
                socket,
                client_path,
                server_path,
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
        let ready = matches!(&device, PacketDevice::Tun(_));
        Ok(Self {
            device: Arc::new(device),
            registry: Arc::new(Registry {
                next_id: AtomicU64::new(1),
                sessions: RwLock::new(HashMap::new()),
            }),
            session_queue: settings.session_queue,
            ready: Arc::new(AtomicBool::new(ready)),
            registration_pending: Arc::new(AtomicBool::new(false)),
            received_packets: Arc::new(AtomicU64::new(0)),
            routed_packets: Arc::new(AtomicU64::new(0)),
            unrouted_packets: Arc::new(AtomicU64::new(0)),
            invalid_packets: Arc::new(AtomicU64::new(0)),
            dropped_packets: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn spawn_reader(&self) -> tokio::task::JoinHandle<()> {
        let network = self.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65536];
            match network.device.as_ref() {
                PacketDevice::Tun(device) => loop {
                    match device.recv(&mut buffer).await {
                        Ok(length) => {
                            network.ready.store(true, Ordering::Relaxed);
                            network.received_packets.fetch_add(1, Ordering::Relaxed);
                            if let Some(destination) = ipv4_destination(&buffer[..length]) {
                                network.route_to_session(destination, &buffer[..length]);
                            } else {
                                network.invalid_packets.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(error) => {
                            network.ready.store(false, Ordering::Relaxed);
                            warn!(reason = %error, "TUN receive failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                },
                PacketDevice::Helper(device) => {
                    let mut registration = tokio::time::interval(HELPER_REGISTRATION_INTERVAL);
                    registration.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    let mut registration_failed = false;
                    let mut receive_failed = false;
                    loop {
                        tokio::select! {
                            _ = registration.tick() => {
                                if network.registration_pending.swap(true, Ordering::Relaxed) {
                                    network.ready.store(false, Ordering::Relaxed);
                                }
                                match device.socket.connect(&device.server_path) {
                                    Ok(()) => {
                                        match device.socket.send(HELPER_REGISTRATION).await {
                                            Ok(length) if length == HELPER_REGISTRATION.len() => {
                                                registration_failed = false;
                                            }
                                            Ok(_) => {
                                                network.ready.store(false, Ordering::Relaxed);
                                                if !registration_failed {
                                                    warn!("partial network helper registration");
                                                }
                                                registration_failed = true;
                                            }
                                            Err(error) => {
                                                network.ready.store(false, Ordering::Relaxed);
                                                if !registration_failed {
                                                    warn!(reason = %error, "network helper registration failed");
                                                }
                                                registration_failed = true;
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        network.ready.store(false, Ordering::Relaxed);
                                        if !registration_failed {
                                            warn!(reason = %error, "network helper reconnect failed");
                                        }
                                        registration_failed = true;
                                    }
                                }
                            }
                            received = device.socket.recv(&mut buffer) => {
                                match received {
                                    Ok(length) if &buffer[..length] == HELPER_ACKNOWLEDGEMENT => {
                                        network.registration_pending.store(false, Ordering::Relaxed);
                                        network.ready.store(true, Ordering::Relaxed);
                                        receive_failed = false;
                                    }
                                    Ok(length) => {
                                        receive_failed = false;
                                        network.received_packets.fetch_add(1, Ordering::Relaxed);
                                        match ipv4_destination(&buffer[..length]) {
                                            Some(destination) => {
                                                network.route_to_session(destination, &buffer[..length]);
                                            }
                                            None => {
                                                network.invalid_packets.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        network.ready.store(false, Ordering::Relaxed);
                                        if !receive_failed {
                                            warn!(reason = %error, "network helper receive failed");
                                        }
                                        receive_failed = true;
                                        tokio::time::sleep(Duration::from_millis(250)).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
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
            PacketDevice::Helper(device) => match device.socket.send(packet).await {
                Ok(written) => Ok(written),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    ) =>
                {
                    self.ready.store(false, Ordering::Relaxed);
                    device
                        .socket
                        .connect(&device.server_path)
                        .context("reconnect network helper socket")?;
                    device.socket.send(packet).await
                }
                Err(error) => Err(error),
            },
        }
        .context("network helper send failed")?;
        if written != packet.len() {
            bail!("partial network packet write");
        }
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets.load(Ordering::Relaxed)
    }

    pub fn received_packets(&self) -> u64 {
        self.received_packets.load(Ordering::Relaxed)
    }

    pub fn routed_packets(&self) -> u64 {
        self.routed_packets.load(Ordering::Relaxed)
    }

    pub fn unrouted_packets(&self) -> u64 {
        self.unrouted_packets.load(Ordering::Relaxed)
    }

    pub fn invalid_packets(&self) -> u64 {
        self.invalid_packets.load(Ordering::Relaxed)
    }

    fn route_to_session(&self, destination: [u8; 4], packet: &[u8]) {
        let Ok(sessions) = self.registry.sessions.read() else {
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(session) = sessions.get(&destination) else {
            self.unrouted_packets.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if session.outbound.try_send(packet.to_vec()).is_err() {
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        } else {
            self.routed_packets.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn connect_helper(socket: &UnixDatagram, helper_socket: &Path) -> Result<()> {
    let deadline = Instant::now() + HELPER_CONNECT_TIMEOUT;
    loop {
        match socket.connect(helper_socket) {
            Ok(()) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) && Instant::now() < deadline =>
            {
                thread::sleep(HELPER_RETRY_INTERVAL);
            }
            Err(error) => return Err(error).context("connect network helper socket"),
        }
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
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[tokio::test]
    async fn reconnects_after_helper_rebind() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("rekaserdoba-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let helper_path = directory.join("helper.sock");
        let client_path = directory.join("client.sock");
        let first = UnixDatagram::bind(&helper_path).unwrap();
        let client = UnixDatagram::bind(&client_path).unwrap();
        connect_helper(&client, &helper_path).unwrap();
        client.send(b"first").await.unwrap();
        let mut buffer = [0u8; 16];
        assert_eq!(first.recv(&mut buffer).await.unwrap(), 5);
        drop(first);
        std::fs::remove_file(&helper_path).unwrap();
        let second = UnixDatagram::bind(&helper_path).unwrap();
        client.connect(&helper_path).unwrap();
        client.send(b"second").await.unwrap();
        assert_eq!(second.recv(&mut buffer).await.unwrap(), 6);
        drop(client);
        drop(second);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
