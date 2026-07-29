#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  ca-certificates \
  curl \
  fail2ban \
  jq \
  nftables \
  unattended-upgrades

if ! id -u rekaserdoba >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/rekaserdoba --create-home \
    --shell /usr/sbin/nologin rekaserdoba
fi

install -d -o root -g rekaserdoba -m 0750 /etc/rekaserdoba
install -d -o rekaserdoba -g rekaserdoba -m 0750 /var/lib/rekaserdoba
install -d -o rekaserdoba -g rekaserdoba -m 0750 /var/log/rekaserdoba
install -d -o root -g root -m 0755 /opt/rekaserdoba/bin
install -d -o root -g root -m 0755 /var/www/rekaserdoba

cat >/etc/sysctl.d/60-rekaserdoba.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.forwarding = 0
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.netdev_max_backlog = 4096
EOF
sysctl --system >/dev/null

cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    ip6 nexthdr ipv6-icmp accept
    iifname "reka0" ip saddr 10.77.0.0/24 ip daddr 10.77.0.1 icmp type echo-request accept
    tcp dport 22 ct state new limit rate 30/minute burst 15 packets accept
    tcp dport { 80, 443 } accept
    udp dport 443 accept
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname "reka0" oifname "ens3" ip saddr 10.77.0.0/24 accept
    iifname "ens3" oifname "reka0" ip daddr 10.77.0.0/24 ct state established,related accept
  }

  chain output {
    type filter hook output priority filter; policy accept;
  }
}

table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "ens3" ip saddr 10.77.0.0/24 masquerade
  }
}
EOF
nft -c -f /etc/nftables.conf
systemctl enable --now nftables

cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
systemctl enable --now fail2ban

cat >/etc/apt/apt.conf.d/52rekaserdoba-unattended-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

if ! swapon --show=NAME --noheadings | grep -qx '/swapfile'; then
  if [[ ! -e /swapfile ]]; then
    fallocate -l 1G /swapfile
    chmod 0600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile
fi
grep -q '^/swapfile ' /etc/fstab || printf '%s\n' '/swapfile none swap sw 0 0' >>/etc/fstab

systemctl restart fail2ban
echo "bootstrap complete"
