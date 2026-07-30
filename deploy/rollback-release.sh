set -euo pipefail

backup=$(realpath "${1:?backup directory is required}")
[[ "$backup" =~ ^/var/backups/rekaserdoba/[0-9]{8}T[0-9]{6}Z$ ]]
test "$(id -u)" -eq 0
test -f "$backup/SHA256SUMS"
(
    cd "$backup"
    sha256sum --check --strict SHA256SUMS
)
install -m 0755 "$backup/bin/rekaserdoba-server" /opt/rekaserdoba/bin/rekaserdoba-server.new
install -m 0755 "$backup/bin/rekaserdoba-net-helper" /opt/rekaserdoba/bin/rekaserdoba-net-helper.new
mv -f /opt/rekaserdoba/bin/rekaserdoba-server.new /opt/rekaserdoba/bin/rekaserdoba-server
mv -f /opt/rekaserdoba/bin/rekaserdoba-net-helper.new /opt/rekaserdoba/bin/rekaserdoba-net-helper
test ! -f "$backup/bin/h3_bridge" || install -m 0755 "$backup/bin/h3_bridge" /opt/rekaserdoba/bin/h3_bridge
cp --preserve=mode,ownership,timestamps "$backup/etc/rekaserdoba/server.json" /etc/rekaserdoba/server.json.new
mv -f /etc/rekaserdoba/server.json.new /etc/rekaserdoba/server.json
install -m 0644 "$backup/systemd/rekaserdoba.service" /etc/systemd/system/rekaserdoba.service
install -m 0644 "$backup/systemd/rekaserdoba-net-helper.service" /etc/systemd/system/rekaserdoba-net-helper.service
test ! -f "$backup/systemd/rekaserdoba-health.service" || install -m 0644 "$backup/systemd/rekaserdoba-health.service" /etc/systemd/system/rekaserdoba-health.service
test ! -f "$backup/systemd/rekaserdoba-health.timer" || install -m 0644 "$backup/systemd/rekaserdoba-health.timer" /etc/systemd/system/rekaserdoba-health.timer
test ! -f "$backup/systemd/rekaserdoba-recover.service" || install -m 0644 "$backup/systemd/rekaserdoba-recover.service" /etc/systemd/system/rekaserdoba-recover.service
if test -f "$backup/systemd/rekaserdoba-maintenance.service"; then
    install -m 0644 "$backup/systemd/rekaserdoba-maintenance.service" /etc/systemd/system/rekaserdoba-maintenance.service
else
    rm -f /etc/systemd/system/rekaserdoba-maintenance.service
fi
if test -f "$backup/systemd/rekaserdoba-maintenance.timer"; then
    install -m 0644 "$backup/systemd/rekaserdoba-maintenance.timer" /etc/systemd/system/rekaserdoba-maintenance.timer
else
    systemctl disable --now rekaserdoba-maintenance.timer >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/rekaserdoba-maintenance.timer
fi
install -d -o root -g root -m 0755 /usr/local/libexec
test ! -f "$backup/libexec/rekaserdoba-health-check" || install -m 0755 "$backup/libexec/rekaserdoba-health-check" /usr/local/libexec/rekaserdoba-health-check
if test -f "$backup/libexec/rekaserdoba-maintenance"; then
    install -m 0755 "$backup/libexec/rekaserdoba-maintenance" /usr/local/libexec/rekaserdoba-maintenance
else
    rm -f /usr/local/libexec/rekaserdoba-maintenance
fi
test ! -f "$backup/sysctl/60-rekaserdoba.conf" || install -m 0644 "$backup/sysctl/60-rekaserdoba.conf" /etc/sysctl.d/60-rekaserdoba.conf
/opt/rekaserdoba/bin/rekaserdoba-server --check-config /etc/rekaserdoba/server.json
sysctl --system >/dev/null
systemctl daemon-reload
test ! -f "$backup/systemd/rekaserdoba-maintenance.timer" || systemctl enable --now rekaserdoba-maintenance.timer
systemctl restart rekaserdoba-net-helper.service
systemctl restart rekaserdoba.service
systemctl reset-failed rekaserdoba-health.service
systemctl start rekaserdoba-health.service
curl --retry 20 --retry-all-errors --retry-delay 1 --fail --silent --show-error --max-time 3 http://127.0.0.1:9080/readyz >/dev/null
