set -euo pipefail

release_dir=$(realpath "${1:?release directory is required}")
config=/etc/rekaserdoba/server.json
backup_root=/var/backups/rekaserdoba
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="$backup_root/$stamp"
server=/opt/rekaserdoba/bin/rekaserdoba-server
helper=/opt/rekaserdoba/bin/rekaserdoba-net-helper
bridge=/opt/rekaserdoba/bin/h3_bridge

test "$(id -u)" -eq 0
test -f "$release_dir/SHA256SUMS"
(
    cd "$release_dir"
    sha256sum --check --strict SHA256SUMS
)
expected_commit=$(cat "$release_dir/COMMIT")
version=$("$release_dir/bin/rekaserdoba-server" --version)
actual_commit=$(printf '%s\n' "$version" | awk '{print $3}')
test "$actual_commit" = "$expected_commit"
printf '%s\n' "$version"
"$release_dir/bin/rekaserdoba-server" --check-config "$config"
certificate=$(jq -er '.h3.certificate_pem' "$config")
openssl x509 -checkend 604800 -noout -in "$certificate"
systemd-analyze verify "$release_dir/systemd/rekaserdoba.service" "$release_dir/systemd/rekaserdoba-net-helper.service"

test ! -e "$backup"
install -d -o root -g root -m 0700 "$backup"
install -d -o root -g root -m 0700 "$backup/bin" "$backup/systemd" "$backup/etc" "$backup/etc/rekaserdoba" "$backup/libexec" "$backup/sysctl" "$backup/host"
install -m 0755 "$server" "$backup/bin/rekaserdoba-server"
install -m 0755 "$helper" "$backup/bin/rekaserdoba-net-helper"
test ! -f "$bridge" || install -m 0755 "$bridge" "$backup/bin/h3_bridge"
cp -aL /etc/rekaserdoba/. "$backup/etc/rekaserdoba/"
install -m 0644 /etc/systemd/system/rekaserdoba.service "$backup/systemd/rekaserdoba.service"
install -m 0644 /etc/systemd/system/rekaserdoba-net-helper.service "$backup/systemd/rekaserdoba-net-helper.service"
test ! -f /etc/systemd/system/rekaserdoba-health.service || install -m 0644 /etc/systemd/system/rekaserdoba-health.service "$backup/systemd/rekaserdoba-health.service"
test ! -f /etc/systemd/system/rekaserdoba-health.timer || install -m 0644 /etc/systemd/system/rekaserdoba-health.timer "$backup/systemd/rekaserdoba-health.timer"
test ! -f /etc/systemd/system/rekaserdoba-recover.service || install -m 0644 /etc/systemd/system/rekaserdoba-recover.service "$backup/systemd/rekaserdoba-recover.service"
test ! -f /usr/local/libexec/rekaserdoba-health-check || install -m 0755 /usr/local/libexec/rekaserdoba-health-check "$backup/libexec/rekaserdoba-health-check"
test ! -f /etc/sysctl.d/60-rekaserdoba.conf || install -m 0644 /etc/sysctl.d/60-rekaserdoba.conf "$backup/sysctl/60-rekaserdoba.conf"
test ! -f /etc/caddy/Caddyfile || install -m 0600 /etc/caddy/Caddyfile "$backup/host/Caddyfile"
test ! -f /etc/nftables.conf || install -m 0600 /etc/nftables.conf "$backup/host/nftables.conf"
test ! -f /etc/ssh/sshd_config.d/60-rekaserdoba-hardening.conf || install -m 0600 /etc/ssh/sshd_config.d/60-rekaserdoba-hardening.conf "$backup/host/60-rekaserdoba-hardening.conf"
(
    cd "$backup"
    find . -type f ! -name SHA256SUMS -print0 |
        sort -z |
        xargs -0 sha256sum >SHA256SUMS
)

rollback() {
    trap - ERR
    bash "$(dirname "$0")/rollback-release.sh" "$backup"
}
trap rollback ERR

install -m 0755 "$release_dir/bin/rekaserdoba-server" "$server.new"
install -m 0755 "$release_dir/bin/rekaserdoba-net-helper" "$helper.new"
install -m 0755 "$release_dir/bin/h3_bridge" "$bridge.new"
mv -f "$server.new" "$server"
mv -f "$helper.new" "$helper"
mv -f "$bridge.new" "$bridge"
install -m 0644 "$release_dir/systemd/rekaserdoba.service" /etc/systemd/system/rekaserdoba.service
install -m 0644 "$release_dir/systemd/rekaserdoba-net-helper.service" /etc/systemd/system/rekaserdoba-net-helper.service
install -m 0644 "$release_dir/systemd/rekaserdoba-health.service" /etc/systemd/system/rekaserdoba-health.service
install -m 0644 "$release_dir/systemd/rekaserdoba-health.timer" /etc/systemd/system/rekaserdoba-health.timer
install -m 0644 "$release_dir/systemd/rekaserdoba-recover.service" /etc/systemd/system/rekaserdoba-recover.service
install -m 0644 "$release_dir/sysctl/60-rekaserdoba.conf" /etc/sysctl.d/60-rekaserdoba.conf
install -d -o root -g root -m 0755 /usr/local/libexec
install -m 0755 "$release_dir/libexec/rekaserdoba-health-check" /usr/local/libexec/rekaserdoba-health-check
sysctl --system >/dev/null
systemctl daemon-reload
systemctl restart rekaserdoba-net-helper.service
systemctl restart rekaserdoba.service
systemctl enable --now rekaserdoba-health.timer
systemctl reset-failed rekaserdoba-health.service
systemctl start rekaserdoba-health.service

deadline=$((SECONDS + 30))
until curl --fail --silent --show-error --max-time 3 http://127.0.0.1:9080/readyz >/dev/null; do
    test "$SECONDS" -lt "$deadline"
    sleep 1
done
curl --fail --silent --show-error --max-time 10 https://messk.online/ >/dev/null
systemctl is-active --quiet rekaserdoba.service rekaserdoba-net-helper.service
bash "$(dirname "$0")/verify-backup.sh" "$backup"
trap - ERR
printf '%s\n' "$backup"
