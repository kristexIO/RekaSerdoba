set -euo pipefail

test "$(id -u)" -eq 0
source_dir=$(realpath "${1:-deploy}")
test -f /etc/rekaserdoba/offsite-backup
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y age rclone
install -m 0755 "$source_dir/offsite-backup.sh" /usr/local/libexec/rekaserdoba-offsite-backup
install -m 0755 "$source_dir/verify-backup.sh" /usr/local/libexec/rekaserdoba-verify-backup
install -m 0644 "$source_dir/rekaserdoba-offsite-backup.service" /etc/systemd/system/rekaserdoba-offsite-backup.service
install -m 0644 "$source_dir/rekaserdoba-offsite-backup.timer" /etc/systemd/system/rekaserdoba-offsite-backup.timer
systemctl daemon-reload
systemctl enable --now rekaserdoba-offsite-backup.timer
systemctl start rekaserdoba-offsite-backup.service
