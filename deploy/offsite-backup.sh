set -euo pipefail

test "$(id -u)" -eq 0
source /etc/rekaserdoba/offsite-backup
[[ "$AGE_RECIPIENT" =~ ^age1[0-9a-z]+$ ]]
[[ "$RCLONE_REMOTE" =~ ^[A-Za-z0-9._-]+:.+$ ]]
backup=$(find /var/backups/rekaserdoba -mindepth 1 -maxdepth 1 -type d -name '20??????T??????Z' -printf '%T@ %p\n' | sort -nr | head -n1 | cut -d' ' -f2-)
backup=$(realpath "$backup")
[[ "$backup" =~ ^/var/backups/rekaserdoba/20[0-9]{6}T[0-9]{6}Z$ ]]
bash /usr/local/libexec/rekaserdoba-verify-backup "$backup"
name=$(basename "$backup")
target="${RCLONE_REMOTE%/}/$name.tar.age"
tar -C /var/backups/rekaserdoba -cf - "$name" | age -r "$AGE_RECIPIENT" | rclone rcat "$target"
rclone size "$target" --json | jq -e '.bytes > 0' >/dev/null
printf '%s\n' "$target"
