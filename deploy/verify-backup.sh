set -euo pipefail

backup=$(realpath "${1:?backup directory is required}")
[[ "$backup" =~ ^/var/backups/rekaserdoba/[0-9]{8}T[0-9]{6}Z$ ]]
test -d "$backup"
test -f "$backup/SHA256SUMS"
(
    cd "$backup"
    sha256sum --check --strict SHA256SUMS
)
test -s "$backup/bin/rekaserdoba-server"
test -s "$backup/bin/rekaserdoba-net-helper"
test -s "$backup/etc/rekaserdoba/server.json"
jq -e '.listen and .authority and .server_signing_seed_b64 and .tun and .clients' "$backup/etc/rekaserdoba/server.json" >/dev/null
