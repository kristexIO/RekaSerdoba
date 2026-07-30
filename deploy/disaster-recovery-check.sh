set -euo pipefail

backup=$(realpath "${1:?backup directory is required}")
[[ "$backup" =~ ^/var/backups/rekaserdoba/20[0-9]{6}T[0-9]{6}Z$ ]]
bash "$(dirname "$0")/verify-backup.sh" "$backup"
test -x "$backup/bin/rekaserdoba-server"
"$backup/bin/rekaserdoba-server" --version
"$backup/bin/rekaserdoba-server" --check-config "$backup/etc/rekaserdoba/server.json"
certificate=$(jq -er '.h3.certificate_pem' "$backup/etc/rekaserdoba/server.json")
private_key=$(jq -er '.h3.private_key_pem' "$backup/etc/rekaserdoba/server.json")
certificate="$backup${certificate}"
private_key="$backup${private_key}"
openssl x509 -checkend 604800 -noout -in "$certificate"
certificate_public=$(openssl x509 -in "$certificate" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
private_public=$(openssl pkey -in "$private_key" -pubout -outform DER | sha256sum | cut -d' ' -f1)
test "$certificate_public" = "$private_public"
printf '%s\n' disaster-recovery-check-ok
