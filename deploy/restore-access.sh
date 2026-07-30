set -euo pipefail

backup=$(realpath "${1:?access backup directory is required}")
[[ "$backup" =~ ^/var/backups/rekaserdoba-access/20[0-9]{6}T[0-9]{6}Z$ ]]
test "$(id -u)" -eq 0
(
    cd "$backup"
    sha256sum --check --strict SHA256SUMS
)
while IFS= read -r path; do
    if ! grep -Fqx "$path" "$backup/present-paths"; then
        rm -f -- "$path"
    fi
done <"$backup/managed-paths"
tar --acls --xattrs -xpf "$backup/access.tar" -C /
visudo -cf /etc/sudoers
sshd -t
systemctl reload ssh.service
printf '%s\n' access-restored
