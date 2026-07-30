set -euo pipefail

mode=${1:?mode is required}
public_key_file=${2:-}
source_config=${3:-}
backup_root=/var/backups/rekaserdoba-access
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=$backup_root/$stamp
paths=(
    /etc/ssh/sshd_config
    /etc/ssh/sshd_config.d/60-rekaserdoba-hardening.conf
    /root/.ssh/authorized_keys
    /home/deployer/.ssh/authorized_keys
    /etc/sudoers.d/90-rekaserdoba-deployer
)

test "$(id -u)" -eq 0
[[ "$mode" = prepare || "$mode" = disable-root ]]
install -d -o root -g root -m 0700 "$backup"
printf '%s\n' "${paths[@]}" >"$backup/managed-paths"
for path in "${paths[@]}"; do
    if test -e "$path"; then
        printf '%s\n' "$path" >>"$backup/present-paths"
    fi
done
mapfile -t present_paths <"$backup/present-paths"
tar --acls --xattrs -C / -cpf "$backup/access.tar" "${present_paths[@]#/}"
(
    cd "$backup"
    sha256sum access.tar managed-paths present-paths >SHA256SUMS
)

if test "$mode" = prepare; then
    test -f "$public_key_file"
    ssh-keygen -lf "$public_key_file" >/dev/null
    if ! id -u deployer >/dev/null 2>&1; then
        useradd --create-home --shell /bin/bash deployer
    fi
    usermod --lock deployer
    usermod --append --groups sudo deployer
    install -d -o deployer -g deployer -m 0700 /home/deployer/.ssh
    install -o deployer -g deployer -m 0600 "$public_key_file" /home/deployer/.ssh/authorized_keys
    printf '%s\n' 'deployer ALL=(root) NOPASSWD: ALL' >/etc/sudoers.d/90-rekaserdoba-deployer
    chmod 0440 /etc/sudoers.d/90-rekaserdoba-deployer
    visudo -cf /etc/sudoers
    sshd -t
    systemctl reload ssh.service
    printf '%s\n' "$backup"
    exit 0
fi

test "${SUDO_USER:-}" = deployer
test -f "$source_config"
rollback() {
    trap - ERR
    if grep -Fqx /etc/ssh/sshd_config.d/60-rekaserdoba-hardening.conf "$backup/present-paths"; then
        tar --acls --xattrs -xpf "$backup/access.tar" -C / etc/ssh/sshd_config.d/60-rekaserdoba-hardening.conf
    else
        rm -f /etc/ssh/sshd_config.d/60-rekaserdoba-hardening.conf
    fi
}
trap rollback ERR
install -o root -g root -m 0600 "$source_config" /etc/ssh/sshd_config.d/60-rekaserdoba-hardening.conf
sshd -t
test "$(sshd -T -C user=root,host="$(hostname)",addr=127.0.0.1 | awk '$1 == "permitrootlogin" {print $2}')" = no
test "$(sshd -T -C user=deployer,host="$(hostname)",addr=127.0.0.1 | awk '$1 == "passwordauthentication" {print $2}')" = no
systemctl reload ssh.service
trap - ERR
printf '%s\n' "$backup"
