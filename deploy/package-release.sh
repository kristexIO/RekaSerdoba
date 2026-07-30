set -euo pipefail

source_dir=${1:?source directory is required}
output_dir=${2:?output directory is required}
commit=${3:?commit is required}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]]

test -x "$source_dir/rekaserdoba-server"
test -x "$source_dir/net_helper"
test -x "$source_dir/h3_bridge"
test -f "$source_dir/rekaserdoba-server.cdx.json"
install -d -m 0755 "$output_dir/bin" "$output_dir/systemd" "$output_dir/sysctl" "$output_dir/libexec"
install -m 0755 "$source_dir/rekaserdoba-server" "$output_dir/bin/rekaserdoba-server"
install -m 0755 "$source_dir/net_helper" "$output_dir/bin/rekaserdoba-net-helper"
install -m 0755 "$source_dir/h3_bridge" "$output_dir/bin/h3_bridge"
install -m 0644 "$source_dir/rekaserdoba-server.cdx.json" "$output_dir/rekaserdoba-server.cdx.json"
install -m 0644 deploy/rekaserdoba.service "$output_dir/systemd/rekaserdoba.service"
install -m 0644 deploy/rekaserdoba-net-helper.service "$output_dir/systemd/rekaserdoba-net-helper.service"
install -m 0644 deploy/rekaserdoba-health.service "$output_dir/systemd/rekaserdoba-health.service"
install -m 0644 deploy/rekaserdoba-health.timer "$output_dir/systemd/rekaserdoba-health.timer"
install -m 0644 deploy/rekaserdoba-recover.service "$output_dir/systemd/rekaserdoba-recover.service"
install -m 0644 deploy/rekaserdoba-maintenance.service "$output_dir/systemd/rekaserdoba-maintenance.service"
install -m 0644 deploy/rekaserdoba-maintenance.timer "$output_dir/systemd/rekaserdoba-maintenance.timer"
install -m 0644 deploy/60-rekaserdoba-sysctl.conf "$output_dir/sysctl/60-rekaserdoba.conf"
install -m 0755 deploy/rekaserdoba-health-check "$output_dir/libexec/rekaserdoba-health-check"
install -m 0755 deploy/rekaserdoba-maintenance "$output_dir/libexec/rekaserdoba-maintenance"
printf '%s\n' "$commit" >"$output_dir/COMMIT"
(
    cd "$output_dir"
    find . -type f ! -name SHA256SUMS -print0 |
        sort -z |
        xargs -0 sha256sum >SHA256SUMS
)
