set -euo pipefail

test "$(id -u)" -eq 0
source_dir=$(realpath "${1:-deploy}")
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/backups/rekaserdoba-observability/$stamp

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y prometheus prometheus-node-exporter prometheus-alertmanager prometheus-blackbox-exporter

install -d -o root -g root -m 0700 "$backup"
for path in \
    /etc/prometheus/prometheus.yml \
    /etc/prometheus/alertmanager.yml \
    /etc/prometheus/blackbox.yml \
    /etc/prometheus/rekaserdoba-alerts.yml \
    /etc/default/prometheus \
    /etc/default/prometheus-node-exporter \
    /etc/default/prometheus-alertmanager \
    /etc/default/prometheus-blackbox-exporter; do
    if test -f "$path"; then
        install -d -o root -g root -m 0700 "$backup$(dirname "$path")"
        install -m 0600 "$path" "$backup$path"
    fi
done

install -m 0644 "$source_dir/prometheus.yml" /etc/prometheus/prometheus.yml
install -m 0644 "$source_dir/alertmanager.yml" /etc/prometheus/alertmanager.yml
install -m 0644 "$source_dir/blackbox.yml" /etc/prometheus/blackbox.yml
install -m 0644 "$source_dir/prometheus-alerts.yml" /etc/prometheus/rekaserdoba-alerts.yml
printf '%s\n' 'ARGS="--config.file=/etc/prometheus/prometheus.yml --storage.tsdb.path=/var/lib/prometheus/metrics2 --storage.tsdb.retention.time=15d --storage.tsdb.retention.size=1GB --web.listen-address=127.0.0.1:9090"' >/etc/default/prometheus
printf '%s\n' 'ARGS="--web.listen-address=127.0.0.1:9100 --collector.textfile.directory=/var/lib/prometheus/node-exporter"' >/etc/default/prometheus-node-exporter
printf '%s\n' 'ARGS="--config.file=/etc/prometheus/alertmanager.yml --storage.path=/var/lib/prometheus/alertmanager --web.listen-address=127.0.0.1:9093"' >/etc/default/prometheus-alertmanager
printf '%s\n' 'ARGS="--config.file=/etc/prometheus/blackbox.yml --web.listen-address=127.0.0.1:9115"' >/etc/default/prometheus-blackbox-exporter

install -d -o prometheus -g prometheus -m 0755 /var/lib/prometheus/node-exporter
promtool check config /etc/prometheus/prometheus.yml
promtool check rules /etc/prometheus/rekaserdoba-alerts.yml
amtool check-config /etc/prometheus/alertmanager.yml
systemctl daemon-reload
systemctl enable --now prometheus.service prometheus-node-exporter.service prometheus-alertmanager.service prometheus-blackbox-exporter.service
systemctl restart prometheus.service prometheus-node-exporter.service prometheus-alertmanager.service prometheus-blackbox-exporter.service
deadline=$((SECONDS + 30))
until curl --fail --silent --show-error http://127.0.0.1:9090/-/ready >/dev/null &&
    curl --fail --silent --show-error http://127.0.0.1:9093/-/ready >/dev/null &&
    curl --fail --silent --show-error 'http://127.0.0.1:9115/probe?module=https_2xx&target=https%3A%2F%2Fmessk.online%2F' | grep -q '^probe_success 1$'; do
    test "$SECONDS" -lt "$deadline"
    sleep 1
done
printf '%s\n' "$backup"
