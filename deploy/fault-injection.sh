set -euo pipefail

test "${1:-}" = "staging"
edge_pid=$(systemctl show -p MainPID --value rekaserdoba.service)
test "$edge_pid" -gt 1
systemctl restart rekaserdoba-net-helper.service
deadline=$((SECONDS + 15))
until curl --fail --silent --max-time 2 http://127.0.0.1:9080/readyz >/dev/null; do
    test "$SECONDS" -lt "$deadline"
    sleep 1
done
test "$(systemctl show -p MainPID --value rekaserdoba.service)" = "$edge_pid"
systemctl kill --signal=TERM rekaserdoba.service
deadline=$((SECONDS + 30))
until systemctl is-active --quiet rekaserdoba.service &&
    curl --fail --silent --max-time 2 http://127.0.0.1:9080/readyz >/dev/null; do
    test "$SECONDS" -lt "$deadline"
    sleep 1
done
test "$(systemctl show -p MainPID --value rekaserdoba.service)" != "$edge_pid"
