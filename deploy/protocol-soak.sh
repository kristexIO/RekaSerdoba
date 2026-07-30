set -euo pipefail

bundle=${1:?test bundle is required}
bridge=${2:?h3 bridge is required}
server_ip=${3:?server IP is required}
duration=${4:-300}
interval=${5:-5}
python=${PYTHON:-python3}
started=$(date +%s)
deadline=$((started + duration))
attempts=0
successes=0
failures=0
maximum_ms=0
log=$(mktemp)
trap 'rm -f "$log"' EXIT

while test "$(date +%s)" -lt "$deadline"; do
    for carrier in wss h2 h3; do
        attempt_started=$(date +%s%3N)
        command=("$python" rekaserdoba/tools/probe.py "$bundle" --carrier "$carrier" --ip "$server_ip")
        if test "$carrier" = h3; then
            command+=(--h3-bridge "$bridge")
        fi
        attempts=$((attempts + 1))
        if "${command[@]}" >"$log" 2>&1; then
            successes=$((successes + 1))
        else
            failures=$((failures + 1))
            printf '%s\n' "$carrier $(tail -n 1 "$log")" >&2
        fi
        elapsed=$(($(date +%s%3N) - attempt_started))
        if test "$elapsed" -gt "$maximum_ms"; then
            maximum_ms=$elapsed
        fi
    done
    sleep "$interval"
done

printf '{"attempts":%d,"successes":%d,"failures":%d,"maximum_ms":%d,"duration":%d}\n' "$attempts" "$successes" "$failures" "$maximum_ms" "$(($(date +%s) - started))"
test "$attempts" -gt 0
test "$failures" -eq 0
