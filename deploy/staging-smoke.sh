set -euo pipefail

bundle=${1:?test bundle is required}
bridge=${2:?h3 bridge is required}
server_ip=${3:?server IP is required}
python=${PYTHON:-python3}

"$python" rekaserdoba/tools/probe.py "$bundle" --carrier wss --ip "$server_ip"
"$python" rekaserdoba/tools/probe.py "$bundle" --carrier h2 --ip "$server_ip"
"$python" rekaserdoba/tools/probe.py "$bundle" --carrier h3 --h3-bridge "$bridge" --ip "$server_ip"
"$python" rekaserdoba/tools/probe.py "$bundle" --carrier wss --migrate-to-h2 --ip "$server_ip"
