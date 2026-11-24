#!/bin/bash
# Temporary measurement (removed before merge): peaks of every URL check's
# container on Juice Shop v20.4.0, as the gate starts it, through SiegeKit.
set -u +e
E=${ENGINE:?}; SK=${SK:?}
export SIEGEKIT_ENGINE=$E
base=$RUNNER_TEMP/m; mkdir -p "$base/w"; chmod 700 "$base/w"
docker run -d --name juice-shop -p 127.0.0.1:3000:3000 docker.io/bkimminich/juice-shop@sha256:9bbaecc41791f00b002bc65931cc5ff355fbdb941fa72b06558c18dace43197b >/dev/null
for i in $(seq 1 60); do curl -sf -o /dev/null http://127.0.0.1:3000/ && break; sleep 2; done
"$(dirname "$0")/poll.sh" "$base/peaks.tsv" & poller=$!
s=$(date +%s)
TMPDIR=$base/w "$SK" scan --yes --authorized-host 127.0.0.1 --no-save --report-dir "$base/r" http://127.0.0.1:3000/ > "$base/log" 2>&1
echo "exit=$? seconds=$(( $(date +%s)-s ))"
kill -TERM $poller; wait $poller
tail -30 "$base/log"
jq -r '.plugins[] | "  \(.id) \(.status) \(.cause // "") requests=\(.requests // 0) findings=\(.findings // 0)"' "$base/r/report.json"
echo "=================== peaks (first seen, container, image args, last read before exit)"
cat "$base/peaks.tsv"
