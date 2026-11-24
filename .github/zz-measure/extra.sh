#!/bin/bash
# Temporary measurement (removed before merge).
# 1. The waiter runs the ZAP, Checkov, Schemathesis and ffuf (Alpine) images'
#    own entrypoints, non-root, read-only root, as the sandbox runs them.
# 2. Can Nuclei name the templates it reports as "runtime error"?
set -u +e
E=${ENGINE:?}; W=${WAITER:?}
img() { jq -r '.tool.artifacts[] | select(.kind=="oci-image") | .ref' "plugins/$1/plugin.json"; }
U="--user $(id -u):$(id -g)"
echo "### 1. waiter under the other images"
for p in zap checkov schemathesis ffuf; do
  i=$(img $p); $E pull -q "$i" >/dev/null 2>&1
  first=$($E image inspect --format '{{if .Config.Entrypoint}}{{index .Config.Entrypoint 0}}{{end}}' "$i")
  case $p in zap) cmd="zap.sh -version";; checkov) cmd="$first --version";; schemathesis) cmd="$first --version";; ffuf) cmd="/bin/sh -c 'echo alpine-ok; exit 0'";; esac
  out=$(eval $E run --rm $U --read-only --tmpfs /tmp:rw,noexec,nosuid --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 2048m \
        -e HOME=/tmp -e COUNTERS_OUT=/tmp/c.json -v "$W:/sk/wait:ro" --entrypoint /sk/wait "$i" $cmd 2>&1 | tail -3 | tr '\n' ' ')
  echo "$p entry=$first exit=${PIPESTATUS[0]} -> ${out:0:300}"
  # counters written: run once more, printing them instead of the tool's output
  c=$(eval $E run --rm $U --read-only --tmpfs /tmp:rw,noexec,nosuid --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 2048m \
        -e HOME=/tmp -v "$W:/sk/wait:ro" --entrypoint /sk/wait "$i" $cmd 2>/dev/null | grep -o '"pids.events": *"[^"]*"\|"memory.peak": *"[^"]*"\|"exit": *[0-9]*' | tr '\n' ' ')
  echo "   counters: $c"
done
echo "### 2. nuclei: which templates have runtime errors"
NUCLEI=$(img nuclei)
T=$(mktemp -d); chmod 755 "$T"
curl -sfL -o "$T/nt.tgz" https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.5.2.tar.gz
echo "016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574  $T/nt.tgz" | sha256sum -c - || exit 1
mkdir -p "$T/nt"; tar -xzf "$T/nt.tgz" -C "$T/nt"; chmod -R a+rX "$T/nt"
TP=/siegekit/files/nuclei-templates/nuclei-templates-10.5.2
ET="$TP/http/cves/2019/CVE-2019-14696.yaml,$TP/http/cves/2021/CVE-2021-28164.yaml,$TP/http/fuzzing/wordpress-themes-detect.yaml,$TP/http/fuzzing/mdb-database-file.yaml,$TP/http/miscellaneous/crypto-address-detect.yaml,$TP/http/vulnerabilities/wp-functions-php-disclosure.yaml"
for v in "-tl" "-tl -validate" "-tl -v" "-tl -debug"; do
  echo "--- nuclei $v (as the plugin selects templates, no target)"
  $E run --rm $U -e HOME=/tmp --read-only --tmpfs /tmp -v "$T/nt:/siegekit/files/nuclei-templates:ro" "$NUCLEI" \
    -t $TP -pt http -et "$ET" -ni -duc -nc -etags intrusive,dos,fuzz,dast,local,bruteforce,txt-service,default-login $v > "$T/out" 2> "$T/err"
  echo "exit=$? stdout lines=$(wc -l < "$T/out") stderr lines=$(wc -l < "$T/err")"
  sed 's/\x1b\[[0-9;]*m//g' "$T/err" | grep -iE "runtime error|error|could not|failed|warn" | sed 's/[0-9a-f-]\{36\}//g' | cut -c1-200 | sort | uniq -c | sort -rn | head -12
done
