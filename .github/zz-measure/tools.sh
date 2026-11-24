#!/bin/bash
# Tool-level completeness signals (temporary measurement, removed before merge).
set -u +e
E=${ENGINE:?}
W=${WAITER:?}
NUCLEI=docker.io/projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb
TRIVY=docker.io/aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
BANDIT=ghcr.io/pycqa/bandit/bandit@sha256:b405a808f5d50156aee921a77fb17c044d69d90ecef6499447a037678967c936
GITLEAKS=docker.io/zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
T=$(mktemp -d); chmod 755 "$T"
U="--user $(id -u):$(id -g)"

echo "### 1. Every pinned image runs under the waiter (entrypoint read from the image)"
for img in $GITLEAKS $BANDIT $TRIVY $NUCLEI; do
  $E pull -q "$img" >/dev/null 2>&1
  ep=$($E image inspect --format '{{json .Config.Entrypoint}} {{json .Config.Cmd}}' "$img")
  first=$($E image inspect --format '{{index .Config.Entrypoint 0}}' "$img" 2>/dev/null)
  case "$img" in *bandit*) arg=--version;; *nuclei*) arg=-version;; *) arg=version;; esac
  out=$($E run --rm $U --read-only --cap-drop ALL --security-opt no-new-privileges -v "$W:/sk/wait:ro" --entrypoint /sk/wait "$img" "$first" $arg 2>&1 | tail -2 | tr '\n' ' ')
  echo "$img entry=$ep exit=$? -> $out"
done

echo "### 2. bandit image: unparsable files and metrics"
mkdir -p "$T/bt/a/.tox" "$T/bt/b"; printf 'import os\nos.system(input())\n' > "$T/bt/a/ok.py"; printf 'print "py2"\n' > "$T/bt/a/bad.py"
printf 'try:\n    pass\nexcept ValueError, TypeError:\n    pass\n' > "$T/bt/a/pep758.py"; cp "$T/bt/a/ok.py" "$T/bt/a/w.pyw"; cp "$T/bt/a/ok.py" "$T/bt/a/.tox/t.py"
printf '#!/usr/bin/env python3\nimport os\n' > "$T/bt/b/script"; chmod -R a+rX "$T/bt"; mkdir -p "$T/bo"; chmod 777 "$T/bo"
$E run --rm $U --entrypoint python3 "$BANDIT" --version 2>&1 | tail -1
$E run --rm $U -v "$T/bt:/target:ro" -v "$T/bo:/out" "$BANDIT" -r /target -f json -o /out/b.json --exit-zero -q; echo "bandit exit=$?"
python3 -c "import json;d=json.load(open('$T/bo/b.json'));print('errors',d['errors']);print('metrics files',sorted(k for k in d['metrics'] if k!='_totals'))"

echo "### 3. trivy: lockfiles it cannot parse"
mkdir -p "$T/tv/good" "$T/tv/bad" "$T/tv/badreq"; mkdir -p "$T/tvc"; chmod 777 "$T/tvc"
printf '{"name":"g","lockfileVersion":3,"packages":{"":{"name":"g","dependencies":{"lodash":"4.17.15"}},"node_modules/lodash":{"version":"4.17.15"}}}\n' > "$T/tv/good/package-lock.json"
printf '{"name":"b","lockfileVersion":3,"packages":{ broken\n' > "$T/tv/bad/package-lock.json"
printf 'name = "x"\n[[package\n' > "$T/tv/bad/poetry.lock"; printf '[tool.poetry]\nname="x"\n' > "$T/tv/bad/pyproject.toml"
printf 'flask==0.12\n-e git+bad\n%%%%%%\n' > "$T/tv/badreq/requirements.txt"; chmod -R a+rX "$T/tv"
$E run --rm $U -e HOME=/tmp -v "$T/tvc:/cache" "$TRIVY" image --download-db-only --cache-dir /cache -q; echo "db exit=$?"
$E run --rm $U -e HOME=/tmp -v "$T/tvc:/cache" -v "$T/tv:/target:ro" "$TRIVY" filesystem --cache-dir /cache --skip-db-update --skip-java-db-update --skip-check-update --offline-scan --scanners vuln --include-dev-deps --list-all-pkgs --format json --output /cache/t.json /target 2> "$T/trivy.err"; echo "trivy exit=$?"
sed 's/\x1b\[[0-9;]*m//g' "$T/trivy.err" | tail -15
python3 -c "import json;d=json.load(open('$T/tvc/t.json'));print([(r['Target'],r.get('Type'),len(r.get('Packages') or []),len(r.get('Vulnerabilities') or [])) for r in d.get('Results',[])])"

echo "### 4. gitleaks-history under memory pressure: commits scanned vs git"
git clone -q --bare https://github.com/juice-shop/juice-shop "$T/js.git"; chmod -R a+rX "$T/js.git"
echo "rev-list --all --no-merges: $(git -C "$T/js.git" rev-list --all --no-merges --count); size $(du -sh "$T/js.git" | cut -f1)"
for mem in 1024 96 64; do
  $E run --rm $U --read-only --tmpfs /tmp --memory ${mem}m --memory-swap ${mem}m -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    -v "$T/js.git:/target:ro" -v "$W:/sk/wait:ro" -e COUNTERS_OUT=/tmp/x --entrypoint /sk/wait "$GITLEAKS" gitleaks git /target --log-opts=--all --redact --no-banner --exit-code 0 --report-format sarif --report-path /tmp/r.sarif 2>&1 \
    | sed 's/\x1b\[[0-9;]*m//g' | grep -i "commits scanned\|scanned ~\|leaks\|error\|fatal\|kill" | tr '\n' ' '; echo " <- mem=${mem}m exit=${PIPESTATUS[0]}"
  cid=$($E run -d $U --read-only --tmpfs /tmp --memory ${mem}m --memory-swap ${mem}m -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' -v "$T/js.git:/target:ro" "$GITLEAKS" git /target --log-opts=--all --redact --no-banner --exit-code 0 --report-path /tmp/r.json)
  $E wait "$cid" >/dev/null; echo "   inspect: $($E inspect --format 'exit={{.State.ExitCode}} oomkilled={{.State.OOMKilled}}' "$cid") log: $($E logs "$cid" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -i 'commits scanned' | tr '\n' ' ')"; $E rm "$cid" >/dev/null
done

echo "### 5. nuclei on Juice Shop: templates loaded, stats, host errors"
curl -sfL -o "$T/nt.tgz" https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v10.5.2.tar.gz
echo "016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574  $T/nt.tgz" | sha256sum -c - || exit 1
mkdir -p "$T/nt"; tar -xzf "$T/nt.tgz" -C "$T/nt"; chmod -R a+rX "$T/nt"; mkdir -p "$T/no"; chmod 777 "$T/no"
TP=/siegekit/files/nuclei-templates/nuclei-templates-10.5.2
ET="$TP/http/cves/2019/CVE-2019-14696.yaml,$TP/http/cves/2021/CVE-2021-28164.yaml,$TP/http/fuzzing/wordpress-themes-detect.yaml,$TP/http/fuzzing/mdb-database-file.yaml,$TP/http/miscellaneous/crypto-address-detect.yaml,$TP/http/vulnerabilities/wp-functions-php-disclosure.yaml"
nuc() { $E run --rm $U --network host -e HOME=/tmp --read-only --tmpfs /tmp -v "$T/nt:/siegekit/files/nuclei-templates:ro" -v "$T/no:/out" "$NUCLEI" \
  -u http://127.0.0.1:3000 -t $TP -pt http -et "$ET" -ni -duc -nc -or -rl 100 -c 8 -j -o /out/$1.jsonl -etags intrusive,dos,fuzz,dast,local,bruteforce,txt-service,default-login -stats -sj -si 20 "${@:2}"; }
$E run -d --name js -p 127.0.0.1:3000:3000 docker.io/bkimminich/juice-shop@sha256:9bbaecc41791f00b002bc65931cc5ff355fbdb941fa72b06558c18dace43197b >/dev/null
for i in $(seq 1 60); do curl -sf -o /dev/null http://127.0.0.1:3000/ && break; sleep 2; done
t0=$(date +%s); nuc full > "$T/n1.out" 2> "$T/n1.err"; echo "nuclei full exit=$? s=$(( $(date +%s)-t0 )) findings=$(wc -l < "$T/no/full.jsonl")"
grep -v '^{' "$T/n1.err" | sed 's/\x1b\[[0-9;]*m//g' | grep -iv "^\s*$" | tail -12; grep '^{' "$T/n1.out" "$T/n1.err" 2>/dev/null | tail -1
echo "--- run 2: Juice Shop stopped 90 s into the run"
( sleep 90; $E stop -t 1 js >/dev/null; echo "stopped juice shop at $(date +%T)" ) &
t0=$(date +%s); nuc cut > "$T/n2.out" 2> "$T/n2.err"; echo "nuclei cut exit=$? s=$(( $(date +%s)-t0 )) findings=$(wc -l < "$T/no/cut.jsonl")"; wait
grep -v '^{' "$T/n2.err" | sed 's/\x1b\[[0-9;]*m//g' | grep -iv "^\s*$" | tail -12; grep -h '^{' "$T/n2.out" "$T/n2.err" 2>/dev/null | tail -1
$E rm -f js >/dev/null
