#!/bin/bash
# TEMPORARY (removed before merge): the storage write test's real runs on a
# cgroup v2 runner, Firebase emulator and Supabase Storage each in rootful
# Docker and rootless Podman. Same rule sets, policies and apps as the
# measurement record of 2026-11-23.
set -euo pipefail
H=$(cd "$(dirname "$0")" && pwd); W=$RUNNER_TEMP/sw; mkdir -p $W; cd $W
SK=$W/siegekit; FAIL=0
PG=supabase/postgres@sha256:d15ecf03474e4f5437002f3951f758b8fbfb182c3be311a998873c768ff53d37
ST=supabase/storage-api@sha256:8a211c1024d661aafee98178d26a2da8d1f43d0b9cddb76b0d6445bee70acdaa
# Pull by digest from Docker Hub, then mirror.gcr.io (each can answer 429); tag the digest locally.
pull() { local E=$1 ref=$2 n; for n in 1 2 3; do for reg in docker.io mirror.gcr.io; do $E pull -q $reg/$ref >/dev/null 2>&1 && { $E tag $reg/$ref local/${ref%%@*}:pinned; return 0; }; done; sleep 20; done; echo "pull failed: $ref"; return 1; }
JRE=mirror.gcr.io/library/eclipse-temurin:21-jre
echo "cgroup: $(stat -fc %T /sys/fs/cgroup) | docker $(docker version -f '{{.Server.Version}}') $(docker info -f 'cgroup={{.CgroupVersion}}') | podman $(podman version -f '{{.Version}}') $(podman info -f 'cgroup={{.Host.CgroupsVersion}} rootless={{.Host.Security.Rootless}}') | node $(node --version) | $(uname -m)"

(cd "$GITHUB_WORKSPACE" && go build -o $SK ./cmd/siegekit)
npm init -y >/dev/null; npm i --silent firebase-tools@15.37.0 firebase@12.19.0 esbuild@0.25.0 @supabase/supabase-js@2.49.4 >/dev/null
SEC=$(python3 -c "import secrets;print(secrets.token_hex(32))"); ANON=$(python3 $H/jwt.py $SEC anon); SERVICE=$(python3 $H/jwt.py $SEC service_role)
mkdir -p fbapp sbapp; cp $H/app/fb.html fbapp/index.html; cp $H/app/sb.html sbapp/index.html
cp $H/app/fb.js fb-app.js; npx esbuild fb-app.js --bundle --minify --format=esm --outfile=fbapp/fb.min.js --log-level=warning
sed "s/ANONKEY/$ANON/" $H/app/sb.js > sb-real.js; npx esbuild sb-real.js --bundle --minify --format=esm --outfile=sbapp/main.js --log-level=warning
python3 -m http.server 8080 --bind 127.0.0.1 --directory fbapp >/dev/null 2>&1 &
python3 -m http.server 8081 --bind 127.0.0.1 --directory sbapp >/dev/null 2>&1 &
report() { python3 -c "import json;r=json.load(open('$1/report.json'));p=[p for p in r['plugins'] if p['id']=='storage-write'][0];print(p['status'],'|',p.get('findings',0),'|',p.get('requests'),'req |',p.get('result') or p.get('reason'))" 2>/dev/null || echo "no report | -1 | -"; }
check() { # name, got findings, want findings, got delta, want delta
  if [ "$2" != "$3" ] || [ "$4" != "$5" ]; then echo "  MISMATCH $1: findings $2 (want $3), objects +$4 (want +$5)"; FAIL=1; fi; }

# Firebase Storage emulator in a container (host 0.0.0.0: 127.0.0.1 inside a container is not reachable through -p).
NODE=$(dirname "$(dirname "$(readlink -f "$(which node)")")")
mkdir -p fb fbcache; printf '{"storage":{"rules":"storage.rules"},"emulators":{"storage":{"host":"0.0.0.0","port":9199},"ui":{"enabled":false},"singleProjectMode":true}}' > fb/firebase.json
cp $H/fb-rules/v1 fb/storage.rules; ln -s $W/node_modules fb/node_modules
WANT_FB=(1 1 1 0 1 1 1); DELTA_FB=(0 0 1 0 0 1 0)
fbcount() { curl -s -H "Authorization: Bearer owner" "http://127.0.0.1:9199/v0/b/demo-siegekit.appspot.com/o?prefix=${1:-}" | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('items',[])))"; }
for E in docker podman; do
  $E pull -q $JRE >/dev/null
  $E run -d --name fbemu -p 127.0.0.1:9199:9199 -v $NODE:/opt/node:ro -v $W:$W -v $W/fbcache:/root/.cache/firebase -w $W/fb \
    -e PATH=/opt/node/bin:/opt/java/openjdk/bin:/usr/bin:/bin $JRE node $W/fb/node_modules/.bin/firebase emulators:start --only storage --project demo-siegekit >/dev/null
  for i in $(seq 90); do $E logs fbemu 2>&1 | grep -q "All emulators ready" && break; sleep 2; done
  echo "== Firebase emulator in $E"
  for n in 1 2 3 4 5 6 7; do v=v$n; cp $H/fb-rules/$v fb/storage.rules; sleep 3; mkdir -p src-$v; cp $H/fb-rules/$v src-$v/storage.rules
    b=$(( $(fbcount) + $(fbcount uploads/) )); rm -rf r-$E-$v
    printf 'write test files\n' | script -qec "$SK scan http://127.0.0.1:8080/ --only storage-write --storage-url http://127.0.0.1:9199 --source $W/src-$v --report-dir $W/r-$E-$v" /dev/null >/dev/null || true
    a=$(( $(fbcount) + $(fbcount uploads/) )); r=$(report r-$E-$v); echo "$v objects $b -> $a | $r"
    check "$E $v" "$(echo "$r" | cut -d'|' -f2 | tr -d ' ')" ${WANT_FB[$((n-1))]} $((a-b)) ${DELTA_FB[$((n-1))]}
  done
  echo "rules reloads: $($E logs fbemu 2>&1 | grep -ci 'change detected')"
  $E rm -f fbemu >/dev/null; sudo rm -f $W/fb/*-debug.log
done

# Supabase Storage (storage-api behind a /storage/v1 proxy, as a real project's gateway).
WANT_SB=(2 2 2 0 1 2 2); DELTA_SB=(0 0 2 0 0 2 2)
for E in docker podman; do
  P=$([ $E = docker ] && echo 5000 || echo 5001)
  pull $E $PG; pull $E $ST
  $E network create sbnet-$E >/dev/null
  $E run -d --name sbdb-$E --network sbnet-$E -e POSTGRES_PASSWORD=pw local/supabase/postgres:pinned >/dev/null
  for i in $(seq 120); do $E exec sbdb-$E pg_isready -U postgres -h localhost >/dev/null 2>&1 && break; sleep 1; done; sleep 5
  $E exec sbdb-$E psql -q -U supabase_admin -h localhost -d postgres -c "alter role supabase_storage_admin with password 'pw'"
  $E run -d --name sbst-$E --network sbnet-$E -p 127.0.0.1:$P:5000 -e ANON_KEY=$ANON -e SERVICE_KEY=$SERVICE -e AUTH_JWT_SECRET=$SEC -e PGRST_JWT_SECRET=$SEC \
    -e AUTH_JWT_ALGORITHM=HS256 -e DATABASE_URL=postgres://supabase_storage_admin:pw@sbdb-$E:5432/postgres -e STORAGE_BACKEND=file -e FILE_STORAGE_BACKEND_PATH=/var/lib/storage \
    -e TENANT_ID=stub -e REGION=stub -e GLOBAL_S3_BUCKET=stub -e FILE_SIZE_LIMIT=52428800 local/supabase/storage-api:pinned >/dev/null
  for i in $(seq 90); do curl -sf localhost:$P/status >/dev/null && break; sleep 1; done
  curl -sf -X POST localhost:$P/bucket -H "apikey: $SERVICE" -H "Authorization: Bearer $SERVICE" -H "content-type: application/json" -d '{"id":"files","name":"files","public":false}' >/dev/null
  python3 $H/proxy.py 54321 $P & PROXY=$!; sleep 1
  count() { $E exec sbdb-$E psql -U postgres -h localhost -tAc "select count(*) from storage.objects"; }
  echo "== Supabase Storage in $E"
  for n in 1 2 3 4 5 6 7; do s=s$n
    $E exec sbdb-$E psql -q -U postgres -h localhost -c "drop policy if exists t1 on storage.objects; drop policy if exists t2 on storage.objects;"
    $E exec -i sbdb-$E psql -q -U postgres -h localhost < $H/sb-policies/$s.sql
    mkdir -p sbsrc-$s/supabase/migrations; cp $H/sb-policies/$s.sql sbsrc-$s/supabase/migrations/1.sql
    b=$(count); rm -rf r-$E-$s
    printf 'write test files\n' | script -qec "$SK scan http://127.0.0.1:8081/ --only storage-write --storage-url http://127.0.0.1:54321 --source $W/sbsrc-$s --report-dir $W/r-$E-$s" /dev/null >/dev/null || true
    a=$(count); r=$(report r-$E-$s); echo "$s objects $b -> $a | $r"
    check "$E $s" "$(echo "$r" | cut -d'|' -f2 | tr -d ' ')" ${WANT_SB[$((n-1))]} $((a-b)) ${DELTA_SB[$((n-1))]}
  done
  kill $PROXY; $E rm -f sbst-$E sbdb-$E >/dev/null
done
[ $FAIL = 0 ] && echo "ALL MATCH the cgroup v1 measurements" || { echo "SOME RUNS DIFFER"; exit 1; }
