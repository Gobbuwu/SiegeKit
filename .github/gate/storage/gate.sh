#!/bin/bash
# The storage write gate (ADR 0059): SiegeKit's storage-write check (ADR
# 0058) against the Firebase Storage emulator or a local Supabase Storage,
# with the storage in a container on APP_ENGINE (rootless Podman or rootful
# Docker), once per rule set or policy set. The gate checks every run
# against its known answer and, from the storage's own listing, that the
# test files left behind are exactly the ones the report names.
#
# For Supabase it also runs an app that calls Supabase only from its server
# (ADR 0061): its page names no backend and serves no key, so the key comes
# from SIEGEKIT_SUPABASE_KEY and the kind from --source; on an address not on
# this machine, behind Supabase's own self-hosted API gateway, the project
# must accept the key before anything is uploaded.
#
#   gate.sh start   start the storage and serve the app (BACKEND, APP_ENGINE)
#   gate.sh scan    scan once per rule set; exit 1 if any run differs
#   gate.sh logs    print the storage's logs
#
# Needs: SK (the siegekit binary), W (an empty work directory), REPO (the
# repository), and `npm ci` run in this directory.
set -euo pipefail
# No grep -q at the end of a pipe: it stops reading at the first match, the
# writer then fails on the closed pipe (podman logs exits 1), and pipefail
# makes the whole test false (measured: 9 of 50 checks on Podman 4.9.3).
H=$(cd "$(dirname "$0")" && pwd)
: "${BACKEND:?firebase or supabase}" "${APP_ENGINE:?podman or docker}" "${SK:?}" "${W:?}" "${REPO:?}"
E=$APP_ENGINE
APP=http://127.0.0.1:8080/

# Pinned images (resolved 2026-11-23). Docker Hub and mirror.gcr.io can each
# answer 429 to anonymous pulls, so each digest is tried at both.
JRE=library/eclipse-temurin@sha256:d77e090ae1f6970c047b443c6f0a6c1358b0426d44432bb5a7753408cd43de0d
PG=supabase/postgres@sha256:d15ecf03474e4f5437002f3951f758b8fbfb182c3be311a998873c768ff53d37
ST=supabase/storage-api@sha256:8a211c1024d661aafee98178d26a2da8d1f43d0b9cddb76b0d6445bee70acdaa
# ADR 0061: Supabase Auth and the Envoy image of Supabase's self-hosted
# docker-compose.yml, with its gateway config from the same commit, each file
# checked by SHA-256 (supabase/supabase, Apache-2.0; downloaded, not copied).
GT=supabase/gotrue@sha256:ba8c0c82c574756c835c696df2a2c698020cc408a42034013d3712e34de7964d
EV=envoyproxy/envoy@sha256:1fde8efee875e4e4f6a39a90fe49d9338e1caacce5762034ef9fb4bbb9ad6aed
SBREF=0af0e9aed420f1b44b808bd693f1c715a5ed4810
ENVOY_FILES="envoy.yaml:3697f23b0be9ec5b829f937c600eb9b878f1f778ab510b42ad5e4f14742447e9
cds.yaml:9f2df9e1355cbeda3ecca809bffca9ed439bb18a66b82ca07caf97e27c34c291
lds.template.yaml:a99cebcc882f5da41baa94a8a632d7ac9e7ad7e0074685267095f1af6e6535fc
docker-entrypoint.sh:8a0c9503764de32ba39e0d81e73629457b13ec42ef19897e30e4918c996d0508"
pull() {
  local reg
  for _ in 1 2 3; do
    for reg in docker.io mirror.gcr.io; do
      if $E pull -q "$reg/$1" >/dev/null 2>&1; then echo "$reg/$1"; return 0; fi
    done
    sleep 20
  done
  echo "pull failed: $1" >&2
  return 1
}

BUCKET=demo-siegekit.appspot.com
FB=http://127.0.0.1:9199
SB=http://127.0.0.1:54321
# The server-only app, and the gateway's port (on every address, so that it
# can be reached at this machine's private address, which SiegeKit treats as
# not on this machine).
APPSO=http://127.0.0.1:8081/
GW=54322
psql() { $E exec -i sbdb psql -q -v ON_ERROR_STOP=1 -U postgres -h localhost "$@"; }

# objects prints every object in the storage, one full path per line, as
# the report names leftovers: gs://BUCKET/PATH (Firebase) or BUCKET/PATH
# (Supabase). Firebase's owner token reads past the rules.
objects() {
  case $BACKEND in
    firebase) curl -sf -H 'Authorization: Bearer owner' "$FB/v0/b/$BUCKET/o" | jq -r --arg b "$BUCKET" '.items[] | "gs://\($b)/\(.name)"' ;;
    supabase) psql -tA -c "select bucket_id || '/' || name from storage.objects" ;;
  esac | sort
}

start() {
  if [ "$E" = podman ]; then test "$(podman info --format '{{.Host.Security.Rootless}}')" = true; fi
  case $E in
    docker) echo "docker $(docker version -f '{{.Server.Version}}'), cgroup $(docker info -f '{{.CgroupVersion}}'), $(case $(docker info -f '{{.SecurityOptions}}') in *rootless*) echo rootless ;; *) echo rootful ;; esac); node $(node --version); $(uname -m)" ;;
    podman) echo "podman $(podman version -f '{{.Version}}'), cgroup $(podman info -f '{{.Host.CgroupsVersion}}'), rootless $(podman info -f '{{.Host.Security.Rootless}}'); node $(node --version); $(uname -m)" ;;
  esac
  mkdir -p "$W/app"
  cd "$H"
  case $BACKEND in
    firebase)
      cp app/fb.html "$W/app/index.html"
      npx --no-install esbuild app/fb.js --bundle --minify --format=esm --outfile="$W/app/fb.min.js" --log-level=warning
      # The emulator needs Java and Node: a pinned JRE image with the
      # runner's Node and the pinned firebase-tools mounted read-only. It
      # must listen on 0.0.0.0: on 127.0.0.1 inside a container the
      # published port answers nothing (ADR 0058). Rules change through
      # its /internal/setRules, which answers once they are loaded.
      local img node
      img=$(pull $JRE)
      node=$(dirname "$(dirname "$(readlink -f "$(command -v node)")")")
      mkdir -p "$W/fb" "$W/fbcache/emulators"
      # The rules runtime firebase-tools would download at start, fetched
      # here and checked against the SHA-256 firebase-tools pins (its own
      # check is size and MD5).
      local jar url sum name
      read -r url sum name < <(jq -r '.storage | "\(.remoteUrl) \(.expectedChecksumSHA256) \(.downloadPathRelativeToCacheDir)"' node_modules/firebase-tools/lib/emulator/downloadableEmulatorInfo.json)
      jar=$W/fbcache/emulators/$name
      curl -sfL --retry 3 -o "$jar" "$url"
      echo "$sum  $jar" | sha256sum -c --quiet
      printf '{"storage":{"rules":"storage.rules"},"emulators":{"storage":{"host":"0.0.0.0","port":9199},"ui":{"enabled":false},"singleProjectMode":true}}' > "$W/fb/firebase.json"
      cp firebase/v4.rules.txt "$W/fb/storage.rules"
      $E run -d --name storage -p 127.0.0.1:9199:9199 -v "$node:/opt/node:ro" -v "$H/node_modules:/opt/tools/node_modules:ro" \
        -v "$W/fb:/fb" -v "$W/fbcache:/root/.cache/firebase" -w /fb -e PATH=/opt/node/bin:/opt/java/openjdk/bin:/usr/bin:/bin \
        "$img" node /opt/tools/node_modules/firebase-tools/lib/bin/firebase.js emulators:start --only storage --project demo-siegekit >/dev/null
      local up=
      for _ in $(seq 90); do
        if $E logs storage 2>&1 | grep -F 'All emulators ready' >/dev/null; then up=1; break; fi
        sleep 2
      done
      if [ -z "$up" ]; then $E logs storage; exit 1; fi
      ;;
    supabase)
      # Keys and passwords made here and thrown away with the job; no
      # Supabase account. A small proxy serves storage-api under
      # /storage/v1, the layout of a real project's gateway (ADR 0058).
      local sec dbpw anon service pg st
      sec=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
      dbpw=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
      anon=$(python3 jwt.py "$sec" anon)
      service=$(python3 jwt.py "$sec" service_role)
      cp app/sb.html "$W/app/index.html"
      sed "s/ANONKEY/$anon/" app/sb.js | npx --no-install esbuild --bundle --minify --format=esm --sourcefile=sb.js --outfile="$W/app/main.js" --log-level=warning
      pg=$(pull $PG)
      st=$(pull $ST)
      $E network create sbnet >/dev/null
      $E run -d --name sbdb --network sbnet -e POSTGRES_PASSWORD="$dbpw" "$pg" >/dev/null
      # The image's entrypoint runs its init scripts on a server with no TCP
      # listener (listen_addresses=''), so an answer on localhost comes
      # from the final server, after the storage role exists.
      for _ in $(seq 120); do
        if $E exec sbdb pg_isready -U postgres -h localhost >/dev/null 2>&1; then break; fi
        sleep 1
      done
      $E exec sbdb psql -q -v ON_ERROR_STOP=1 -U supabase_admin -h localhost -d postgres -c "alter role supabase_storage_admin with password '$dbpw'"
      $E run -d --name storage --network sbnet -p 127.0.0.1:5000:5000 -e ANON_KEY="$anon" -e SERVICE_KEY="$service" \
        -e AUTH_JWT_SECRET="$sec" -e PGRST_JWT_SECRET="$sec" -e AUTH_JWT_ALGORITHM=HS256 \
        -e DATABASE_URL="postgres://supabase_storage_admin:$dbpw@sbdb:5432/postgres" -e STORAGE_BACKEND=file \
        -e FILE_STORAGE_BACKEND_PATH=/var/lib/storage -e TENANT_ID=stub -e REGION=stub -e GLOBAL_S3_BUCKET=stub \
        -e FILE_SIZE_LIMIT=52428800 "$st" >/dev/null
      for _ in $(seq 90); do
        if curl -sf http://127.0.0.1:5000/status >/dev/null; then break; fi
        sleep 1
      done
      curl -sf -X POST http://127.0.0.1:5000/bucket -H "apikey: $service" -H "Authorization: Bearer $service" \
        -H 'Content-Type: application/json' -d '{"id":"files","name":"files","public":false}' >/dev/null
      gateway "$sec" "$dbpw" "$anon" "$service"
      nohup python3 proxy.py 54321 5000 >/dev/null 2>&1 &
      for _ in $(seq 20); do
        if [ "$(curl -s -o /dev/null -w '%{http_code}' $SB/storage/v1/status)" = 200 ]; then break; fi
        sleep 0.5
      done
      ;;
  esac
  nohup python3 -m http.server 8080 --bind 127.0.0.1 --directory "$W/app" >/dev/null 2>&1 &
  if [ "$BACKEND" = supabase ]; then
    mkdir -p "$W/app-so"
    cp app/so.html "$W/app-so/index.html"
    nohup python3 -m http.server 8081 --bind 127.0.0.1 --directory "$W/app-so" >/dev/null 2>&1 &
  fi
  for _ in $(seq 20); do
    if curl -sf -o /dev/null $APP; then break; fi
    sleep 0.5
  done
  curl -sf -o /dev/null $APP
  if [ "$BACKEND" = supabase ]; then curl -sf -o /dev/null $APPSO; fi
  echo "storage and app up; objects at start: $(objects | wc -l)"
}

# gateway starts Supabase Auth and Supabase's self-hosted API gateway in
# front of it and the storage (ADR 0061), with sb_ key translation on, and
# writes the keys the server-only runs use: the project's publishable key and
# anon key, and another project's publishable key.
gateway() {
  local sec=$1 dbpw=$2 anon=$3 service=$4 f name gt ev pub secr
  mkdir -p "$W/envoy"
  while read -r f; do
    name=${f%%:*}
    curl -sfL --retry 3 -o "$W/envoy/$name" "https://raw.githubusercontent.com/supabase/supabase/$SBREF/docker/volumes/api/envoy/$name"
    echo "${f#*:}  $W/envoy/$name" | sha256sum -c --quiet
  done <<< "$ENVOY_FILES"
  token() { python3 -c 'import secrets; print(secrets.token_urlsafe(16))'; }
  pub=sb_publishable_$(token)
  secr=sb_secret_$(token)
  printf '%s' "$pub" > "$W/key-pub"
  printf '%s' "$anon" > "$W/key-anon"
  printf 'sb_publishable_%s' "$(token)" > "$W/key-other"
  gt=$(pull $GT)
  ev=$(pull $EV)
  $E exec sbdb psql -q -v ON_ERROR_STOP=1 -U supabase_admin -h localhost -d postgres -c "alter role supabase_auth_admin with password '$dbpw'"
  $E run -d --name sbauth --network sbnet --network-alias auth -e GOTRUE_API_HOST=0.0.0.0 -e PORT=9999 \
    -e API_EXTERNAL_URL=http://127.0.0.1:$GW -e GOTRUE_SITE_URL=$APPSO -e GOTRUE_DB_DRIVER=postgres \
    -e GOTRUE_DB_DATABASE_URL="postgres://supabase_auth_admin:$dbpw@sbdb:5432/postgres" -e GOTRUE_JWT_SECRET="$sec" \
    -e GOTRUE_JWT_EXP=3600 -e GOTRUE_JWT_AUD=authenticated -e GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated \
    -e GOTRUE_JWT_ADMIN_ROLES=service_role "$gt" >/dev/null
  # The translated keys are the HS256 anon and service keys, which the
  # storage checks with its JWT secret.
  $E run -d --name sbgw --network sbnet -p "$GW:8000" \
    -v "$W/envoy/envoy.yaml:/etc/envoy/envoy.yaml:ro" -v "$W/envoy/cds.yaml:/etc/envoy/cds.yaml:ro" \
    -v "$W/envoy/lds.template.yaml:/etc/envoy/lds.template.yaml:ro" -v "$W/envoy/docker-entrypoint.sh:/docker-entrypoint.sh:ro" \
    -e ANON_KEY="$anon" -e SERVICE_ROLE_KEY="$service" -e SUPABASE_PUBLISHABLE_KEY="$pub" -e SUPABASE_SECRET_KEY="$secr" \
    -e ANON_KEY_ASYMMETRIC="$anon" -e SERVICE_ROLE_KEY_ASYMMETRIC="$service" -e SUPABASE_PUBLIC_URL=http://127.0.0.1:$GW \
    -e DASHBOARD_USERNAME=gate -e DASHBOARD_PASSWORD="$dbpw" --entrypoint /bin/sh "$ev" /docker-entrypoint.sh >/dev/null
  local code=
  for _ in $(seq 90); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "apikey: $pub" "http://127.0.0.1:$GW/auth/v1/settings" || true)
    if [ "$code" = 200 ]; then break; fi
    sleep 1
  done
  if [ "$code" != 200 ]; then echo "gateway: /auth/v1/settings answered $code"; $E logs sbgw 2>&1 | tail -20; $E logs sbauth 2>&1 | tail -20; exit 1; fi
  echo "gateway up: another project's key gets $(curl -s -o /dev/null -w '%{http_code}' -H "apikey: $(cat "$W/key-other")" "http://127.0.0.1:$GW/auth/v1/settings")"
}

# setrules puts rule set or policy set $1 in place, and its copy in the
# repository given to --source ($2).
setrules() {
  rm -rf "$2"
  case $BACKEND in
    firebase)
      mkdir -p "$2"
      cp "$H/firebase/$1.rules.txt" "$2/storage.rules"
      jq -n --rawfile c "$2/storage.rules" '{rules: {files: [{name: "storage.rules", content: $c}]}}' |
        curl -sf -X PUT -H 'Content-Type: application/json' --data-binary @- "$FB/internal/setRules" >/dev/null
      ;;
    supabase)
      mkdir -p "$2/supabase/migrations"
      cp "$H/supabase/$1.sql.txt" "$2/supabase/migrations/1.sql"
      psql -c 'drop policy if exists t1 on storage.objects; drop policy if exists t2 on storage.objects'
      psql < "$H/supabase/$1.sql.txt"
      ;;
  esac
}

# verify checks one run ($1, report directory $2, scan log $3) against its
# known answer and measured result (with the machine's address as ADDR), and
# the storage's listing before and after it; it returns 1 if anything
# differs.
verify() {
  local s=$1 rep=$2 log=$3 fail=0 got new named
  echo "== $BACKEND $s"
  if ! grep -q 'Type "write test files" to upload them' "$log"; then echo "  FAIL: no typed confirmation asked"; fail=1; fi
  if ! jq -e '[.plugins[] | select(.id == "storage-write")] | length == 1' "$rep/report.json" >/dev/null 2>&1; then
    echo "  FAIL: no storage-write result"; tail -20 "$log"; return 1
  fi
  jq -r '.plugins[] | select(.id == "storage-write") | "  \(.status), \(.requests // 0) requests, \(.findings) findings: \(.result // .reason)"' "$rep/report.json"
  got=$(jq -r --arg s "$s" '.plugins[] | select(.id == "storage-write") | "\($s) | \(.requests // 0) | \(.result // .reason | sub("delete them: .*$"; "delete them: NAMES") | gsub("http://[0-9.]+:"; "http://ADDR:"))"' "$rep/report.json")
  if ! grep -qxF "$got" "$H/results.txt"; then echo "  FAIL: not the measured requests and result (results.txt)"; fail=1; fi
  # The storage's own listing: the new objects must be exactly the files
  # the report names as left behind.
  new=$(comm -13 "$W/before-$s" "$W/after-$s")
  named=$(jq -r '.plugins[] | select(.id == "storage-write") | .result // "" | if test("delete them: ") then sub(".*delete them: "; "") | split(", ")[] else empty end' "$rep/report.json" | sort)
  if [ -n "$(comm -23 "$W/before-$s" "$W/after-$s")" ]; then echo "  FAIL: objects that were there before are gone"; fail=1; fi
  if [ "$new" != "$named" ]; then echo "  FAIL: new objects [$new] are not the leftovers named [$named]"; fail=1; fi
  echo "  objects $(wc -l < "$W/before-$s") -> $(wc -l < "$W/after-$s"), new: $(echo "${new:-none}" | paste -sd ' ')"
  if ! (cd "$REPO" && go run ./internal/knownanswers/check -answers "testdata/known-answers/storage-$BACKEND-$s.json" -report "$rep/report.json" -observed "$W/observed/storage-$BACKEND-$s.json"); then
    cat "$W/observed/storage-$BACKEND-$s.json"; fail=1
  fi
  return $fail
}

scan() {
  local sets url fail=0 s src rep
  case $BACKEND in
    firebase) sets="v1 v2 v3 v4 v5 v6 v7"; url=$FB ;;
    supabase) sets="s1 s2 s3 s4 s5 s6 s7"; url=$SB ;;
  esac
  mkdir -p "$W/observed"
  for s in $sets; do
    src=$W/src-$s
    rep=$W/report-$s
    setrules "$s" "$src"
    objects > "$W/before-$s"
    # The check asks a person to type "write test files" (ADR 0058 item 4;
    # a loopback storage asks for no host name). The gate made the storage
    # and the app, so it types the phrase through a pseudo-terminal (ADR
    # 0044), as the writes job does.
    printf 'write test files\n' | script -qec "$SK scan --no-save --report-dir $rep --only storage-write --storage-url $url --source $src $APP" "$W/scan-$s.log" >/dev/null || true
    objects > "$W/after-$s"
    verify "$s" "$rep" "$W/scan-$s.log" || fail=1
  done
  if [ "$BACKEND" = supabase ]; then serveronly || fail=1; fi
  return $fail
}

# serveronly scans the app that calls Supabase only from its server (ADR
# 0061), on policy set s2: its page names neither Supabase nor a key, so
# the kind comes from --source (a supabase/ directory), the bucket from its
# migration and the key from SIEGEKIT_SUPABASE_KEY. so-local: the storage on
# this machine, no key check. so-remote: the gateway at this machine's
# private address (not on this machine for SiegeKit), its host typed, the
# publishable key accepted by GET /auth/v1/settings, then the uploads.
# so-other: the same with another project's key, refused by the gateway:
# nothing is uploaded. No run may write the key to its report or output.
serveronly() {
  local fail=0 src=$W/src-so addr run name url key typed rep
  addr=$(hostname -I | tr ' ' '\n' | grep -E '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | head -1)
  if [ -z "$addr" ]; then echo "FAIL: no private address on this machine ($(hostname -I))"; return 1; fi
  setrules s2 "$src"
  printf 'project_id = "server-only-app"\n' > "$src/supabase/config.toml"
  printf "insert into storage.buckets (id, name, public) values ('files', 'files', false);\n" > "$src/supabase/migrations/0.sql"
  for run in "so-local http://127.0.0.1:54321 anon" "so-remote http://$addr:$GW pub" "so-other http://$addr:$GW other"; do
    read -r name url key <<< "$run"
    rep=$W/report-$name
    typed='write test files\n'
    if [ "$name" != so-local ]; then typed="$addr\\nwrite test files\\n"; fi
    objects > "$W/before-$name"
    # shellcheck disable=SC2059 # typed holds the \n escapes on purpose
    printf "$typed" | SIEGEKIT_SUPABASE_KEY=$(cat "$W/key-$key") script -qec "$SK scan --no-save --report-dir $rep --only storage-write --storage-url $url --source $src $APPSO" "$W/scan-$name.log" >/dev/null || true
    objects > "$W/after-$name"
    verify "$name" "$rep" "$W/scan-$name.log" || fail=1
    if [ "$name" != so-local ] && ! grep -qF "Type its host name ($addr)" "$W/scan-$name.log"; then echo "  FAIL: the host name was not asked"; fail=1; fi
    if grep -rlF "$(cat "$W/key-$key")" "$rep" "$W/scan-$name.log" >/dev/null; then echo "  FAIL: the key was written to the report or the output"; fail=1; fi
  done
  return $fail
}

case ${1:-} in
  start) start ;;
  scan) scan ;;
  logs) $E logs storage 2>&1 | tail -50; if [ "$BACKEND" = supabase ]; then $E logs sbdb 2>&1 | tail -20; $E logs sbauth 2>&1 | tail -20; $E logs sbgw 2>&1 | tail -20; fi ;;
  *) echo "usage: gate.sh start|scan|logs" >&2; exit 2 ;;
esac
