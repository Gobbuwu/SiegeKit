#!/bin/bash
# The storage write gate (ADR 0059): SiegeKit's storage-write check (ADR
# 0058) against the Firebase Storage emulator or a local Supabase Storage,
# with the storage in a container on APP_ENGINE (rootless Podman or rootful
# Docker), once per rule set or policy set. The gate checks every run
# against its known answer and, from the storage's own listing, that the
# test files left behind are exactly the ones the report names.
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
      nohup python3 proxy.py 54321 5000 >/dev/null 2>&1 &
      for _ in $(seq 20); do
        if [ "$(curl -s -o /dev/null -w '%{http_code}' $SB/storage/v1/status)" = 200 ]; then break; fi
        sleep 0.5
      done
      ;;
  esac
  nohup python3 -m http.server 8080 --bind 127.0.0.1 --directory "$W/app" >/dev/null 2>&1 &
  for _ in $(seq 20); do
    if curl -sf -o /dev/null $APP; then break; fi
    sleep 0.5
  done
  curl -sf -o /dev/null $APP
  echo "storage and app up; objects at start: $(objects | wc -l)"
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

scan() {
  local sets url fail=0 s src rep got new named
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
    echo "== $BACKEND $s"
    if ! grep -q 'Type "write test files" to upload them' "$W/scan-$s.log"; then echo "  FAIL: no typed confirmation asked"; fail=1; fi
    if ! jq -e '[.plugins[] | select(.id == "storage-write" and .status == "ran")] | length == 1' "$rep/report.json" >/dev/null 2>&1; then
      echo "  FAIL: storage-write did not run"; tail -20 "$W/scan-$s.log"; fail=1; continue
    fi
    jq -r '.plugins[] | select(.id == "storage-write") | "  \(.requests) requests, \(.findings) findings: \(.result)"' "$rep/report.json"
    got=$(jq -r --arg s "$s" '.plugins[] | select(.id == "storage-write") | "\($s) | \(.requests) | \(.result | sub("delete them: .*$"; "delete them: NAMES"))"' "$rep/report.json")
    if ! grep -qxF "$got" "$H/results.txt"; then echo "  FAIL: not the measured requests and result (results.txt)"; fail=1; fi
    # The storage's own listing: the new objects must be exactly the
    # files the report names as left behind.
    new=$(comm -13 "$W/before-$s" "$W/after-$s")
    named=$(jq -r '.plugins[] | select(.id == "storage-write") | .result | if test("delete them: ") then sub(".*delete them: "; "") | split(", ")[] else empty end' "$rep/report.json" | sort)
    if [ -n "$(comm -23 "$W/before-$s" "$W/after-$s")" ]; then echo "  FAIL: objects that were there before are gone"; fail=1; fi
    if [ "$new" != "$named" ]; then echo "  FAIL: new objects [$new] are not the leftovers named [$named]"; fail=1; fi
    echo "  objects $(wc -l < "$W/before-$s") -> $(wc -l < "$W/after-$s"), new: $(echo "${new:-none}" | paste -sd ' ')"
    if ! (cd "$REPO" && go run ./internal/knownanswers/check -answers "testdata/known-answers/storage-$BACKEND-$s.json" -report "$rep/report.json" -observed "$W/observed/storage-$BACKEND-$s.json"); then
      cat "$W/observed/storage-$BACKEND-$s.json"; fail=1
    fi
  done
  return $fail
}

case ${1:-} in
  start) start ;;
  scan) scan ;;
  logs) $E logs storage 2>&1 | tail -50; if [ "$BACKEND" = supabase ]; then $E logs sbdb 2>&1 | tail -20; fi ;;
  *) echo "usage: gate.sh start|scan|logs" >&2; exit 2 ;;
esac
