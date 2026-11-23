#!/bin/bash
# The form login gate (ADR 0062): SiegeKit's login-throttle and login-spray
# checks against a Next.js app whose logins are Server Action forms that
# call Supabase Auth on the server (Supabase's own server-side login guide
# pattern, and a useActionState form), with Supabase Auth and its database
# in containers on APP_ENGINE (rootless Podman or rootful Docker). Each
# scan is checked against its known answer and its measured result
# (results.txt), and the Supabase Auth logins each scan caused are counted
# at the gateway, so a login SiegeKit thinks it sent but the app never ran
# is seen.
#
#   gate.sh start   start Supabase Auth and the app (APP_ENGINE)
#   gate.sh scan    run the scans; exit 1 if any differs
#   gate.sh logs    print the logs
#
# Needs: SK (the siegekit binary), W (an empty work directory), REPO (the
# repository), and `npm ci` run in this directory.
set -euo pipefail
H=$(cd "$(dirname "$0")" && pwd)
: "${APP_ENGINE:?podman or docker}" "${SK:?}" "${W:?}" "${REPO:?}"
E=$APP_ENGINE
APP=http://127.0.0.1:3100
AUTH=http://127.0.0.1:54331 # the gateway in front of Supabase Auth

# Pinned images (resolved 2026-11-23); each digest is tried at Docker Hub
# and mirror.gcr.io, which can each answer 429 to anonymous pulls.
PG=supabase/postgres@sha256:d15ecf03474e4f5437002f3951f758b8fbfb182c3be311a998873c768ff53d37
GT=supabase/gotrue@sha256:ba8c0c82c574756c835c696df2a2c698020cc408a42034013d3712e34de7964d # v2.198.0
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

# The test account. The password is made here and thrown away with the job.
USER_EMAIL=gate-user@siegekit.test

# authup waits for Supabase Auth to answer.
authup() {
  for _ in $(seq 90); do
    if curl -sf http://127.0.0.1:9999/health >/dev/null; then return 0; fi
    sleep 1
  done
  $E logs gt 2>&1 | tail -20
  return 1
}

# logins counts the password logins Supabase Auth got through the gateway.
logins() { grep -c 'POST /auth/v1/token?grant_type=password' "$W/gateway.log" || true; }

start() {
  if [ "$E" = podman ]; then test "$(podman info --format '{{.Host.Security.Rootless}}')" = true; fi
  # Next.js 16 needs Node 20.9 or later.
  node -e 'const [a,b]=process.versions.node.split(".").map(Number); process.exit(a > 20 || a === 20 && b >= 9 ? 0 : 1)'
  case $E in
    docker) echo "docker $(docker version -f '{{.Server.Version}}'), cgroup $(docker info -f '{{.CgroupVersion}}'), $(case $(docker info -f '{{.SecurityOptions}}') in *rootless*) echo rootless ;; *) echo rootful ;; esac); node $(node --version); $(uname -m)" ;;
    podman) echo "podman $(podman version -f '{{.Version}}'), cgroup $(podman info -f '{{.Host.CgroupsVersion}}'), rootless $(podman info -f '{{.Host.Security.Rootless}}'); node $(node --version); $(uname -m)" ;;
  esac
  mkdir -p "$W"
  local sec dbpw anon pg gt
  sec=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  dbpw=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
  python3 -c 'import secrets; print("Gate-" + secrets.token_hex(12))' > "$W/password"
  anon=$(python3 "$H/../storage/jwt.py" "$sec" anon)
  pg=$(pull $PG)
  gt=$(pull $GT)
  $E network create lgnet >/dev/null
  $E run -d --name lgdb --network lgnet -e POSTGRES_PASSWORD="$dbpw" "$pg" >/dev/null
  # The image's entrypoint runs its init scripts on a server with no TCP
  # listener, so an answer on localhost comes from the final server.
  for _ in $(seq 120); do
    if $E exec lgdb pg_isready -U postgres -h localhost >/dev/null 2>&1; then break; fi
    sleep 1
  done
  $E exec lgdb psql -q -v ON_ERROR_STOP=1 -U supabase_admin -h localhost -d postgres -c "alter role supabase_auth_admin with password '$dbpw'"
  # Supabase Auth with password logins limited by client address, read
  # from X-Forwarded-For, which only the gateway sets (as the hosted
  # gateway sets the client address). 1 login per 5 minutes after a burst
  # of 30 (Supabase Auth's fixed burst): no login comes back during a scan,
  # so the login the limit starts at is the same every run.
  $E run -d --name gt --network lgnet -p 127.0.0.1:9999:9999 \
    -e GOTRUE_API_HOST=0.0.0.0 -e PORT=9999 -e API_EXTERNAL_URL=$AUTH -e GOTRUE_SITE_URL=$APP \
    -e GOTRUE_DB_DRIVER=postgres -e GOTRUE_DB_DATABASE_URL="postgres://supabase_auth_admin:$dbpw@lgdb:5432/postgres" \
    -e GOTRUE_JWT_SECRET="$sec" -e GOTRUE_JWT_EXP=3600 -e GOTRUE_JWT_AUD=authenticated -e GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated \
    -e GOTRUE_JWT_ADMIN_ROLES=service_role -e GOTRUE_MAILER_AUTOCONFIRM=true -e GOTRUE_EXTERNAL_EMAIL_ENABLED=true \
    -e GOTRUE_RATE_LIMIT_TOKEN_REFRESH=1 -e GOTRUE_RATE_LIMIT_HEADER=X-Forwarded-For "$gt" >/dev/null
  authup
  nohup node "$H/gateway.js" > "$W/gateway.log" 2>&1 &
  for _ in $(seq 20); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' $AUTH/auth/v1/health)" = 200 ]; then break; fi
    sleep 0.5
  done
  curl -sf -o /dev/null -H "apikey: $anon" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$(cat "$W/password")\"}" $AUTH/auth/v1/signup
  # The app, built and served by the runner's Node; Supabase's URL and key
  # are read on the server only.
  cd "$H"
  NEXT_TELEMETRY_DISABLED=1 SUPABASE_URL=$AUTH SUPABASE_PUBLISHABLE_KEY="$anon" npx --no-install next build > "$W/next-build.log" 2>&1 || { tail -30 "$W/next-build.log"; exit 1; }
  NEXT_TELEMETRY_DISABLED=1 SUPABASE_URL=$AUTH SUPABASE_PUBLISHABLE_KEY="$anon" nohup npx --no-install next start -H 127.0.0.1 -p 3100 > "$W/next.log" 2>&1 &
  for _ in $(seq 60); do
    if curl -sf -o /dev/null $APP/login; then break; fi
    sleep 0.5
  done
  curl -sf -o /dev/null $APP/login
  echo "Supabase Auth, gateway and app up"
}

# Each scan: name | flags | the logins Supabase Auth must get. The limit
# is reset before each (Supabase Auth keeps it in memory).
SCANS=(
  "login|--only login-throttle --login-page $APP/login --login-attempts 5|6"
  "login2|--only login-throttle --login-page $APP/login2 --login-attempts 5|6"
  "ignored|--only login-throttle --login-url $APP/login --login-attempts 5|0"
  "limited|--only login-throttle,login-spray --login-page $APP/login --login-attempts 40|32"
)

scan() {
  local fail=0 line name flags want rep before got after
  mkdir -p "$W/observed"
  for line in "${SCANS[@]}"; do
    IFS='|' read -r name flags want <<< "$line"
    rep=$W/report-$name
    $E restart gt >/dev/null
    authup
    before=$(logins)
    # --authorized-host stands for the owner's confirmation of the scan
    # of the runner's own app (ADR 0005), as in the web job.
    # shellcheck disable=SC2086 # flags are split on purpose
    SIEGEKIT_LOGIN_PASSWORD="$(cat "$W/password")" "$SK" scan --authorized-host 127.0.0.1 --no-save --report-dir "$rep" $flags \
      --login-user "$USER_EMAIL" --login-body 'email={user}&password={password}' $APP/ > "$W/scan-$name.log" 2>&1 || true
    after=$(logins)
    echo "== $name"
    if [ ! -f "$rep/report.json" ]; then echo "  FAIL: no report"; tail -20 "$W/scan-$name.log"; fail=1; continue; fi
    jq -r '.plugins[] | "  \(.id): \(.status), \(.requests // 0) requests, \(.findings // 0) findings: \(.result // .reason)"' "$rep/report.json"
    if grep -qF "$(cat "$W/password")" "$rep/report.json" "$W/scan-$name.log"; then echo "  FAIL: the password was written"; fail=1; fi
    echo "  Supabase Auth logins: $((after - before)) (want $want)"
    if [ "$((after - before))" != "$want" ]; then echo "  FAIL: not the logins the scan should cause"; fail=1; fi
    while IFS= read -r got; do
      if ! grep -qxF "$got" "$H/results.txt"; then echo "  FAIL: not the measured requests and result (results.txt): $got"; fail=1; fi
    done < <(jq -r --arg n "$name" '.plugins[] | "\($n) | \(.id) | \(.status) | \(.requests // 0) | \(.result // .reason)"' "$rep/report.json")
    if ! (cd "$REPO" && go run ./internal/knownanswers/check -answers "testdata/known-answers/nextjs-login-$name.json" -report "$rep/report.json" -observed "$W/observed/nextjs-login-$name.json"); then
      cat "$W/observed/nextjs-login-$name.json"; fail=1
    fi
  done
  return $fail
}

case ${1:-} in
  start) start ;;
  scan) scan ;;
  logs) $E logs gt 2>&1 | tail -40; tail -40 "$W/next.log" "$W/gateway.log" 2>/dev/null || true ;;
  *) echo "usage: gate.sh start|scan|logs" >&2; exit 2 ;;
esac
