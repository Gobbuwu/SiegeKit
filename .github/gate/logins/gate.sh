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
# The same app's sign-up and reset pages (ADR 0069, issue #81) are Server
# Action forms too: each scan of them is checked the same way, and the
# action runs under each page's limit are counted at Mailpit, where every
# such run sends one email.
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
MP=axllent/mailpit@sha256:e22dce5b36f93c77082e204a3942fb6b283b7896e057458400a4c88344c3df68 # v1.27.11, the mail job's
MAILPIT=http://127.0.0.1:8025/
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
  local sec dbpw anon pg gt mp
  sec=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  dbpw=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
  python3 -c 'import secrets; print("Gate-" + secrets.token_hex(12))' > "$W/password"
  anon=$(python3 "$H/../storage/jwt.py" "$sec" anon)
  pg=$(pull $PG)
  gt=$(pull $GT)
  mp=$(pull $MP)
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
  $E run -d --name lgmail -p 127.0.0.1:8025:8025 "$mp" >/dev/null
  for _ in $(seq 60); do
    if curl -sf -o /dev/null ${MAILPIT}api/v1/info; then break; fi
    sleep 0.5
  done
  curl -sf -o /dev/null ${MAILPIT}api/v1/info
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
  NEXT_TELEMETRY_DISABLED=1 SUPABASE_URL=$AUTH SUPABASE_PUBLISHABLE_KEY="$anon" MAILPIT_URL=$MAILPIT npx --no-install next build > "$W/next-build.log" 2>&1 || { tail -30 "$W/next-build.log"; exit 1; }
  NEXT_TELEMETRY_DISABLED=1 SUPABASE_URL=$AUTH SUPABASE_PUBLISHABLE_KEY="$anon" MAILPIT_URL=$MAILPIT nohup npx --no-install next start -H 127.0.0.1 -p 3100 > "$W/next.log" 2>&1 &
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
  "login|--only login-throttle --login-page $APP/login --login-attempts 20|21"
  "login2|--only login-throttle --login-page $APP/login2 --login-attempts 20|21"
  "ignored|--only login-throttle --login-url $APP/login --login-attempts 5|0"
  "limited|--only login-throttle,login-spray --login-page $APP/login --login-attempts 40|32"
)

scan() {
  local fail=0 line name flags want rep before after
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
    if grep -qF "$(cat "$W/password")" "$rep/report.json" "$W/scan-$name.log"; then echo "  FAIL: the password was written"; fail=1; fi
    echo "  Supabase Auth logins: $((after - before)) (want $want)"
    if [ "$((after - before))" != "$want" ]; then echo "  FAIL: not the logins the scan should cause"; fail=1; fi
    check "$name" "$rep" login || fail=1
  done
  pages || fail=1
  return $fail
}

# check compares a scan's report with results.txt and its known answer.
check() {
  local name=$1 rep=$2 kind=$3 fail=0 got
  jq -r '.plugins[] | "  \(.id): \(.status), \(.requests // 0) requests, \(.findings // 0) findings: \(.result // .reason)"' "$rep/report.json"
  while IFS= read -r got; do
    if ! grep -qxF "$got" "$H/results.txt"; then echo "  FAIL: not the measured requests and result (results.txt): $got"; fail=1; fi
  done < <(jq -r --arg n "$name" '.plugins[] | "\($n) | \(.id) | \(.status) | \(.requests // 0) | \(.result // .reason)"' "$rep/report.json")
  if ! (cd "$REPO" && go run ./internal/knownanswers/check -answers "testdata/known-answers/nextjs-$kind-$name.json" -report "$rep/report.json" -observed "$W/observed/nextjs-$kind-$name.json"); then
    cat "$W/observed/nextjs-$kind-$name.json"; fail=1
  fi
  return $fail
}

# mails counts the emails at Mailpit: the action runs under the limits.
mails() { curl -sf "${MAILPIT}api/v1/messages?limit=1" | jq .total; }

# The sign-up and reset pages (ADR 0069): name | flags | the action runs
# under the limit (emails) the scan must cause. The raw posts are issue
# #81's case: the action never runs, so nothing may be reported. --page
# scans send the page's form; /signup2 answers 200 with no limit, so only
# the emails show the sign-ups reached it. {SID} and {FID} are the
# action IDs of this build's /signup and /forgot forms.
MC="--mail-catcher $MAILPIT"
SIGNUP='email={new}%40example.com&password=Gate-page-1'
PAGE_SCANS=(
  "signup-raw|--only signup-limit --signup-url $APP/signup --signup-body %24{SID}=&$SIGNUP|0"
  "reset-raw|--only reset-limit $MC --reset-url $APP/forgot --reset-body %24{FID}=&email=gate-user%40siegekit.test|0"
  "signup-page|--only signup-limit $MC --signup-page $APP/signup --signup-body $SIGNUP|10"
  "reset-page|--only reset-limit $MC --reset-page $APP/forgot --reset-body email=gate-user%40siegekit.test|5"
  "signup2-page|--only signup-limit --signup-page $APP/signup2 --signup-body $SIGNUP|20"
  "signup2-mail|--only signup-limit $MC --signup-page $APP/signup2 --signup-body $SIGNUP|20"
)

pages() {
  local fail=0 line name flags want rep sid fid got
  sid=$(curl -sf $APP/signup | grep -o 'ACTION_ID_[0-9a-f]*' | head -1)
  fid=$(curl -sf $APP/forgot | grep -o 'ACTION_ID_[0-9a-f]*' | head -1)
  test -n "$sid" && test -n "$fid"
  for line in "${PAGE_SCANS[@]}"; do
    IFS='|' read -r name flags want <<< "$line"
    flags=${flags//\{SID\}/$sid}
    flags=${flags//\{FID\}/$fid}
    rep=$W/report-page-$name
    curl -sf -X DELETE "${MAILPIT}api/v1/messages" >/dev/null
    curl -sf -o /dev/null -X POST $APP/gate-reset
    # shellcheck disable=SC2086 # flags are split on purpose
    "$SK" scan --authorized-host 127.0.0.1 --no-save --report-dir "$rep" $flags $APP/ > "$W/scan-page-$name.log" 2>&1 || true
    echo "== page $name"
    if [ ! -f "$rep/report.json" ]; then echo "  FAIL: no report"; tail -20 "$W/scan-page-$name.log"; fail=1; continue; fi
    got=$(mails)
    echo "  action runs under the limit (emails at Mailpit): $got (want $want)"
    if [ "$got" != "$want" ]; then echo "  FAIL: not the runs the scan should cause"; fail=1; fi
    check "$name" "$rep" pages || fail=1
  done
  return $fail
}

case ${1:-} in
  start) start ;;
  scan) scan ;;
  logs) $E logs gt 2>&1 | tail -40; $E logs lgmail 2>&1 | tail -10; tail -40 "$W/next.log" "$W/gateway.log" 2>/dev/null || true ;;
  *) echo "usage: gate.sh start|scan|logs" >&2; exit 2 ;;
esac
