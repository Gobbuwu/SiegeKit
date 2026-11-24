#!/bin/bash
# Temporary measurement (removed before merge). For each gate repository
# in $REPOS: scan it with SiegeKit (built with its work directory kept),
# record every container's peaks (poll.sh), and count the tool signals a
# completeness check would read: bandit errors and files read, trivy
# lockfiles read against lockfiles present, checkov JSON parsing errors.
set -u +e
E=${ENGINE:?}; SK=${SK:?}
export SIEGEKIT_ENGINE=$E
base=$RUNNER_TEMP/m; mkdir -p "$base"
"$(dirname "$0")/poll.sh" "$base/peaks.tsv" & poller=$!
for repo in $REPOS; do
  echo "=================== $repo"
  ans="testdata/known-answers/${repo//\//__}.json"; sha=$(jq -r '.fixture | split("@")[1]' "$ans")
  t="$base/t-${repo//\//__}"; git init -q "$t"; git -C "$t" fetch -q --depth 1 "https://github.com/$repo.git" "$sha"; git -C "$t" -c advice.detachedHead=false checkout -q FETCH_HEAD
  w="$base/w-${repo//\//__}"; mkdir -p "$w"; chmod 700 "$w"
  echo "=== start $repo $(date +%s)" >> "$base/peaks.tsv.marks"
  s=$(date +%s); TMPDIR=$w "$SK" scan --yes --update --no-save --report-dir "$base/r-${repo//\//__}" "$t" > "$base/log-${repo//\//__}" 2>&1; code=$?
  echo "exit=$code seconds=$(( $(date +%s)-s ))"
  jq -r '.plugins[] | "  \(.id) \(.status) \(.cause // "") findings=\(.findings // 0)"' "$base/r-${repo//\//__}/report.json" 2>/dev/null
  # bandit: files bandit says it read and could not parse, against .py/.pyw files outside its default excludes
  b=$(find "$w" -name bandit.json | head -1)
  if [ -n "$b" ]; then
    py=$(find "$t" -type d \( -name .git -o -name .svn -o -name CVS -o -name .bzr -o -name .hg -o -name .tox -o -name .eggs -o -name '*.egg' -o -name __pycache__ -o -name .venv -o -name node_modules \) -prune -o -type f \( -name '*.py' -o -name '*.pyw' \) -print | wc -l)
    jq -r --arg py "$py" '"  bandit signal: py files on disk=\($py) metrics files=\([.metrics|keys[]|select(.!="_totals")]|length) errors=\(.errors|length) \([.errors[].reason]|unique|.[0:3])"' "$b"
  fi
  # trivy: lockfiles present (names trivy's language analyzers read) against Results targets
  v=$(find "$w" -name trivy.json | head -1)
  if [ -n "$v" ]; then
    lf=$(find "$t" -path "$t/.git" -prune -o -type f \( -name package-lock.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name poetry.lock -o -name Pipfile.lock -o -name uv.lock -o -name requirements.txt -o -name go.mod -o -name Cargo.lock -o -name composer.lock -o -name Gemfile.lock -o -name pom.xml -o -name packages.lock.json -o -name mix.lock -o -name pubspec.lock -o -name Package.resolved -o -name bun.lock \) -print | sed "s#^$t/##" | sort)
    targets=$(jq -r '.Results[]?.Target' "$v" | sort -u)
    echo "  trivy signal: lockfiles on disk=$(echo "$lf" | grep -c .) targets=$(echo "$targets" | grep -c .)"
    comm -23 <(echo "$lf") <(echo "$targets") | sed 's/^/    on disk, no result: /' | head -15
  fi
  c=$(find "$w" -name 'results_json.json' | head -1)
  [ -n "$c" ] && jq -r '"  checkov signal: parsing_errors=\([.. | objects | .summary? // empty | .parsing_errors] | add)"' "$c"
  echo "=== end $repo $(date +%s)" >> "$base/peaks.tsv.marks"
done
kill -TERM $poller; wait $poller
echo "=================== peaks (container, image args, last read before exit)"
cat "$base/peaks.tsv"
