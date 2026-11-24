#!/bin/bash
# Temporary measurement (removed before merge): every 0.2 s, record each
# running container's cgroup v2 peaks and event counters from the host.
# memory.peak and pids.peak only grow, so the last read before the
# container exits is its peak, less what happened in its last 0.2 s.
# Output: one line per container in $1 when stopped (SIGTERM).
set -u
E=${ENGINE:?}
out=${1:?}
declare -A cg img last anon first
finish() {
  for id in "${!cg[@]}"; do
    printf '%s\t%s\t%s\t%s\tanonmax=%s\n' "${first[$id]}" "${id:0:12}" "${img[$id]}" "${last[$id]:-gone-before-read}" "${anon[$id]:-0}" >> "$out"
  done
  exit 0
}
trap finish TERM INT
while true; do
  for id in $($E ps -q --no-trunc 2>/dev/null); do
    [ -n "${cg[$id]:-}" ] && continue
    pid=$($E inspect -f '{{.State.Pid}}' "$id" 2>/dev/null) || continue
    p=$(awk -F: '$1=="0"{print $3}' "/proc/$pid/cgroup" 2>/dev/null) || continue
    [ -n "$p" ] || continue
    cg[$id]="/sys/fs/cgroup$p"; first[$id]=$(date +%s)
    img[$id]="$($E inspect -f '{{.Config.Image}}' "$id" 2>/dev/null | sed 's/@sha256.*//; s#.*/##') $($E inspect -f '{{join .Args " "}}' "$id" 2>/dev/null | cut -c1-60 | tr '\t' ' ')"
  done
  for id in "${!cg[@]}"; do
    d=${cg[$id]}
    [ -r "$d/memory.peak" ] || continue
    a=$(awk '$1=="anon"{print $2}' "$d/memory.stat" 2>/dev/null)
    [ -n "$a" ] && [ "$a" -gt "${anon[$id]:-0}" ] && anon[$id]=$a
    last[$id]="mempeak=$(cat "$d/memory.peak" 2>/dev/null) memmax=$(cat "$d/memory.max" 2>/dev/null) pidspeak=$(cat "$d/pids.peak" 2>/dev/null) pidsmax=$(cat "$d/pids.max" 2>/dev/null) $(grep -E '^(max|oom|oom_kill) ' "$d/memory.events" 2>/dev/null | tr ' \n' '= ') pids.$(grep -E '^max ' "$d/pids.events" 2>/dev/null | tr ' ' '=')"
  done
  sleep 0.2
done
