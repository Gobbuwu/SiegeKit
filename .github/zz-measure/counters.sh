#!/bin/bash
# Kernel-counter reading options: B = waiter inside, A = host poll every 2 s, C = inspect after exit (no --rm).
set -u
E=${ENGINE:-docker}
IMG=docker.io/library/alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
W=${WAITER:?}
OUT=$(mktemp -d); chmod 777 "$OUT"
declare -A CMD
CMD[normal]='echo hi; sleep 1'
# 25 forks under a 20-process limit, then exit at once (refusal in the last moment)
CMD[latefork]='sleep 3; sh -c "for i in \$(seq 1 25); do sleep 30 & done" 2>/dev/null; exit 0'
# a child is killed for memory, the parent exits 0 right after
CMD[childoom]='sleep 3; head -c 300m /dev/zero | tail >/dev/null; exit 0'
base() { echo --pids-limit 20 --memory 64m --memory-swap 64m --cap-drop ALL --security-opt no-new-privileges --read-only --user "$(id -u):$(id -g)"; }
cgpath() { # host cgroup dir of a running container's pid
  local pid=$1 rel
  if [ -f /sys/fs/cgroup/cgroup.controllers ]; then rel=$(awk -F: '$1=="0"{print $3}' /proc/$pid/cgroup); echo "/sys/fs/cgroup$rel"
  else rel=$(awk -F: '$2 ~ /(^|,)pids(,|$)/{print $3}' /proc/$pid/cgroup); echo "/sys/fs/cgroup/pids$rel"; fi
}
for c in normal latefork childoom; do
  echo "=== case $c engine $E"
  # B: waiter
  $E run --rm $(base) -v "$W:/sk/wait:ro" -v "$OUT:/out" -e COUNTERS_OUT=/out/b-$c.json --entrypoint /sk/wait $IMG sh -c "${CMD[$c]}" >/dev/null 2>&1; echo "B exit $?"
  python3 -c "import json,sys;d=json.load(open('$OUT/b-$c.json'));[print('B',k,'=',v.replace(chr(10),' | ')) for k,v in d.items() if not v.startswith('ERR')]"
  # A: host poll every 2 s
  n=a$RANDOM; $E run -d --rm --name $n $(base) $IMG sh -c "${CMD[$c]}" >/dev/null
  last=""; lastm=""
  while :; do
    pid=$($E inspect --format '{{.State.Pid}}' $n 2>/dev/null) || break
    [ -z "$pid" ] || [ "$pid" = 0 ] && break
    d=$(cgpath $pid)
    v=$(cat $d/pids.events 2>/dev/null | tr '\n' ' '); [ -n "$v" ] && last=$v
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then m=$(cat $d/memory.events 2>/dev/null | tr '\n' ' '); else m=$(grep oom_kill /sys/fs/cgroup/memory${d#/sys/fs/cgroup/pids}/memory.oom_control 2>/dev/null); fi; [ -n "$m" ] && lastm=$m
    sleep 2
  done
  echo "A last pids.events: $last"; echo "A last memory: $lastm"
  # C: no --rm, inspect after exit
  n=c$RANDOM; $E run -d --name $n $(base) $IMG sh -c "${CMD[$c]}" >/dev/null
  pid=$($E inspect --format '{{.State.Pid}}' $n); d=$(cgpath $pid 2>/dev/null)
  $E wait $n >/dev/null
  echo "C inspect: $($E inspect --format 'exit={{.State.ExitCode}} oomkilled={{.State.OOMKilled}}' $n)"
  [ -d "$d" ] && echo "C cgroup dir still exists after exit: $(cat $d/pids.events 2>/dev/null|tr '\n' ' ')" || echo "C cgroup dir gone after exit"
  $E rm $n >/dev/null
done
