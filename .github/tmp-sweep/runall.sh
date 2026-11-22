# $1 har name, $2 target, $3 out prefix, rest: spec files. One harness run per spec file (the CLI takes one --openapi file).
h=$1; t=$2; o=$3; shift 3
for f in "$@"; do sleep ${GAP:-65}; n=$(basename $f .yaml); n=${n%.json}; bash run.sh $h $t $f $o-$n >/dev/null; echo "== $n: $(grep PARSED $SW/$o-$n.txt)"; grep -E "RSUMMARY |RFINDING" $SW/$o-$n.txt; done
