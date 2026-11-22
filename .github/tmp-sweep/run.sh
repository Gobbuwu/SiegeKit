# $1 har name, $2 target, $3 spec file or "", $4 out name
cd $GITHUB_WORKSPACE
cp $SW/zz_sweep_test.go internal/authz/zz_sweep_test.go
env ZZ_HAR=$SW/$1.har ZZ_TARGET=$2 ZZ_SPEC="$3" ZZ_USER=alice ZZ_B="$(cat $SW/${SB:-bob.session})" ZZ_C="$(cat $SW/${SC:-carol.session})" go test ./internal/authz -run ZZSweep -count=1 -v > $SW/$4.txt 2>&1
rm internal/authz/zz_sweep_test.go
grep -E "PARSED|RSUMMARY|RFINDING|FAIL|panic" $SW/$4.txt
