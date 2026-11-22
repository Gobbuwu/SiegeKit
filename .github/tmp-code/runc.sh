# $1 har name, $2 target, $3 code dir, $4 out name
cd $GITHUB_WORKSPACE
cp $SW/zz_code_test.go.txt cmd/siegekit/zz_code_test.go
env ZZ_HAR=$SW/$1.har ZZ_TARGET=$2 ZZ_SPEC="" ZZ_CODE="$3" ZZ_USER=alice ZZ_B="$(cat $SW/${SB:-bob.session})" ZZ_C="$(cat $SW/${SC:-carol.session})" go test ./cmd/siegekit -run ZZCode -count=1 -v > $SW/$4.txt 2>&1
rm cmd/siegekit/zz_code_test.go
grep -E "CODE|PARSED|RSUMMARY|RFINDING|FAIL|panic" $SW/$4.txt
