#!/usr/bin/env bash
# Makes the git index files of gitstate_test.go with the git on PATH
# (git 2.43 or later for the sha256 and sparse cases). Each repository has
# the same files: a.txt, dir/b.txt, dir/sub/c.txt and a tracked file that
# .gitignore ignores, .env.local. Run from this directory.
set -euo pipefail
out="$PWD"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
make() { # name, init args, config...
	local name="$1" init="$2"; shift 2
	local d="$tmp/$name"
	git init -q $init "$d"
	cd "$d"
	git config user.name t; git config user.email t@example.invalid; git config commit.gpgsign false
	for kv in "$@"; do git config "${kv%%=*}" "${kv#*=}"; done
	mkdir -p dir/sub
	echo a > a.txt; echo b > dir/b.txt; echo c > dir/sub/c.txt
	printf '.env*.local\n' > .gitignore
	echo k > .env.local
	git add .gitignore a.txt dir
	git add -f .env.local
	git commit -q -m one
}
make v2 "" index.version=2
cp "$tmp/v2/.git/index" "$out/index-v2"
make v3 "" index.version=3
echo n > "$tmp/v3/new.txt"; (cd "$tmp/v3" && git add -N new.txt) # intent-to-add sets the extended flags
cp "$tmp/v3/.git/index" "$out/index-v3"
make v4 "" index.version=4
cp "$tmp/v4/.git/index" "$out/index-v4"
make sha256 "--object-format=sha256"
cp "$tmp/sha256/.git/index" "$out/index-sha256"
make skiphash "" index.skipHash=true
(cd "$tmp/skiphash" && touch a.txt && git update-index --refresh -q >/dev/null || true; echo x >> a.txt; git add a.txt)
cp "$tmp/skiphash/.git/index" "$out/index-skiphash"
make split "" core.splitIndex=true
(cd "$tmp/split" && git update-index --split-index)
cp "$tmp/split/.git/index" "$out/index-split"
make sparse ""
(cd "$tmp/sparse" && git sparse-checkout set --cone --sparse-index . && git sparse-checkout set --cone --sparse-index a-dir-that-does-not-exist >/dev/null 2>&1 || true)
cp "$tmp/sparse/.git/index" "$out/index-sparse"
