#!/usr/bin/env bash
# Builds the planted repository of the Porchlet run (ADR 0063): a small
# Next.js and Supabase app with one known case per secret and dependency
# rule, in the working tree and in git history. The answers are in
# testdata/known-answers/planted-secrets.json, by file and line, so keep
# every line where it is.
#
# Keys are made here at run time from a hash, so that no key, real or fake,
# is stored in SiegeKit's repository. The Supabase CLI's local keys are
# public (supabase/cli, packages/stack/src/Defaults.ts) and must stay
# unreported.
set -euo pipefail
dir="$1"
test ! -e "$dir"
mkdir -p "$dir"
cd "$dir"

# Fixed names and dates keep the commits the same on every run.
export GIT_AUTHOR_NAME=planted GIT_AUTHOR_EMAIL=planted@example.invalid
export GIT_COMMITTER_NAME=planted GIT_COMMITTER_EMAIL=planted@example.invalid
commit() {
	export GIT_AUTHOR_DATE="2026-11-23T12:0$1:00Z" GIT_COMMITTER_DATE="2026-11-23T12:0$1:00Z"
	git add -A
	git commit -q -m "$2"
}
git init -q -b main .
git config commit.gpgsign false

h() { printf '%s' "$1" | sha256sum | cut -c1-"$2"; }
b64url() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
sb="sb_"
secret_tree="${sb}secret_$(h planted-tree 32)"
secret_gone="${sb}secret_$(h planted-gone 32)"
publishable="${sb}publishable_$(h planted-publishable 32)"
cli_secret="${sb}secret_N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"
cli_publishable="${sb}publishable_ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH"
jwt="$(printf '{"alg":"HS256","typ":"JWT"}' | b64url).$(printf '{"iss":"supabase","ref":"plantedref","role":"service_role","iat":1700000000,"exp":2000000000}' | b64url).$(h planted-jwt 43)"
token="pl_tok_$(h planted-token 24)"

# Commit 1: the app. .gitignore leaves .env out (the Porchlet case);
# .env*.local stays ignored.
printf '.next/\nnode_modules/\n.env*.local\n' > .gitignore
cat > package.json <<'JSON'
{
  "name": "planted", "version": "1.0.0", "private": true,
  "dependencies": {"lodash": "4.17.20"},
  "devDependencies": {"minimist": "1.2.5"}
}
JSON
# lodash on line 5 (production), minimist on line 6 (development).
cat > package-lock.json <<'JSON'
{
  "name": "planted", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "planted", "version": "1.0.0", "dependencies": {"lodash": "4.17.20"}, "devDependencies": {"minimist": "1.2.5"}},
    "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz", "integrity": "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA=="},
    "node_modules/minimist": {"version": "1.2.5", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz", "integrity": "sha512-FM9nNUYrRBAELZQT3xeZQ7fmMOBg6nWNmJKTcgsJeaLstP/UODVpGsr5OhXhhXg6f+qtJ8uiZ+PUxkDWcgIXLw==", "dev": true}
  }
}
JSON
# The repository's own rules, as Porchlet has: Gitleaks' defaults plus one
# rule of its own, which only the repository's file knows (SK-1).
cat > .gitleaks.toml <<'TOML'
title = "planted"

[extend]
useDefault = true

[[rules]]
id = "planted-internal-token"
description = "Planted app's internal API token"
regex = '''\b(pl_tok_[0-9a-f]{24})\b'''
keywords = ["pl_tok_"]
TOML
mkdir -p src/lib
# A publishable key is public: reported as info (SK-2).
printf 'export const url = "https://plantedref.supabase.co";\nexport const publishableKey = "%s";\n' "$publishable" > src/lib/client.ts
# A secret key in the tree (SK-2).
printf 'export const secretKey = "%s";\n' "$secret_tree" > src/lib/planted.ts
# A service_role JWT (Gitleaks' jwt rule).
printf '// Legacy key.\nexport const serviceRole = "%s";\n' "$jwt" > src/lib/admin.ts
# A committed .env (dotenv-gitignore, and env-file-committed in history).
printf 'NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321\nNEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=%s\n' "$cli_publishable" > .env
commit 1 "app"

# Commit 2: a secret key and an internal token added, commit 3: deleted.
# Only the history scan sees them; the token only with the repository's
# rules (SK-1).
printf 'export const old = "%s";\nexport const internal = "%s";\n' "$secret_gone" "$token" > src/lib/old.ts
commit 2 "add old keys"
git rm -q src/lib/old.ts
commit 3 "remove old keys"

# Commit 4 (issue #82, ADR 0068): the repository's path allowlists, written
# repository-relative and anchored as in Porchlet's .gitleaks.toml, and a
# .gitleaksignore line, which Gitleaks applies to both scans. The tree scan
# must leave these files out, as the history scan does.
cat >> .gitleaks.toml <<'TOML'

[[allowlists]]
description = "Generated word list"
paths = ['''^src/lib/wordlist\.ts$''', '''(?i)^docs/sample\.ts$''']
TOML
printf 'export const words = "%s";\n' "${sb}secret_$(h planted-wordlist 32)" > src/lib/wordlist.ts
mkdir -p Docs
printf 'export const sample = "%s";\n' "${sb}secret_$(h planted-sample 32)" > Docs/Sample.ts
printf 'export const ignored = "%s";\n' "${sb}secret_$(h planted-ignored 32)" > src/lib/ignored.ts
printf 'src/lib/ignored.ts:siegekit-supabase-secret-key:1\n' > .gitleaksignore
# Ignored by .gitignore but committed (git add -f): its finding must not
# say that it is not committed (ADR 0068).
printf 'export const forced = "%s";\n' "${sb}secret_$(h planted-forced 32)" > .env.production.local
git add -f .env.production.local
commit 4 "allowlisted files and a committed ignored file"

# Not committed and ignored: the CLI's local keys, which are public.
# Nothing may be reported for this file (negative control).
printf 'SUPABASE_SECRET_KEY=%s\nNEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=%s\n' "$cli_secret" "$cli_publishable" > .env.local
test "$(git status --porcelain)" = ""
