# 0068. Repository tools run from the repository's top level; findings in git-ignored, untracked files say so

- Status: Accepted (owner, 2026-11-25 00:54Z: "All recommended picks" on the Porchlet R1 fix plan card: Q1 A, N1 keep high with a note)
- Date: 2026-11-25
- Amends: [0020](0020-repository-suppressions.md) (the repository's settings now apply as in its own runs), [0063](0063-repo-gitleaks-rules-supabase-keys-trivy-dev-deps.md) (the tree scan reads the repository's path allowlists)
- Related: issue [#82](https://github.com/Gobbuwu/SiegeKit/issues/82) (`from-porchlet`), Porchlet R1 note N1, threat model T20, T22

## Context

Porchlet's R1 run (2026-11-24) found the `gitleaks` tree scan reporting 3 high findings in `src/lib/auth/common-passwords.ts`, a file Porchlet's `.gitleaks.toml` leaves out with `paths = ['''^src/lib/auth/common-passwords\.ts$''']`. `gitleaks-history` reported 0 on the same repository.

Cause (reproduced): the plugin ran `gitleaks dir {target}`, so Gitleaks saw `/target/src/...` with the container's working directory `/tmp`. Gitleaks matches allowlist paths and `.gitleaksignore` lines against the path it walked, so a repository-relative `^src/...` never matched. Bandit had the same cause: `bandit -r {target}` read `.bandit` exclude paths against `/target`, while the repository's own `bandit -r .` reads them against `.`. The history scan gets repository-relative paths from git and was not affected; neither was Checkov (`skip-path` measured the same from `/tmp` and from `/target`).

Note N1 of the same run: `.env.local`, ignored by Porchlet's `.env*` and never committed, was reported high by the tree scan with nothing saying so.

The measurements, through SiegeKit on fixtures and real repositories, are in the project files (`siegekit/porchlet-r1-fixes-2026-11-24.md`; CI run 45509836043 for the options on rootless Podman and Docker, amd64 and arm64).

## Decision

1. **`run.inRepoRoot`.** A plugin whose only target is `repo` can run with the repository as its working directory (`--workdir /target`, still mounted read-only) and name it `.` in its arguments; the manifest validator refuses `{target}` in its arguments, so the path the tool sees is always repository-relative. `gitleaks` (`dir .`) and `bandit` (`-r .`) use it. Every allowlist form (`^`, `(?i)^`, unanchored) and `.gitleaksignore` then apply as in the repository's own runs. Paths reported as `./x` are read as `x` (`sarif.RelURI`), so finding locations and fingerprints do not change.
2. **`output.gitIgnoredNote`.** For a secrets plugin that scans the files on disk (`gitleaks`), a finding in a file that git ignores and does not track ends with "This file is git-ignored: not committed." The severity stays: a measured `docker build` with `COPY .` and no `.dockerignore` puts a git-ignored `.env.local` in the image.
3. **"Not committed" is read from git's index, not from `.gitignore` alone.** A file can be ignored and still tracked (added with `git add -f`, or committed before the ignore line), and the round-2 prototype, which used only the `.gitignore` matcher, would have called such a file "not committed". SiegeKit reads `.git/index` itself (versions 2 to 4, SHA-1 and SHA-256 object IDs, sparse-index directory entries, the zero checksum of `index.skipHash`), checks every length, the entry order and the trailing checksum, and gives no note when it cannot read the index in full: no `.git` directory (a worktree or submodule's `.git` file), a split index, an unknown object format, a symlinked or damaged index, or one over 256 MiB. Ignore rules come from the dotenv check's matcher (`.gitignore` files and `.git/info/exclude`; not the user's global excludes file, which can only leave a note out).

## Measured (this PR, through SiegeKit)

Local: Docker 29.9.3 rootful, cgroup v1, linux/amd64, gitleaks 8.30.1 at the pinned digest; `main` 6d110a7 against this PR.

| Target | main | this PR |
|---|---|---|
| Fixture: allowlist `^a/one`, `b/two`, `(^\|/)c/three`, `(?i)^d/four` (file `D/four.ts`), `.gitleaksignore` `e/five.ts:…:1`, control `g/six` | a, D, e, g reported | g only |
| Same fixture: `.env.local` ignored, untracked | high, no note | high, "… This file is git-ignored: not committed." |
| Same fixture: `.env.production.local` ignored but committed with `git add -f` | high, no note | high, no note |
| Gate fixture `planted` (commit 4 added: `^` and `(?i)^` allowlisted files, a `.gitleaksignore` line, a committed ignored file) | allowlisted and ignored files reported by the tree scan only | tree and history scans agree; only `.env.local`'s findings carry the note (gate check) |

`gitleaks-history` was measured with a `.gitleaksignore` line on `main`: Gitleaks already applies it (it matches `file:rule:line` in every commit), so the history scan is unchanged. Bandit 1.9.4 reports `./app.py` from `-r .` and excludes `./lib/vendor` (measured natively; the pinned image runs in the container test and was measured in CI run 45509836043).

## Consequences

- A repository's allowlists, `.gitleaksignore` and `.bandit` excludes now hide findings as they do in its own runs. They stay visible: every report lists the settings files used (ADR 0020).
- Bandit changes only where `.bandit` writes a path for a different directory than the repository's own run: `exclude = app/vendor` excluded with `-r /target` and does not with `-r .`, as in the repository's own `bandit -r .` (CI run 45509836043). On the 8 real repositories of that run (NodeGoat, terragoat, awesome-compose, firebase quickstart-js, Juice Shop, nextjs-subscription-payments, flask, black) both tools' findings were identical.
- Bandit also scans paths it used to drop. Its default excludes (`.svn`, `CVS`, `.bzr`, `.hg`, `.git`, `__pycache__`, `.tox`, `.eggs`, `*.egg`) become `NAME/*` only when `os.path.isdir(NAME)` is true in the working directory (`bandit/core/manager.py`, 1.9.4); from `/tmp` none existed, so each stayed a plain substring and every path containing `.git` was dropped, `.github/` included. Found by this PR's CI self-scan: Bandit reported B310 in SiegeKit's own `.github/gate/storage/proxy.py`, which `main` never scanned. The gate proxy now uses `http.client` to its fixed loopback upstream (same answers as before on GET, POST, PUT, DELETE, HEAD, 4xx and repeated `Set-Cookie`, measured), not a suppression.
- The tool's working directory is read-only, as `/tmp` is not. Both tools ran from it on all 4 CI setups (run 45509836043) and in this PR's container test and gate.
- Bandit's `.bandit` handling is still Bandit's: SiegeKit does not rewrite it.

## Alternatives considered

- **B: keep `/target` and rewrite the repository's settings** (anchored allowlist regexes prefixed with `/target/`, `.gitleaksignore` copied with `/target/` prefixes and passed by flag). Measured: misses the `(?i)^` form and leaves Bandit wrong; a rewrite of user regexes is a second parser of Gitleaks' config.
- **N1 as info, or dropped.** Measured: hides the image path above.
- **N1 from the `.gitignore` matcher only** (the round-2 prototype): wrong for ignored files that are tracked, as above.

## Also fixed: the matcher's `[!…]` and escapes

The `.gitignore` matcher this note relies on (shared with `dotenv-gitignore`) read `[!a]` as `path.Match` does, a class holding `!` and `a`, where git negates it, and it dropped a leading backslash, so `\[!a].log` became a class too. Both are fixed: `[!` becomes `[^` outside escapes, and a leading backslash stays (`path.Match` reads `\c` as `c`). Answers checked against `git check-ignore` (git 2.43) for `[!a].log`, `[^a].log`, `\[!a].log` and `.env[!.]*`.

## Follow-up outside this decision

Trivy looks for `.trivyignore` and `trivy.yaml` in its working directory by default (`--ignorefile` and `--config` defaults in the pinned image's `filesystem --help`); its plugin still runs from `/tmp` and does not list them as repository settings, so a repository's `.trivyignore` is probably not applied today. Not measured (this sandbox cannot download Trivy's data), and whether it should be is a separate decision for the M2 milestone check.
