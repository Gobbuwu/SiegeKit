# 0015. Built-in static checks run in-process

- Status: Accepted
- Date: 2026-11-19
- Amends: [0006](0006-sandbox.md) (which runs every tool in a container) and [0011](0011-app-logic-and-ai-checks.md) item 3 (which planned the static backend-rules check as Semgrep rules)

## Context

ADR 0011 planned the static hosted-backend check (public Firebase rules, Supabase tables without row-level security) as SiegeKit-maintained Semgrep rules. The Semgrep image is published for linux/amd64 only (checked 2026-11-19), so the check would not run on Apple silicon Macs, and Semgrep itself is not yet a plugin. The check only needs to read a few small text files.

## Decision

- SiegeKit may implement a check in Go and run it in its own process when the check only reads files under the target directory, never executes anything from it, never writes, and never uses the network.
- Such checks walk the target without following symlinks, open files with `O_NOFOLLOW`, skip files over 1 MiB, stop after 200,000 entries or 40 directory levels, and skip `.git`, `node_modules`, `vendor` and virtual-environment directories.
- They are listed with the plugins (`siegekit plugins list`), selected with `--only` and `--skip`, and reported in the coverage table with tool "siegekit".
- Each one gets fixture tests and a fuzz target in CI, as parsers do (ADR 0011 consequences).
- The first such check is `backend-rules`: Firebase rules with `allow` statements that have no condition or `if true`, Realtime Database rules where `.read` or `.write` is true, and Supabase migrations (`supabase/` directories) that create public-schema tables without `enable row level security`.

## Consequences

- The check runs on every platform and needs no download.
- A bug in a built-in check runs with the user's privileges rather than in a sandbox. The limits above, Go's memory safety and fuzzing are the mitigation; anything that needs to run code from the target stays in a container.
- Pattern matching cannot follow every way RLS can be enabled (for example in a function or a later dynamic statement), so it can report a table that is in fact protected. Findings say what to check.

## Alternatives considered

- Semgrep rules, as planned: unavailable on arm64 and blocked on adding Semgrep.
- Running the SiegeKit binary itself inside a container for this check: possible later if built-in checks grow more complex; unnecessary for reading small text files.
