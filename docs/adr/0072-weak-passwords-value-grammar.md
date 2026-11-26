# 0072. Weak passwords: each config format reads values by its own grammar

- Status: Accepted (owner, 2026-11-26 00:58Z: "go for it then" on the R2 fix plan, PR A)
- Date: 2026-11-26
- Amends: [0034](0034-weak-passwords.md) decision 2 (what is read in SQL, Terraform and TOML files)
- Related: issue [#93](https://github.com/Gobbuwu/SiegeKit/issues/93) (`from-porchlet`)

## Context

Porchlet's R2 run (2026-11-26) got two medium `weak-password` findings on a PL/pgSQL trigger line that clears a hash column, `new.encrypted_password := '';`, shown with the value `= '';`.

Root cause (reproduced with `weakHits` at 703389e, and through SiegeKit below): every config file, `.sql`, `.tf`, `.tfvars` and `.toml` included, was read with one `key = value` line pattern. Its separator `:?[ \t]*[=:]` took the `:` of `:=` alone, so the value started at `=`; and an unquoted value was taken as a literal. That is right for `.env`, YAML, INI, `.properties` and Dockerfile `ENV`, where an unquoted value is a string, and wrong for SQL, Terraform (HCL) and TOML, where an unquoted right-hand side is an expression (`var.pw`, `gen_random_uuid()::text`, a number or a table). ADR 0034 listed SQL as `IDENTIFIED BY` and `PASSWORD '...'` only, so reading SQL with the line pattern was not the decided design.

The class: any `<password key> := <anything>` line in any config file, and any password key set to an expression in SQL, Terraform or TOML, was reported. Unit cases at 703389e (`TestWeakHitsValueGrammar`, 14 of its 19 cases fail there, the 3 CRLF cases among them): `new.encrypted_password := ''` reported as `= ''`; `v_pass := p_pass;` reported; `password = var.pw` in `.tf` reported; `password = admin` in `.toml` reported; `password = "pass"` in SQL (a column compared with a column) reported; `DB_PASSWORD := admin` in `.env` reported as `= admin`; and `  password = 'admin',` in a multi-line SQL `UPDATE` missed.

## Decision

1. **One separator token.** `:=` is matched as one separator (before `=` and `:`), and an unquoted value never starts with `=`. So `key := value` reads `value`, and `password :=` with nothing after it is no hit.
2. **Values by format:**

   | Files | Line pattern | Other patterns (unchanged) |
   |---|---|---|
   | `.env*`, Dockerfiles, YAML, JSON, INI, `.cfg`, `.conf`, `.properties`, XML | `key = value`: double-quoted, single-quoted or unquoted | JSON, XML element, `key="..."` attribute, `IDENTIFIED BY` / `PASSWORD '...'` |
   | `.tf`, `.tfvars`, `.toml` | `key = value`: quoted values only | the same four |
   | `.sql` | `key = '...'` or `key := '...'` at a line's start: single-quoted literals only (a double-quoted SQL token is an identifier), optional `;` or `,` and a `--` or MySQL `#` comment after it | JSON, XML element, `IDENTIFIED BY` / `PASSWORD '...'`, `crypt('...', ...)` (ADR 0064); not the `key="..."` attribute pattern, which reads an identifier in SQL |

3. **CRLF lines.** Every line pattern accepts a `\r` before the line's end, so files saved on Windows read the same. Before, a quoted value on a CRLF line was missed (only the unquoted pattern took the `\r` into the value). Found by the critical review sweep: without it, this change would have missed `v_pass := 'abc';` in a CRLF `.sql` file that main reported.
4. An empty literal stays skipped, so `:= ''` is no finding (ADR 0034).
5. No owner card: one root fix for one cause, no options that change coverage against each other.

## Measured (through SiegeKit)

Built binaries of main 05373ff and this change, `siegekit scan --only weak-passwords --no-save`, linux/amd64, both built with Go 1.27.4, no container engine (the check runs no container, so the engine does not matter), 2026-11-26:

- The 20 repositories of the gate's known-answer job at their pinned commits: the same findings, lines and `result` lines from both binaries, and every one matches its known-answer file exactly (terragoat `terraform/azure/sql.tf:15` and `:83` kept: quoted values).
- Porchlet `main` 381ccbf (the R2 commit): 5 reported before, 3 after. The two dropped are the issue's two lines; the 3 kept are the local stack's `postgres:postgres` URL, as in R1. The skipped counts are unchanged (1 in tests, 1 in comments).

## Consequences

- PL/pgSQL assignments and Terraform and TOML references no longer read as passwords.
- Gained: a quoted SQL literal at a line's start followed by `,` or `;` (a multi-line `UPDATE ... SET`, a PL/pgSQL `v_pass := 'abc';`) is now read; before, `,` or `;` after the closing quote made the line pattern fail or read `= 'abc';`.
- Gained: quoted values on CRLF lines in every config format.
- Lost: an unquoted TOML or HCL value is no longer read. Neither format has unquoted strings (TOML's are numbers, booleans, dates, arrays and tables; HCL's are expressions), so nothing a valid file holds is lost. A YAML or `.env` value that starts with `=` is no longer read.
- **Not covered (unchanged gap, M2 check list):** a SQL assignment that is not at a line's start, such as `UPDATE users SET password = 'hunter2';` on one line; a PL/pgSQL declaration with a type, `v_password text := 'abc';`.

## Alternatives considered

- Drop `.sql`, `.tf` and `.toml` from the line pattern only, with no `:=` token: leaves `DB_PASSWORD := admin` in other formats reading `= admin`, the same cause.
- Skip any value that starts with `=`: hides the symptom; `password = var.pw` in Terraform and SQL expressions would still be reported.
