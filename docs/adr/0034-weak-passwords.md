# 0034. Weak passwords written into files

- Status: Accepted
- Date: 2026-11-20

## Context

On 2026-11-20 the owner asked for a check that finds weak or factory-default passwords written into a project's own files, with no login attempts. The design questions ([design](https://claude.ai/artifact/2iDYSAqkwibQajztdWp678)) were answered "1b 2b 3a 4a 5a" ("let's go with that then"), after a measurement the owner asked for ("measure before decide").

Evidence:

- **Gitleaks misses them.** The pinned Gitleaks 8.30.1 reported none of 7 weak passwords planted in `.env`, Compose, YAML and Python files (2026-11-20). Its rules look for random-looking keys.
- **The SecLists list.** `Passwords/Common-Credentials/10k-most-common.txt` at commit `145f1f45ba7bc5fd6b3966d3a79bf95654deb20e` (tag 2026.2, the same commit as the ffuf list of ADR 0027) is 73,026 bytes and 10,001 lines, SHA-256 `68782d6a4a19a4768d5f15dd66bd534e7a33055cc755411e33f16d18c50fdcce`. This was checked against the file downloaded from that commit on 2026-11-20. SecLists is MIT.
- **Prototype measurement** (Python, not shipped) on 24 repositories: the 20 of the CI gate plus Spring PetClinic, Laravel, dotnet/eShop and Rails. 55 were reported: 53 true, 2 false. Without skipping, tests added 380 hits, translation files 101, comments 30 and documentation 13, nearly all noise.
- **The Go check** (this ADR) on the same 24 repositories plus 4 Java and C# apps (jhipster-sample-app `6b000b5`, macrozheng/mall `dcaa93b`, eShopOnWeb `4da8212`, nopCommerce `9cdf7a5`; shallow clones of 2026-11-20). It reported 76: 55 on the first 24, the same files and lines as the prototype, and 21 on the other 4.
  - Hand labelled: **74 true, 2 false.** The false ones are `'password' => 'hashed'` (a Laravel cast type) and `password: "--password"` (a Rails command-line flag).
  - In code, 12 hits were reported: 10 true, 2 false (the two above).
  - Not reported: 422 in tests, 138 in translation files, 31 in comments and 13 in documentation.
  - A first run had 2 more false hits in generated MyBatis code (`addCriterion("password =", value, "password")`). They were fixed before the counts above: a key that opens a string that does not close right after it is not a name being set.
  - The labelled list is in the project's shared files (`weak-password-go-check-labels-2026-11-20.json`), not in the repository. The labels are Claude's; nobody else checked them.

## Decision

1. **`weak-passwords`** is SiegeKit's own check (ADR 0015), in the `secrets` family, for directory scans. It reads files only. Nothing runs and nothing is sent anywhere, and the files are read with the limits every built-in check uses.
2. **What it reads** (answer 1b):
   - Config files: `.env*`, Dockerfiles (`ENV`, `ARG`), YAML, JSON, TOML, INI, `.cfg`, `.conf`, `.properties`, XML, SQL (`IDENTIFIED BY`, `PASSWORD '...'`), Terraform. A key that names a password is matched: `password`, `passwd`, `pwd`, `pass`, alone or after a prefix and `_`, `.` or `-`, such as `POSTGRES_PASSWORD` or `druid.pass`. `bypass` and `passage` are not.
   - Source code in JavaScript, TypeScript, Java, Kotlin, Scala, PHP, Python, Go, Ruby, C#, Rust and Swift: a quoted value set to such a key.
   - Any text file: the `user:password@` part of a URL.
   - Not read: dependency and build folders (`node_modules`, `vendor`, `.venv`, `dist`, `build`, `.next`), lock files, minified scripts and source maps, binary files.
3. **What counts as weak** (answer 2b), with the reason given in the message:
   - the value is on the SecLists list above or among 22 vendor defaults (`admin`, `root`, `postgres`, `changeme`, ...), ignoring case;
   - it equals a user name set in the same file;
   - it equals the key's name without the password word (`druid.pass=druid`);
   - it is shorter than 12 characters.
   Never reported: values that point at a variable (`${X}`, `$X`, `{{ x }}`, `#{x}`, `<%= %>`, `process.env`, `os.environ`, `getenv`), placeholders (`{password}`, `<your-password>`), `true`/`false`/`null` and similar, numbers and versions, YAML block markers, and `%s`.
4. **Skipped and counted** (answer 3a, extended after the measurement): files in test folders (`test`, `tests`, `testdata`, `fixtures`, `__tests__`, `spec`, `e2e`, `cypress`, .NET `*.Tests`, `*UnitTests`, `*FunctionalTests`, `*IntegrationTests`) or with test names (`*.spec.ts`, `*.test.js`, `*_test.go`, `test_*.py`, `*Test.java`, `*Tests.cs`, `*_spec.rb` and similar); translation folders (`i18n`, `locale`, `locales`, `lang`, `translations`, `l10n`); documentation (`.md`, `.rst`, `.adoc`, `.txt`, and `doc`, `docs`, `guides` folders); templates (`.env.example`, `*.example`, `*.sample`, `*.template`, `*.dist`, read as the file they are a template of); and code comments (lines starting with `#`, `//`, `/*`, `*`, `--`, `;` or `<!--`, Python triple-quoted strings, Ruby `=begin` blocks). The report's `result` gives the counts, for example `3 weak password(s) reported; 30 not reported: 27 in tests, 2 in translation files, 1 in comments`.
5. **Findings** (answer 4a): rule `weak-password`, severity medium, CWE-521 and CWE-798, at the file and line. The message names the key and the reason, shows the value masked (the first four characters, as for every secret, ADR 0007), and says that a development-only setting is fine only if it never reaches a deployed system.
6. **The list ships inside SiegeKit** (`internal/checks/data/`), pinned by a test of its SHA-256 and size; THIRD_PARTY.md names it.
7. **Plan** (answer 5a): M2.6d, its own PR after M2.6c.

## Consequences

- Weak and default passwords in config and code are reported for any app, whatever its language. In the sample, about 97% of reported hits were true (74 of 76).
- **Not covered:**
  - weak passwords of 12 or more characters that are not on the list, such as `mysecretpassword` or `IamUsedForTesting` (both seen in the sample);
  - weak passwords in tests, translations, documentation, templates and comments (counted, not reported);
  - passwords in binary files, images, secrets managers and CI settings;
  - passwords whose key does not name a password (`secret = "..."`, `credentials: ...`).
- A short but real password is reported too. The message says why, so it can be judged.
- The labels come from one reviewer on 28 repositories, mostly samples and deliberately vulnerable apps. False-positive rates on other code are unmeasured. The M2 milestone check triages the gate's results again.
- The binary grows by 73 KB.

## Alternatives considered

- Config files only, plus URLs (answer 1a): code added 10 true findings in the sample (NodeGoat's seed users, eShopOnWeb's default password), for 2 false.
- A list only (answer 2a): in the prototype run it caught only 13 of the 53 true findings.
- Info severity or scanning templates and tests like other files (answers 3b, 3c): about 600 extra hits in the sample, nearly all noise.
- High severity in `.env`, Compose and deploy files (answer 4b): most hits are development settings such as `postgres`/`postgres` in Compose.
