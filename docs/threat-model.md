# Threat model

- Version: 0.1 (M0 draft)
- Date: 2026-11-18
- Method: STRIDE per trust boundary. Reviewed again at each milestone gate and whenever an ADR changes.

## What we protect

1. The user's machine: files, credentials, other processes.
2. Third parties: hosts the user does not own must never receive attack traffic from SiegeKit.
3. The user's target: in deployed mode, real data and real users.
4. The integrity of results: a "no findings" report must not be forgeable by the target, and must not be read as "secure".
5. The confidentiality of findings: secrets and vulnerabilities found stay on the machine.
6. SiegeKit's own release: users must be able to trust the binary they download.

## Trust boundaries

```text
 [User] --CLI--> [SiegeKit core] --container API--> [Plugin container] --egress proxy--> [Target]
                      |                                    |
                 [Findings DB]                    [Tool artifact registry]
```

- B1: user input (paths, URLs, flags) into the core.
- B2: core to container engine.
- B3: plugin container to the network (egress proxy).
- B4: tool output (untrusted) back into the core's parsers.
- B5: tool artifacts downloaded from upstream.
- B6: SiegeKit's own source and build pipeline.

## Threats and mitigations

| ID | Boundary | STRIDE | Threat | Mitigation | ADR |
| --- | --- | --- | --- | --- | --- |
| T1 | B1 | Elevation | A target path or URL containing shell metacharacters runs commands. | No shell is ever invoked; arguments are passed as a vector; placeholders are whitelisted in the manifest schema. | 0004 |
| T2 | B1/B3 | Spoofing | User (or a typo) points active tests at a host they do not own. | Local mode limited to loopback, SiegeKit containers, and confirmed private addresses; deployed mode requires per-run proof of control. Destructive checks on loopback need a typed `yes` or `--authorized-host` (`--yes` does not count), and one GET checks the target answers before any plugin runs (ADR 0023). | 0005 |
| T3 | B3 | Spoofing | DNS rebinding: the verified name later resolves to a third-party address. | Addresses pinned at verification; egress proxy allows only those addresses. | 0005, 0006 |
| T4 | B3 | Elevation | A tool follows redirects or links to other hosts. | Egress proxy denies every address not approved for this run. | 0006 |
| T5 | B2 | Elevation | A hostile repository's build script or fuzz harness escapes to the host. | Container with dropped capabilities, non-root user, read-only target mount, no secrets or engine socket mounted; rootless engine recommended. | 0006 |
| T6 | B2 | Denial of service | A fuzzer or scanner exhausts CPU, memory or disk. | Per-container CPU, memory, process and time limits; output directory size cap (512 MiB per plugin). | 0006 |
| T7 | B4 | Tampering | A scanned web app injects content that breaks our parsers or forges findings. | Memory-safe parsers in Go, strict schemas, fuzzed in CI; tool output never interpreted as commands; report files opened without following symlinks; control characters stripped from tool messages shown to the user. An OpenAPI spec fetched from the target is read by SiegeKit only for a size-limited sanity check and its base path (fuzzed), then handed to Schemathesis inside the sandbox. The login throttling check reads each answer only for its status, its `Retry-After` header and a fixed list of words, at most 2 MiB each. The access-control check reads each answer, at most 2 MiB, only to compare its status and bytes and to look for data in JSON (depth-limited), and never copies answers or headers into reports; the HAR file the user gives is size-limited, parsed as JSON and fuzzed. The rate-limit check reads each answer only for its status and header names, at most 2 MiB each, and puts only header names it matched into reports; its URL and body flags are fuzzed. | 0007, 0028, 0030, 0035, 0036 |
| T8 | B4 | Tampering | Attacker-controlled text in findings executes script in the HTML report. | Every value escaped; report has a strict Content-Security-Policy and no external resources. | 0007 |
| T9 | B4 | Information disclosure | Secrets found by scanners leak through reports or logs. | Masked by default in all outputs, including credential values that code scanners quote (snippet removed, quoted strings masked for CWE-256/259/321/798); reports stay local (mode 0600); no telemetry. | 0007 |
| T10 | B5 | Tampering | A compromised upstream release or re-pointed tag delivers malware (as in the March 2026 Trivy incident). | Version + SHA-256 pinning, signature checks where available, reviewed updates, 7-day adoption delay. | 0008 |
| T11 | B6 | Tampering | Our CI is hijacked through a mutable third-party Action or an over-privileged token. | Actions pinned by commit SHA; read-only default token; protected release environment; OIDC signing. | 0008 |
| T12 | B6 | Spoofing | A fake "SiegeKit" binary is distributed. | Signed releases with provenance; verification instructions in the README. | 0008 |
| T13 | B3 | Denial of service | Deployed-mode tests take down the user's production app or change its data. | Destructive plugins off by default, rate cap, automatic stop on repeated server errors, staging recommended. On deployed targets the egress proxy allows only GET and HEAD from non-destructive plugins, and ZAP's spider does not submit forms. Nuclei sends about 10,500 such requests per deployed scan, at 10 per second (owner decision, ADR 0026). A crawl can still follow links that change data with GET. | 0005, 0023 |
| T14 | All | Repudiation | No record of what was tested and when. | Append-only local audit log of active runs. | 0005 |
| T15 | B1/B3 | Elevation (misuse) | Someone removes or bypasses the ownership check to attack hosts they do not own. | See "Misuse by a determined attacker" below: the check stops accidents and casual misuse, not a determined attacker; SiegeKit adds no attack capability beyond the public tools it wraps. | 0005 |
| T16 | B3 | Elevation | A deployed target's name resolves to an internal or cloud-metadata address, turning SiegeKit into a path into the user's internal network. | Deployed mode refuses names resolving to loopback, private or link-local addresses; egress proxy always blocks link-local and metadata ranges. | 0005, 0006 |
| T17 | Report | Information (false assurance) | A user reads a clean report as "safe to deploy" and ships an app with flaws scanners cannot detect. | No "secure"/"passed" wording; coverage summary and "not tested" section in every report; separate exit code for incomplete runs; pre-deploy checklist. | 0009 |
| T18 | B3/B4 | Information disclosure / Tampering | Access-control replays or the live backend-rules check copy real user data into reports, or change data by replaying state-changing requests. | Response bodies truncated and personal data masked in reports; backend check is read-only; state-changing replays are `destructive` and off in deployed mode by default. | 0011, 0005 |
| T19 | B3/B5 | Elevation / Tampering | A data-update container (which has network access) is abused by a compromised tool image to reach the local network, or downloads tampered vulnerability data. | Update containers mount no target, user files or credentials and keep every other sandbox limit; the sandbox refuses network access when a target is mounted; images pinned by digest with a 7-day delay; data replaced only after a successful update and used read-only and offline. Restricting update containers to the publisher's hosts is not scheduled yet: the M2 egress proxy covers `target-only` plugins only (re-check of 2026-11-19). | 0014 |
| T20 | B1/B4 | Elevation / Denial of service | A hostile repository attacks a built-in check that runs in the SiegeKit process (symlinks out of the target, huge or deeply nested trees, crafted file contents). | Built-in checks only read files: no symlinks followed (`O_NOFOLLOW`), 1 MiB file limit, 200,000-entry and 40-level limits, dependency directories skipped, Go memory safety, fuzzed in CI. | 0015 |
| T21 | B3 | Elevation | An active tool reaches services on the user's host or local network (databases, SSH, routers) through the container network instead of the target. | The tool container has no network of its own: it joins a relay container started with `--network none`, whose only way out is a Unix socket to the SiegeKit proxy, which allows only the target. Tested: no routes, no DNS, the host bridge address unreachable. | 0018, 0019 |
| T22 | B4 | Tampering (hidden results) | The scanned repository hides findings with suppression comments or tool settings files (`# nosec`, `gitleaks:allow`, `.gitleaksignore`), so a check reports 0 findings. | Suppressions are obeyed but every report counts them and lists the settings files used; the AI assistant guide forbids adding them without the person's agreement. | 0020 |
| T23 | B5 | Tampering / Elevation | A pinned tool file (release archive or binary) is replaced at the source or in transit, or a crafted archive writes outside its directory (links, `..`, absolute paths) or fills the disk. | Downloaded by SiegeKit only after consent, over HTTPS from GitHub hosts only (redirects checked too); exact size and SHA-256 checked before unpacking; only regular files and directories unpacked, no links, absolute or parent paths, at most 2 GiB and 200,000 entries; nothing kept on failure; mounted read-only and run only in the sandbox. Upstream signatures not checked yet. | 0024, 0008 |

## Misuse by a determined attacker

SiegeKit is open source, so anyone can fork it and delete the ownership check. No design can prevent that, and we do not claim otherwise. The ownership check exists to stop **accidents** (a typo, a wrong URL) and **casual misuse** by unmodified copies.

What limits the harm a modified copy can do:

1. **No new attack capability.** SiegeKit only orchestrates tools that are already public (ZAP, Nuclei, sqlmap and others). Removing the check gives an attacker nothing they could not get by running those tools directly.
2. **Features we will not build**, in any mode: denial-of-service or load-flooding tests; scanning of address ranges, lists of targets, or the internet at large (one verified host per run); detection or WAF evasion (traffic disguising, IP rotation, proxy chains, payload obfuscation aimed at bypassing defenses); exploitation beyond proving a finding (no shells, persistence, data exfiltration or lateral movement); guessing or brute-forcing passwords through live login services (hash auditing is offline only; the capped login-throttling check on the user's own test account in [ADR 0010](adr/0010-login-checks.md) uses a known-wrong password and cannot discover passwords).
3. **Identifiable traffic.** Every HTTP request SiegeKit's plugins send carries a `User-Agent` that includes `SiegeKit/<version>` where the wrapped tool allows setting it, so defenders can recognize and block it. There is no option to remove it.
4. **Rate caps by default** in deployed mode, and an automatic stop on repeated server errors.
5. **Clear authorized-use notice** shown on first run and in the README: testing systems without permission may be illegal.

A pull request that adds any feature in point 2 will be declined, and this section may only be changed through a new ADR.

## Open questions (to resolve before the milestone noted)

- Resolved in M2.3 and M2.4: loopback targets on the host are reached through the egress proxy, which runs on the host and connects only to the pinned target addresses; the tool container has no network of its own (ADR 0019). The M2.4 container test reaches a test app on the host's loopback this way.
- Default request-rate cap for deployed mode, set from measurements on test fixtures (M2.10). Until then ADR 0023 sets provisional limits: 10 requests per second and a stop after 10 server errors in a row on deployed targets, and ZAP's attack scan does not run on them.
- ~~Output directory size cap and behavior when exceeded (M1).~~ Resolved in M1.3: 512 MiB default per plugin; exceeding it marks the plugin as failed, so the run is reported incomplete.
- Rootless Podman and rootless Docker map container users to sub-UIDs, so the output directory may not be writable with `--user <host uid>`. Needs `--userns=keep-id` (Podman) or equivalent, tested on each engine (M1.5). Status on 2026-11-19: not tested in M1; rootless Podman is part of the self-audit gate (roadmap, item 5). ADR 0006's warning when rootless mode is not used is not implemented, because recommending rootless engines waits on that test.
- ~~When SiegeKit runs as root, tools run as UID 65532 and cannot read target files that only root may read, so those files are silently not scanned. Decide before M1 ends whether to detect this and mark the plugin incomplete, or to refuse to run as root (M1.5).~~ Decided by the owner on 2026-11-19 and done: when SiegeKit runs as root, it lists the target files and directories user 65532 cannot read, and each check that needs them is marked incomplete (failed, exit code 4) with the paths and how to fix it. Its findings are kept.
- GPU pass-through isolation guarantees per engine (M3).

## Residual risks accepted

- A user who controls a host can test it; SiegeKit cannot verify legal authorization beyond technical control.
- A fork with the ownership check removed can be pointed at any host. This is mitigated only as described in "Misuse by a determined attacker".
- Container isolation is not equivalent to a VM; a kernel-level container escape in the engine is outside SiegeKit's control. Rootless mode reduces impact.
