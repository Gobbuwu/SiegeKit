# Threat model

- Version: 0.1 (M0 draft)
- Date: 2026-11-18
- Method: STRIDE per trust boundary. Reviewed again at each milestone gate and whenever an ADR changes.

## What we protect

1. The user's machine: files, credentials, other processes.
2. Third parties: hosts the user does not own must never receive attack traffic from SiegeKit.
3. The user's target: in deployed mode, real data and real users.
4. The integrity of results: a "no findings" report must not be forgeable by the target.
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
| T2 | B1/B3 | Spoofing | User (or a typo) points active tests at a host they do not own. | Local mode limited to loopback, SiegeKit containers, and confirmed private addresses; deployed mode requires per-run proof of control. | 0005 |
| T3 | B3 | Spoofing | DNS rebinding: the verified name later resolves to a third-party address. | Addresses pinned at verification; egress proxy allows only those addresses. | 0005, 0006 |
| T4 | B3 | Elevation | A tool follows redirects or links to other hosts. | Egress proxy denies every address not approved for this run. | 0006 |
| T5 | B2 | Elevation | A hostile repository's build script or fuzz harness escapes to the host. | Container with dropped capabilities, non-root user, read-only target mount, no secrets or engine socket mounted; rootless engine recommended. | 0006 |
| T6 | B2 | Denial of service | A fuzzer or scanner exhausts CPU, memory or disk. | Per-container CPU, memory, process and time limits; output directory size cap (to be set in M1). | 0006 |
| T7 | B4 | Tampering | A scanned web app injects content that breaks our parsers or forges findings. | Memory-safe parsers in Go, strict schemas, fuzzed in CI; tool output never interpreted as commands. | 0007 |
| T8 | B4 | Tampering | Attacker-controlled text in findings executes script in the HTML report. | Every value escaped; report has a strict Content-Security-Policy and no external resources. | 0007 |
| T9 | B4 | Information disclosure | Secrets found by scanners leak through reports or logs. | Masked by default in all outputs; reports stay local; no telemetry. | 0007 |
| T10 | B5 | Tampering | A compromised upstream release or re-pointed tag delivers malware (as in the March 2026 Trivy incident). | Version + SHA-256 pinning, signature checks where available, reviewed updates, 7-day adoption delay. | 0008 |
| T11 | B6 | Tampering | Our CI is hijacked through a mutable third-party Action or an over-privileged token. | Actions pinned by commit SHA; read-only default token; protected release environment; OIDC signing. | 0008 |
| T12 | B6 | Spoofing | A fake "SiegeKit" binary is distributed. | Signed releases with provenance; verification instructions in the README. | 0008 |
| T13 | B3 | Denial of service | Deployed-mode tests take down the user's production app. | Destructive plugins off by default, rate cap, automatic stop on repeated server errors, staging recommended. | 0005 |
| T14 | All | Repudiation | No record of what was tested and when. | Append-only local audit log of active runs. | 0005 |

## Open questions (to resolve before the milestone noted)

- How loopback targets on the host are reached from inside a container without giving the container general host-network access (M2). Candidate: run the app under test inside a SiegeKit-managed container, or expose only the target port through the egress proxy.
- Default request-rate cap for deployed mode, set from measurements on test fixtures (M2).
- Output directory size cap and behavior when exceeded (M1).
- GPU pass-through isolation guarantees per engine (M3).

## Residual risks accepted

- A user who controls a host can test it; SiegeKit cannot verify legal authorization beyond technical control.
- Container isolation is not equivalent to a VM; a kernel-level container escape in the engine is outside SiegeKit's control. Rootless mode reduces impact.
