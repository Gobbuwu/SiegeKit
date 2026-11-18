# 0004. Plugin manifest

- Status: Proposed
- Date: 2026-11-18

## Context

Users must be able to pick any single test, a group, or everything. The scheduler must know what each test needs (target type, CPU, GPU, network) and how dangerous it is, without hard-coding knowledge of each tool in the core.

## Decision

Each plugin is described by one declarative manifest file, `plugins/<id>/plugin.yaml`, validated against [`schemas/plugin-manifest.schema.json`](../../schemas/plugin-manifest.schema.json) at build time and again at load time. A manifest that fails validation is a fatal error, never a warning.

Key fields:

| Field | Purpose |
| --- | --- |
| `id`, `name`, `version` | Identity. `id` is lowercase, stable, and used on the command line. |
| `family` | One of `sast`, `sca`, `secrets`, `iac`, `dast`, `fuzz`, `credential-audit`. |
| `mode` | `passive` (reads local files), `active` (sends traffic to a running target) or `offline` (computes on user-supplied data). |
| `destructive` | `true` if the plugin can change or delete data on the target. Destructive plugins never run in deployed mode unless the user opts in for that run (ADR 0005). |
| `targets` | Accepted target kinds: `repo`, `url`, `openapi`, `image`, `binary`, `hashfile`. |
| `tool` | Upstream name, pinned version, SPDX license id, upstream URL, and an `artifacts` list with image digest or download URL plus SHA-256 per OS/architecture. |
| `resources` | CPU threads, memory limit, GPU (`none`, `optional`, `required`), default and maximum timeout. |
| `network` | `none` or `target-only`. There is no "unrestricted" value. |
| `run` | Argument template using only named placeholders (`{target}`, `{outdir}`, ...). No shell is ever invoked. |
| `output` | Output format the parser expects (`sarif`, `json`, ...) and parser id. |

Selection on the command line:

```text
siegekit scan <target> --only sast,secrets
siegekit scan <target> --skip dast
siegekit scan <target> --profile full
siegekit plugins list
```

Before anything runs, SiegeKit prints the resolved plan (plugins, versions, mode, target, limits) and asks for confirmation.

## Consequences

- Adding a tool is mostly a manifest plus a parser, reviewed like code.
- The schema is a security boundary: for example, the absence of an "unrestricted network" value means no manifest can ask for it.
- Argument templates without a shell remove command-injection risk from target names and paths.

## Alternatives considered

- **Go code per plugin with no manifest:** harder to review, and safety properties (network, destructive) would be scattered in code.
- **Third-party plugins loaded at runtime:** deferred until after 1.0; for now all plugins ship in the repository and are reviewed.
