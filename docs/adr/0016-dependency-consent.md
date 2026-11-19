# 0016. Ask before installing dependencies

- Status: Accepted
- Date: 2026-11-19
- Amends: [0006](0006-sandbox.md) (images were pulled on first use) and [0014](0014-offline-tool-data.md) (missing data failed the check)
- Amended by: [0024](0024-pinned-file-downloads.md) (pinned files are a fourth kind of dependency)

## Context

Until now `siegekit scan` pulled each tool image the first time it was needed, with no question asked. The project owner asked on 2026-11-19 that nothing be installed without the user's confirmation, that dependencies already present be reported and not reinstalled, and that tests be skipped, and listed, when the user declines a dependency. The owner accepted the six recommendations below on the same day.

SiegeKit has three kinds of dependency:

- the container engine (Docker or Podman), which runs every external tool;
- one pinned tool image per plugin;
- tool data, such as Trivy's vulnerability database (ADR 0014).

## Decision

1. **Container engine: detect, never install.** Installing one needs administrator rights and differs by operating system. SiegeKit detects it and, if it is missing, prints the install steps for the user's system and runs only the built-in checks (ADR 0015). The tests that need the engine are listed as skipped.
2. **"Installed" means the exact pinned copy.** A tool image counts as installed only when the engine already holds the image with the manifest's digest. A tool found elsewhere on the machine (for example `trivy` on the PATH) is reported as "found on your system at <path>, but SiegeKit uses its own sandboxed, pinned copy", and is never run, not even to read its version. Host tools are not pinned and do not run in the sandbox (ADR 0006, ADR 0008). Data counts as installed when its directory and update stamp exist (ADR 0014).
3. **One question before the scan.** Before anything is downloaded, SiegeKit lists every missing dependency with its download size and the tests that need it. Present dependencies are listed as "already installed" and are not downloaded again. The user answers all, none, or chooses by number. `--yes` installs everything without asking, for CI. Without an interactive terminal and without `--yes`, nothing is installed and the dependent tests are skipped.
4. **Declined dependencies skip tests, not the run.** Each test whose dependency was declined is reported as skipped with the reason "you declined <dependency>", in the terminal summary and in every report. Such a run counts as complete (exit codes are unchanged). `--require-all` makes a test skipped for a missing dependency mark the run incomplete (exit code 4, unless findings at or above `--fail-on` give exit code 3, as for any incomplete run). Tests skipped because the target has none of their files (for example gosec on a repository without Go code) do not count.
5. **Refusals are not remembered.** SiegeKit asks again on the next scan that finds the dependency missing. `--no-install` answers "none" without asking.
6. **GUI Dependencies tab (after M5).** It lists each dependency with the tests that use it, its status, version and size, and buttons to install, remove and (for data) update it. It uses the same backend as the CLI.

Downloads keep their existing safeguards: images are pulled by digest only; data updates run in the update container of ADR 0014. Download sizes are read from the registry's manifest for the pinned digest, and each manifest is checked against its digest; if the registry cannot be reached, the size is shown as not known.

## Consequences

- Scans pull nothing on their own: the engine is called with `--pull never`, and pulls happen only after consent.
- The first scan in CI needs `--yes` (or a prior `siegekit update --yes`), or its external tests are skipped.
- Download sizes must come from the registry manifest of the pinned digest, not from a hard-coded number, so they stay correct after an upgrade.
- Detecting host tools means looking up names on the PATH; host tools are never run.
- `siegekit update` downloads data without a further question (the command is the request), but asks before downloading a missing tool image.
- When the engine is installed but not working (for example the Docker daemon is stopped), the external tests are reported as failed, not skipped, so the run is incomplete.

## Alternatives considered

- Using a host-installed tool when present: faster to start, but the version is unpinned and it runs outside the sandbox. Rejected.
- Remembering "no" per dependency: fewer questions, but a forgotten refusal would quietly drop tests from later scans. Rejected.
- Installing the container engine for the user: needs administrator rights and package-manager logic for each system. Rejected.
