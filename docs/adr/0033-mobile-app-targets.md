# 0033. Mobile app targets

- Status: Accepted (built in M3; two questions decided later, see Decision 4 and 5)
- Date: 2026-11-20
- Amends: [0004](0004-plugin-manifest.md) (a new target kind, when built)

## Context

The owner approved adding mobile apps as a new kind of target on 2026-11-20. These are Android `.apk` and `.aab` files and iOS `.ipa` files that the user built. The owner answered the design questions on 2026-11-20 ([design](https://claude.ai/artifact/Y2MUgNP6PpFsxrYnzJc9cD)). They asked for the claims behind each answer to be measured first. Anything not yet backed by a test, a measurement or a source is checked before it is committed (docs/milestones/README.md).

Measured on 2026-11-20 in the development sandbox (also listed in the [M2 record](../milestones/M2.md) under "Verified"):

- **MobSF**
  - Image: `opensecurity/mobile-security-framework-mobsf:v4.6.4` (GPL-3.0), the newest tag at least 7 days old.
  - Size: 733 MB to download and 2.49 GB on disk.
  - It ran with `--network none`, skipped its update, Play Store and tracker lookups, and scanned normally.
  - Scan times (after about 27 seconds to start):

    | App | Size | Scan time |
    | --- | --- | --- |
    | InsecureBankv2.apk | 3.4 MB | 24.7 s |
    | OWASP UnCrackable-Level3.apk | 1.5 MB | 12.3 s |
    | OWASP iGoat-Swift.ipa | 16.7 MB | 6.5 s |

  - Peak memory over the three scans was 1.56 GB.
  - Its JSON report gives each finding a severity, a CWE and a MASVS ID.
  - It is a web server with a REST API, not a command.
  - It skips app code under 26 library package paths such as `com/android/` and `com/google/`. InsecureBankv2, whose package is `com.android.insecurebankv2`, got no code findings, though its manifest and certificate checks ran.
  - Its code accepts `.aab` files. That was not tested, for lack of a sample.
- **mobsfscan**
  - Version 1.2.0, LGPL-3.0-or-later.
  - It needs the Semgrep engine (`semgrep==1.172.0`). Without it on the path, it silently runs only its regex rules.
  - It ran offline in about 5 seconds each on the DIVA Android and iGoat-Swift sources.
  - There is no official image or binary.
  - Its 142 rules are mostly in Semgrep format.
- **Android emulators** need hardware virtualization. GitHub's standard Linux runners have offered it since 2024-04-02 ([GitHub changelog](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/)). It was not measured here, because this machine has no `/dev/kvm`.

## Decision

1. **Milestone:** M3, next to container-image and binary targets. These are all file targets scanned offline in the sandbox (answer 1a).
2. **Tool:** MobSF static analysis only (answer 2a).
   - The plugin runs the pinned image with no network.
   - It starts MobSF's server inside the container and drives its REST API from inside the same container. Nothing leaves the sandbox.
   - The report says when the app's own code sits under one of MobSF's skipped package paths, because that code is then not analyzed.
3. **Encrypted iOS apps** (App Store downloads, FairPlay) are refused with a clear message and never decrypted (answer 3a). MobSF's IPA report has an `encrypted` field. Whether it is set for an encrypted app is checked with a real sample before this is built.
4. **Mobile source code in directory scans** is decided in M2.9, when Opengrep is pinned. M2.9 first tests whether Opengrep runs mobsfscan's LGPL rules.
   - If it does, those rules run in Opengrep, with no second engine.
   - If not, mobsfscan is used with the Semgrep engine, in an image SiegeKit builds from pinned packages.
   The owner chose Opengrep over Semgrep on 2026-11-19, which is why this is tested first.
5. **Dynamic testing** (running the app) is decided in the M3 design. First comes one measured run on a scratch branch: an Android emulator on GitHub's Linux runners plus MobSF's dynamic analysis of a test app. iOS dynamic testing needs a real device.

## Consequences

- Android and iOS apps are tested before 1.0, statically. What the app does at run time, its server APIs (a URL scan covers those), store metadata and apps the user did not build are not covered.
- A mobile scan needs a 733 MB download (2.49 GB on disk), about 30 seconds of start-up and up to about 1.6 GB of memory.
- Driving a server inside the sandbox is new plugin work: about one PR more than a plugin that runs one command (estimate).

## Alternatives considered

- A separate milestone between M3 and 1.0, or after 1.0 (answers 1b, 1c): not chosen.
- jadx plus Gitleaks, Opengrep and SiegeKit's own manifest and `Info.plist` checks (answer 2b): smaller images, but more SiegeKit code, and no iOS binary checks. MobSF's IPA report includes NX, PIE, stack canary, ARC and encryption checks.
- MobSF plus Gitleaks over the unpacked app (answer 2c): mostly overlap.
