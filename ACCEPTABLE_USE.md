# Acceptable use policy

> This document is a template prepared without legal review. It is not legal advice.

This policy states how the SiegeKit project expects its software, documentation and community spaces to be used. It is a statement of project policy. It does not add restrictions to the [Apache License 2.0](LICENSE), which alone governs your rights to use, modify and distribute the code.

## Acceptable

- Testing software, websites, APIs, containers and infrastructure that you own or are authorized in writing to test.
- Security research on deliberately vulnerable training applications.
- Teaching and learning, using your own lab environments.

## Not acceptable

- Testing any system without the owner's authorization.
- Using SiegeKit to disrupt services, steal or destroy data, or gain unauthorized access.
- Circumventing or removing SiegeKit's ownership verification in order to test systems you are not authorized to test.

## What the project does about misuse

- **Feature scope.** The project will not add mass scanning, denial-of-service, detection-evasion, post-exploitation or live password-guessing features ([threat model](docs/threat-model.md), "Misuse by a determined attacker"). Pull requests adding them will be closed.
- **Support and community.** The maintainers will not help with, and may remove from project spaces (issues, discussions, pull requests), any request or content that seeks to use SiegeKit against systems without authorization, under the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Reporting.** If you believe SiegeKit traffic is hitting your system without your permission, its requests carry a `User-Agent` containing `SiegeKit/<version>` that you can block. The project cannot see or control who runs the software.
