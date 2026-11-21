# 0044. What a typed confirmation can and cannot stop

- Status: Accepted
- Date: 2026-11-21
- Amends: [0035](0035-access-control-replay.md) item 11, [0037](0037-backend-live-check.md) item 3 (what the typed confirmation guarantees), the threat model rows T24 and T25

## Context

Some confirmations need a person to type an answer in a terminal: the host name of a deployed target ([agents.md](../agents.md), ADR 0017), the host name of a hosted backend (ADR 0037), and `test accounts` before `access-control` replays sessions (ADR 0035 item 11, owner Q5). No flag or environment variable skips them. ADR 0035, ADR 0037, the threat model (T24, T25) and the milestone record said that, because of this, "an AI assistant cannot confirm it for the person".

SiegeKit decides whether a person is there by checking that standard input is a terminal (`isTerminal(os.Stdin)` in `cmd/siegekit/scan.go`). Measured on 2026-11-21 (development sandbox, Linux amd64, util-linux `script` 2.39.3, the fix G build): `printf 'test accounts\n' | script -qec "siegekit scan ... --har a.har --only access-control http://127.0.0.1:3911/" /dev/null` gave SiegeKit a pseudo-terminal, the answer was read from the pipe, and `access-control` ran (3 requests). Without `script`, the same pipe made it skip with `not-confirmed`. The deployed-target and backend prompts use the same check, so the same command answers them too. That is from reading the code; it was not run against a deployed target.

Any program that can run commands can do this: `script`, `expect`, `unbuffer`, or a few lines of Python. A command-line tool cannot tell a person's keystrokes from a program's keystrokes on a pseudo-terminal.

The CI gate also needs to run `access-control` on Juice Shop, with the two accounts it creates, and it has no terminal.

## Decision

Owner, 2026-11-21, "Gate types it via a pseudo-terminal":

1. **The claims are corrected.** A typed confirmation stops accidents: a script, a pipeline, or an AI assistant that follows SiegeKit's guide. It does not stop a program that deliberately gives SiegeKit a pseudo-terminal and types the answer. A modified copy of SiegeKit can also skip it (threat model, "Misuse by a determined attacker"). ADR 0035, ADR 0037 and the threat model now say this.
2. **The agent guide forbids it.** `siegekit agents` tells AI assistants never to run SiegeKit inside `script`, `expect`, `unbuffer` or a similar program, and never to pipe or type answers to its questions. Doing so is answering for the person.
3. **The gate types `test accounts` through `script`.** This stands for the owner's confirmation, as `--authorized-host` does for the attack scan (ADR 0017): the accounts are the two the gate has just created in its own Juice Shop container. The gate also checks that the question was asked, so a run where SiegeKit stops asking fails.
4. **No new mechanism.** No flag or environment variable is added for this, and the prompts are unchanged.

## Consequences

- The confirmation is a guard against mistakes and against assistants that follow the rules, not a security boundary against software that runs commands on the person's machine. Nothing a local command-line tool does can be that boundary.
- The gate keeps checking `access-control`'s 4 findings on Juice Shop. No coverage is lost.
- An assistant that ignores the guide can still confirm. That is recorded as a known gap in the M2 record. It is not fixed, because no local mechanism is known that a program on the same machine cannot also drive.

## Alternatives considered

- **The gate skips `access-control`.** It would avoid using a pseudo-terminal in CI, but the gate would stop checking the 4 known findings. Rejected by the owner.
- **Pause and design a stronger check.** No design is known that a program with the person's shell cannot also satisfy. Examples are detecting the parent process, or a time-based check, and each can be defeated. Not chosen; it can be raised again if one is found.
