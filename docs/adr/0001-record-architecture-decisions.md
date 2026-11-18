# 0001. Record architecture decisions

- Status: Accepted
- Date: 2026-11-18

## Context

SiegeKit is a security tool. Design mistakes in it (for example a target check that can be bypassed) are expensive to fix after release and can harm users. The project owner asked for a plan-first process with no undocumented assumptions.

## Decision

Every significant decision is written as an ADR in `docs/adr/` and reviewed before implementation. A pull request that changes behavior covered by an ADR must reference it, and a change that contradicts an accepted ADR needs a new ADR first.

## Consequences

Slower start, but reviewers can check code against a written intent, and later contributors can see why things are the way they are.
