# 0012. Plugin manifest file format and validator

- Status: Accepted
- Date: 2026-11-18
- Amends: [0004](0004-plugin-manifest.md) (file name and validation mechanism only)

## Context

ADR 0004 named the manifest file `plugin.yaml` and said it is validated against the JSON Schema. Implementing that in Go would add two third-party dependencies to the core (a YAML parser and a JSON Schema validator), and ADR 0008 asks for minimal dependencies in security-relevant code.

## Decision

- Manifests are JSON files named `plugins/<id>/plugin.json`, parsed with Go's standard library only.
- Decoding is strict: unknown fields, duplicate trailing data and files larger than 64 KiB are rejected.
- The Go validator (`internal/manifest`) is the authority at build and load time. It implements every rule in `schemas/plugin-manifest.schema.json` plus rules JSON Schema cannot express (for example `timeoutSeconds <= maxTimeoutSeconds`).
- The JSON Schema stays as published documentation and for editor support. A Go test keeps the two in step: every fixture in `schemas/testdata/valid` must pass and every fixture in `schemas/testdata/invalid` must fail, and the schema's enum values must equal the Go validator's.

## Consequences

- No YAML or JSON Schema library in the core; manifests are slightly more verbose to write.
- The temporary Python fixture checker from M0 is removed.
