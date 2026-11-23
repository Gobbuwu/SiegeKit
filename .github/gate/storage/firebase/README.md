The Firebase Storage rule sets v1 to v7 of ADR 0058's measurements, used by
`../gate.sh` (ADR 0059). Six of them are deliberately open. They are named
`.rules.txt` so that SiegeKit's own CI self-scan does not read them as this
repository's rules; the gate copies each one to `storage.rules`.
