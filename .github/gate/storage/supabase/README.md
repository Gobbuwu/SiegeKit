The Supabase Storage policy sets s1 to s7 of ADR 0058's measurements, used by
`../gate.sh` (ADR 0059). Six of them are deliberately open. They are named
`.sql.txt` so that SiegeKit's own CI self-scan, whose `backend-rules` check
reads storage policies since ADR 0064, does not read them as this
repository's migrations; the gate copies each one to
`supabase/migrations/1.sql`. The same files are the known answers of
`backend-rules`' storage policy rule (`internal/checks`, `TestStorageGateSets`).
