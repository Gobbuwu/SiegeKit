package checks

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

// backendRules flags hosted-backend access rules that let anyone read or
// write data (ADR 0011 item 3, static part): Firebase security rules that
// allow access unconditionally, Realtime Database rules set to true, and
// Supabase tables created without row-level security.
const (
	backendRulesID     = "backend-rules"
	backendRulesFamily = "iac"
)

var backendRules = Check{
	ID:      backendRulesID,
	Name:    "Hosted backend access rules",
	Family:  backendRulesFamily,
	Targets: []string{"repo"},
	Run:     runBackendRules,
}

func runBackendRules(ctx context.Context, root string) ([]findings.Finding, error) {
	var out []findings.Finding
	sql := map[string][]byte{}
	err := walk(ctx, root, func(rel string) bool {
		base := path.Base(rel)
		switch {
		case strings.HasSuffix(base, ".rules"):
			return true
		case base == "database.rules.json":
			return true
		case strings.HasSuffix(base, ".sql") && isSupabasePath(rel):
			return true
		}
		return false
	}, func(rel string, data []byte) error {
		switch base := path.Base(rel); {
		case strings.HasSuffix(base, ".rules"):
			out = append(out, firebaseRules(rel, data)...)
		case base == "database.rules.json":
			out = append(out, realtimeRules(rel, data)...)
		default:
			sql[rel] = data
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out = append(out, supabaseRLS(sql)...)
	for i := range out {
		out[i].Family = backendRulesFamily
		out[i].Sources = []findings.Source{{Plugin: backendRulesID, RuleID: out[i].RuleID}}
		out[i].ComputeFingerprint()
	}
	return out, nil
}

func isSupabasePath(rel string) bool {
	return strings.HasPrefix(rel, "supabase/") || strings.Contains(rel, "/supabase/")
}

// Firebase rules (Firestore and Cloud Storage). An "allow" statement grants
// access when it has no condition or its condition is literally true.
var reAllow = regexp.MustCompile(`\ballow\s+([a-z]+(?:\s*,\s*[a-z]+)*)\s*(?:;|:\s*if\s+true\s*;)`)

func firebaseRules(rel string, data []byte) []findings.Finding {
	if !bytes.Contains(data, []byte("service ")) {
		return nil // not a Firebase rules file
	}
	clean := stripComments(data, "//")
	var out []findings.Finding
	for _, m := range reAllow.FindAllSubmatchIndex(clean, -1) {
		ops := string(clean[m[2]:m[3]])
		out = append(out, findings.Finding{
			RuleID:   "firebase-public-access",
			Title:    "Firebase security rule allows access to everyone",
			Message:  fmt.Sprintf("This rule allows %q with no condition, so anyone with the app's public config can do it without signing in. Add a condition such as request.auth != null and check that the user owns the data.", ops),
			Severity: severityFor(ops),
			CWEs:     []string{"CWE-284", "CWE-862"},
			Location: findings.Location{URI: rel, StartLine: lineOf(clean, m[0])},
			Snippet:  strings.TrimSpace(string(clean[m[0]:m[1]])),
		})
	}
	return out
}

// Writes are worse than reads, but both expose user data.
func severityFor(ops string) findings.Severity {
	for _, w := range []string{"write", "create", "update", "delete"} {
		if strings.Contains(ops, w) {
			return findings.Critical
		}
	}
	return findings.High
}

// Realtime Database rules: any ".read" or ".write" that is true (or "true").
// A pattern on the raw text is enough here and keeps line numbers exact.
var reRTDB = regexp.MustCompile(`"(\.read|\.write)"\s*:\s*(?:true|"\s*true\s*")`)

func realtimeRules(rel string, data []byte) []findings.Finding {
	var out []findings.Finding
	for _, m := range reRTDB.FindAllSubmatchIndex(data, -1) {
		out = append(out, realtimeFinding(rel, data, string(data[m[2]:m[3]]), int64(m[0])))
	}
	return out
}

func realtimeFinding(rel string, data []byte, key string, off int64) findings.Finding {
	sev := findings.High
	if key == ".write" {
		sev = findings.Critical
	}
	return findings.Finding{
		RuleID:   "firebase-rtdb-public-access",
		Title:    "Realtime Database rule allows access to everyone",
		Message:  fmt.Sprintf("%q is true, so anyone can do it without signing in. Use a condition such as \"auth != null && auth.uid === $uid\".", key),
		Severity: sev,
		CWEs:     []string{"CWE-284", "CWE-862"},
		Location: findings.Location{URI: rel, StartLine: lineOf(data, int(min(off, int64(len(data)))))},
	}
}

// Supabase: tables in the public schema (exposed through the Data API) must
// have row-level security enabled, or anyone with the public anon key can
// read and change every row.
var (
	reCreate = regexp.MustCompile(`(?i)\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?((?:"[^"]+"|[a-z_][a-z0-9_$]*)(?:\s*\.\s*(?:"[^"]+"|[a-z_][a-z0-9_$]*))?)`)
	reRLS    = regexp.MustCompile(`(?i)\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?((?:"[^"]+"|[a-z_][a-z0-9_$]*)(?:\s*\.\s*(?:"[^"]+"|[a-z_][a-z0-9_$]*))?)\s+enable\s+row\s+level\s+security`)
)

type table struct {
	rel  string
	line int
}

func supabaseRLS(files map[string][]byte) []findings.Finding {
	created := map[string]table{}
	enabled := map[string]bool{}
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels) // migrations apply in name order
	for _, rel := range rels {
		clean := stripSQLComments(files[rel])
		for _, m := range reCreate.FindAllSubmatchIndex(clean, -1) {
			name := tableName(string(clean[m[2]:m[3]]))
			if name == "" {
				continue
			}
			if _, seen := created[name]; !seen {
				created[name] = table{rel, lineOf(clean, m[0])}
			}
		}
		for _, m := range reRLS.FindAllSubmatch(clean, -1) {
			if name := tableName(string(m[1])); name != "" {
				enabled[name] = true
			}
		}
	}
	names := make([]string, 0, len(created))
	for n := range created {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []findings.Finding
	for _, n := range names {
		if enabled[n] {
			continue
		}
		t := created[n]
		out = append(out, findings.Finding{
			RuleID:   "supabase-table-without-rls",
			Title:    "Supabase table without row-level security",
			Message:  fmt.Sprintf("Table %s is created without \"alter table %s enable row level security\". Tables in the public schema are reachable with the public anon key, so anyone could read or change every row. Enable RLS and add policies.", n, n),
			Severity: findings.High,
			CWEs:     []string{"CWE-284", "CWE-862"},
			Location: findings.Location{URI: t.rel, StartLine: t.line},
		})
	}
	return out
}

// tableName normalizes a possibly schema-qualified, possibly quoted name to
// "table" for the public schema; tables in other schemas return "" because
// Supabase does not expose them by default.
func tableName(s string) string {
	parts := strings.Split(s, ".")
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, `"`) {
			p = strings.Trim(p, `"`)
		} else {
			p = strings.ToLower(p)
		}
		parts[i] = p
	}
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		if parts[0] == "public" {
			return parts[1]
		}
	}
	return ""
}

// stripComments blanks line comments starting with marker, keeping offsets
// and line numbers. It does not track strings, which is acceptable for the
// short rules files it is used on.
func stripComments(data []byte, marker string) []byte {
	out := bytes.Clone(data)
	for i := 0; i+len(marker) <= len(out); i++ {
		if string(out[i:i+len(marker)]) == marker {
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		}
	}
	return out
}

// stripSQLComments blanks "--" and "/* */" comments and the contents of
// string literals, keeping offsets and line numbers. Quoted identifiers
// ("Name") are kept.
func stripSQLComments(data []byte) []byte {
	out := bytes.Clone(data)
	var quote byte
	for i := 0; i < len(out); i++ {
		c := out[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if quote == '\'' && c != '\n' {
				out[i] = ' ' // string literals can contain SQL-looking text
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '-' && i+1 < len(out) && out[i+1] == '-':
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			for ; i < len(out) && !(out[i] == '*' && i+1 < len(out) && out[i+1] == '/'); i++ {
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
			if i+1 < len(out) {
				out[i], out[i+1] = ' ', ' '
				i++
			}
		}
	}
	return out
}

func lineOf(data []byte, off int) int {
	return bytes.Count(data[:off], []byte("\n")) + 1
}
