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
	"github.com/Gobbuwu/SiegeKit/internal/testpath"
)

// backendRules flags hosted-backend access rules that let anyone read or
// write data (ADR 0011 item 3, static part; ADR 0064): Firebase security
// rules that allow access unconditionally or without checking who is asking,
// Realtime Database rules set to true, Supabase tables, views, policies and
// storage policies left open (supabasesql.go), and weak Supabase Auth
// settings in supabase/config.toml. Test files and folders are never read
// (testpath): they are not deployed.
const (
	backendRulesID     = "backend-rules"
	backendRulesFamily = "iac"
)

var backendRules = Check{
	ID:      backendRulesID,
	Name:    "Hosted backend access rules",
	Family:  backendRulesFamily,
	Targets: []string{"repo"},
	Run:     noResult(runBackendRules),
}

func runBackendRules(ctx context.Context, root string) ([]findings.Finding, error) {
	var out []findings.Finding
	sql := map[string][]byte{}
	err := walk(ctx, root, func(rel string) bool {
		if testpath.IsTest(rel) {
			return false
		}
		base := path.Base(rel)
		switch {
		case strings.HasSuffix(base, ".rules"):
			return true
		case base == "database.rules.json":
			return true
		case strings.HasSuffix(base, ".sql") && isSupabasePath(rel):
			return true
		case base == "config.toml" && isSupabasePath(rel):
			return true
		}
		return false
	}, func(rel string, data []byte) error {
		switch base := path.Base(rel); {
		case strings.HasSuffix(base, ".rules"):
			out = append(out, firebaseRules(rel, data)...)
		case base == "database.rules.json":
			out = append(out, realtimeRules(rel, data)...)
		case base == "config.toml":
			out = append(out, supabaseAuthConfig(rel, data)...)
		default:
			sql[rel] = data
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out = append(out, supabaseSQL(sql)...)
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
// access to everyone when it has no condition or its condition is literally
// true (firebase-public-access), or when its condition never checks who is
// asking (firebase-rule-without-auth, ADR 0064 item 4): a write limited only
// by file size, content type or the shape of the data, or a read limited
// only by time (Firestore's "test mode").
var (
	reAllow    = regexp.MustCompile(`\ballow\s+([a-z]+(?:\s*,\s*[a-z]+)*)\s*(?:;|:\s*if\b([^;]*);)`)
	reFunction = regexp.MustCompile(`\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{`)
	// Who is asking: request.auth, directly or through a function.
	reRuleAuth = regexp.MustCompile(`\brequest\s*\.\s*auth\b`)
	// What is stored: the document or object, or another document.
	reRuleData = regexp.MustCompile(`\bresource\b|\b(?:get|exists|getAfter|existsAfter)\s*\(`)
	reRuleCall = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
)

func firebaseRules(rel string, data []byte) []findings.Finding {
	if !bytes.Contains(data, []byte("service ")) {
		return nil // not a Firebase rules file
	}
	clean := stripComments(data, "//")
	authFn, dataFn := ruleFunctions(string(clean))
	ln := newLines(clean)
	var out []findings.Finding
	for _, m := range reAllow.FindAllSubmatchIndex(clean, -1) {
		ops := string(clean[m[2]:m[3]])
		loc := findings.Location{URI: rel, StartLine: ln.at(m[0])}
		snippet := strings.TrimSpace(string(clean[m[0]:m[1]]))
		cond := ""
		if m[4] >= 0 {
			cond = strings.TrimSpace(string(clean[m[4]:m[5]]))
		}
		if cond == "" || cond == "true" {
			out = append(out, findings.Finding{
				RuleID:   "firebase-public-access",
				Title:    "Firebase security rule allows access to everyone",
				Message:  fmt.Sprintf("This rule allows %q with no condition, so anyone with the app's public config can do it without signing in. Add a condition such as request.auth != null and check that the user owns the data.", ops),
				Severity: severityFor(ops),
				CWEs:     []string{"CWE-284", "CWE-862"},
				Location: loc,
				Snippet:  snippet,
			})
			continue
		}
		if cond == "false" || mentions(cond, reRuleAuth, authFn) {
			continue
		}
		// A read that depends on the stored data (resource.data.public ==
		// true) can be meant for everyone; a write never is.
		var open []string
		for _, op := range strings.Split(ops, ",") {
			op = strings.TrimSpace(op)
			if severityFor(op) == findings.Critical || !mentions(cond, reRuleData, dataFn) {
				open = append(open, op)
			}
		}
		if len(open) == 0 {
			continue
		}
		o := strings.Join(open, ", ")
		out = append(out, findings.Finding{
			RuleID:   "firebase-rule-without-auth",
			Title:    "Firebase security rule never checks who is asking",
			Message:  fmt.Sprintf("This rule allows %q when %s, a condition that never looks at request.auth, so anyone with the app's public config can do it without signing in (a size or type check limits what is written, not who writes it). Add request.auth != null and check that the user owns the data.", o, cond),
			Severity: severityFor(o),
			CWEs:     []string{"CWE-284", "CWE-862"},
			Location: loc,
			Snippet:  snippet,
		})
	}
	return out
}

// ruleFunctions returns the rules file's functions whose bodies check the
// caller (authFn) or read stored data (dataFn), directly or by calling one
// that does. It walks the call graph backwards once, so a long chain of
// functions costs linear time.
func ruleFunctions(clean string) (authFn, dataFn map[string]bool) {
	bodies := map[string]string{}
	callers := map[string][]string{} // callee -> functions that call it
	for _, m := range reFunction.FindAllStringSubmatchIndex(clean, -1) {
		name := clean[m[2]:m[3]]
		body, _ := balancedBrace(clean, m[1])
		bodies[name] = body
	}
	for name, body := range bodies {
		for _, g := range reRuleCall.FindAllStringSubmatch(body, -1) {
			if _, ok := bodies[g[1]]; ok {
				callers[g[1]] = append(callers[g[1]], name)
			}
		}
	}
	closure := func(re *regexp.Regexp) map[string]bool {
		set := map[string]bool{}
		var queue []string
		for name, body := range bodies {
			if re.MatchString(body) {
				set[name] = true
				queue = append(queue, name)
			}
		}
		for len(queue) > 0 {
			n := queue[0]
			queue = queue[1:]
			for _, c := range callers[n] {
				if !set[c] {
					set[c] = true
					queue = append(queue, c)
				}
			}
		}
		return set
	}
	return closure(reRuleAuth), closure(reRuleData)
}

// mentions reports whether s matches re or calls one of fns.
func mentions(s string, re *regexp.Regexp, fns map[string]bool) bool {
	if re.MatchString(s) {
		return true
	}
	for _, g := range reRuleCall.FindAllStringSubmatch(s, -1) {
		if fns[g[1]] {
			return true
		}
	}
	return false
}

// balancedBrace returns the text up to the brace that closes the one opened
// just before start.
func balancedBrace(s string, start int) (string, int) {
	depth := 1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return s[start:i], i + 1
			}
		}
	}
	return s[start:], len(s)
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
	ln := newLines(data)
	for _, m := range reRTDB.FindAllSubmatchIndex(data, -1) {
		out = append(out, realtimeFinding(rel, ln.at(m[0]), string(data[m[2]:m[3]])))
	}
	return out
}

func realtimeFinding(rel string, line int, key string) findings.Finding {
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
		Location: findings.Location{URI: rel, StartLine: line},
	}
}

// reCreate finds tables created in Supabase migrations for --source
// (source.go); backend-rules itself replays the migrations (supabasesql.go).
var reCreate = regexp.MustCompile(`(?i)\bcreate\s+(?:unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?((?:"[^"]+"|[a-z_][a-z0-9_$]*)(?:\s*\.\s*(?:"[^"]+"|[a-z_][a-z0-9_$]*))?)`)

// supabaseSQL replays the migrations in name order (the order Supabase
// applies them) and reports what the final schema leaves open.
func supabaseSQL(files map[string][]byte) []findings.Finding {
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	m := newSQLModel()
	for _, rel := range rels {
		m.apply(rel, files[rel])
	}
	return m.findings()
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

// lines gives line numbers for offsets met in increasing order, counting
// forward from the last one, so a file with many matches stays linear
// (lineOf on each match counts from the start: quadratic).
type lines struct {
	data      []byte
	line, off int
}

func newLines(data []byte) *lines { return &lines{data: data, line: 1} }

func (l *lines) at(off int) int {
	if off < l.off {
		return lineOf(l.data, off)
	}
	l.line += bytes.Count(l.data[l.off:off], []byte("\n"))
	l.off = off
	return l.line
}
