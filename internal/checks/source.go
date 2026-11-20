package checks

import (
	"context"
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Source is what a URL scan reads from the app's repository given with
// --source (ADR 0037, owner answers 1a and 6a): no network, the same limits
// and skipped directories as the checks.
type Source struct {
	Tables []string     // Supabase tables in the public schema, from migrations
	Paths  []string     // Realtime Database paths, from database.rules.json
	Specs  []SourceFile // OpenAPI candidates, shortest path first
}

// SourceFile is a file read from the repository.
type SourceFile struct {
	Rel  string
	Data []byte
}

var reSpecName = regexp.MustCompile(`^(?i)(openapi|swagger)[a-z0-9._-]*\.(json|ya?ml)$`)

// ReadSource reads table names, database paths and OpenAPI candidates from
// root. Spec files over MaxFileSize are skipped.
func ReadSource(ctx context.Context, root string) (Source, error) {
	var s Source
	sql := map[string][]byte{}
	paths := map[string]bool{}
	err := walk(ctx, root, func(rel string) bool {
		base := path.Base(rel)
		return base == "database.rules.json" || reSpecName.MatchString(base) ||
			strings.HasSuffix(base, ".sql") && isSupabasePath(rel)
	}, func(rel string, data []byte) error {
		switch base := path.Base(rel); {
		case base == "database.rules.json":
			for _, p := range rulesPaths(data) {
				paths[p] = true
			}
		case strings.HasSuffix(base, ".sql"):
			sql[rel] = data
		default:
			s.Specs = append(s.Specs, SourceFile{Rel: rel, Data: data})
		}
		return nil
	})
	if err != nil {
		return Source{}, err
	}
	tables := map[string]bool{}
	for _, data := range sql {
		clean := stripSQLComments(data)
		for _, m := range reCreate.FindAllSubmatch(clean, -1) {
			if n := tableName(string(m[1])); n != "" {
				tables[n] = true
			}
		}
	}
	s.Tables, s.Paths = keys(tables), keys(paths)
	sort.SliceStable(s.Specs, func(i, j int) bool {
		a, b := s.Specs[i].Rel, s.Specs[j].Rel
		if strings.Count(a, "/") != strings.Count(b, "/") {
			return strings.Count(a, "/") < strings.Count(b, "/")
		}
		return a < b
	})
	return s, nil
}

// rulesPaths returns the literal paths under "rules" in a Realtime Database
// rules file, at most two levels deep: "users" and "users/public", not
// "$uid" wildcards or ".read" rules. Line comments are allowed in the file.
func rulesPaths(data []byte) []string {
	var doc struct {
		Rules map[string]json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(stripComments(data, "//"), &doc) != nil {
		return nil
	}
	var out []string
	for k, v := range doc.Rules {
		if !literalKey(k) {
			continue
		}
		out = append(out, k)
		var child map[string]json.RawMessage
		if json.Unmarshal(v, &child) != nil {
			continue
		}
		for c := range child {
			if literalKey(c) {
				out = append(out, k+"/"+c)
			}
		}
	}
	sort.Strings(out)
	return out
}

func literalKey(k string) bool {
	return k != "" && !strings.ContainsAny(k, ".$#[]/ \t\r\n")
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
