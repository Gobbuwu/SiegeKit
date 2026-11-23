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
	// For the storage write test (ADR 0058): folders named in Firebase
	// storage rules, and buckets and folders named in Supabase migrations.
	FirebaseFolders []string
	SupabaseBuckets []string
	SupabaseFolders []string
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
	paths, fbFolders := map[string]bool{}, map[string]bool{}
	err := walk(ctx, root, func(rel string) bool {
		base := path.Base(rel)
		return base == "database.rules.json" || reSpecName.MatchString(base) || strings.HasSuffix(base, ".rules") ||
			strings.HasSuffix(base, ".sql") && isSupabasePath(rel)
	}, func(rel string, data []byte) error {
		switch base := path.Base(rel); {
		case base == "database.rules.json":
			for _, p := range rulesPaths(data) {
				paths[p] = true
			}
		case strings.HasSuffix(base, ".rules"):
			for _, f := range StorageRuleFolders(data) {
				fbFolders[f] = true
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
	tables, buckets, sbFolders := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, data := range sql {
		clean := stripSQLComments(data)
		for _, m := range reCreate.FindAllSubmatch(clean, -1) {
			if n := tableName(string(m[1])); n != "" {
				tables[n] = true
			}
		}
		// The cleaned text blanks string literals but keeps their
		// places, so the names are read from the original.
		for _, m := range reBucketInsert.FindAllSubmatchIndex(clean, -1) {
			if b := string(data[m[2]:m[3]]); literalFolder(b) {
				buckets[b] = true
			}
		}
		for _, m := range rePolicyFolder.FindAllSubmatchIndex(clean, -1) {
			if f := string(data[m[2]:m[3]]); literalFolder(f) {
				sbFolders[f+"/"] = true
			}
		}
	}
	s.Tables, s.Paths = keys(tables), keys(paths)
	s.FirebaseFolders, s.SupabaseBuckets, s.SupabaseFolders = keys(fbFolders), keys(buckets), keys(sbFolders)
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

// Supabase storage in migrations: insert into storage.buckets (id, ...)
// values ('NAME', ...), and policies that name a top folder with
// (storage.foldername(name))[1] = 'NAME'.
var (
	reBucketInsert = regexp.MustCompile(`(?i)\binsert\s+into\s+storage\s*\.\s*buckets\s*\(\s*"?id"?\s*,[^)]*\)\s*values\s*\(\s*'([^']{1,100})'`)
	rePolicyFolder = regexp.MustCompile(`(?i)\(\s*storage\s*\.\s*foldername\s*\(\s*(?:[a-z_]+\s*\.\s*)?name\s*\)\s*\)\s*\[\s*1\s*\]\s*=\s*'([^']{1,100})'`)
	reFolderName   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	// match /PATH { in Firebase rules; a path holds no spaces.
	reMatch          = regexp.MustCompile(`\bmatch\s+(/[^\s]*)\s*\{`)
	reStorageService = regexp.MustCompile(`\bservice\s+firebase\.storage\b`)
)

func literalFolder(s string) bool {
	return reFolderName.MatchString(s) && s != "." && s != ".."
}

// StorageRuleFolders returns the folders that Firebase Cloud Storage rules
// name, at most three literal segments deep ("uploads/", "users/" from
// /users/{uid}/photos/{p}), following nested match blocks. A file that is
// not a Cloud Storage rules file gives none.
func StorageRuleFolders(data []byte) []string {
	if !reStorageService.Match(data) {
		return nil
	}
	clean := string(stripComments(data, "//"))
	type open struct {
		depth int
		path  string
	}
	var stack []open
	depth := 0
	folders := map[string]bool{}
	matches := reMatch.FindAllStringSubmatchIndex(clean, -1)
	mi := 0
	for i := 0; i < len(clean); i++ {
		if mi < len(matches) && i == matches[mi][0] {
			m := matches[mi]
			mi++
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1].path
			}
			full := parent + clean[m[2]:m[3]]
			// The match that ends on its own { opens one level.
			depth++
			stack = append(stack, open{depth, full})
			if f := ruleFolder(full); f != "" {
				folders[f] = true
			}
			i = m[1] - 1
			continue
		}
		switch clean[i] {
		case '{':
			depth++
		case '}':
			for len(stack) > 0 && stack[len(stack)-1].depth >= depth {
				stack = stack[:len(stack)-1]
			}
			depth--
		}
	}
	return keys(folders)
}

// ruleFolder is the literal folder at the start of a full match path,
// after the /b/{bucket}/o wrapper: "uploads/" from
// /b/{bucket}/o/uploads/{file}, "" from /b/{bucket}/o/{all=**}.
func ruleFolder(full string) string {
	segs := strings.Split(strings.Trim(full, "/"), "/")
	if len(segs) >= 3 && segs[0] == "b" && strings.HasPrefix(segs[1], "{") && segs[2] == "o" {
		segs = segs[3:]
	} else {
		return ""
	}
	var lit []string
	for _, s := range segs {
		if len(lit) == 3 || !literalFolder(s) {
			break
		}
		lit = append(lit, s)
	}
	// The last literal segment of a path such as /uploads/avatar.png is a
	// file, not a folder, unless a wildcard follows it.
	if len(lit) == len(segs) && len(lit) > 0 {
		lit = lit[:len(lit)-1]
	}
	if len(lit) == 0 {
		return ""
	}
	return strings.Join(lit, "/") + "/"
}
