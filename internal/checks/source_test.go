package checks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestReadSource(t *testing.T) {
	root := t.TempDir()
	write := func(rel, data string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("supabase/migrations/001_init.sql", `-- create table ignored_comment (id int);
create table public.profiles (id uuid primary key);
CREATE TABLE IF NOT EXISTS "Orders" (id int);
create table auth.hidden (id int);
alter table profiles enable row level security;
insert into x values ('create table in_string (id int)');`)
	write("supabase/migrations/002.sql", `create table notes (id int);`)
	write("db/other.sql", `create table not_supabase (id int);`)
	write("database.rules.json", `{
  // comments are allowed
  "rules": {
    ".read": false,
    "users": {"$uid": {".read": "auth.uid === $uid"}, "public": {".read": true}},
    "messages": {".read": true},
    "$other": {}
  }
}`)
	write("api/openapi.yaml", "openapi: 3.0.0\n")
	write("swagger.json", `{"swagger":"2.0"}`)
	write("docs/openapi-notes.md", "not a spec")
	write("node_modules/x/openapi.json", "{}")
	s, err := ReadSource(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Tables, []string{"Orders", "notes", "profiles"}) {
		t.Errorf("tables %v", s.Tables)
	}
	if !slices.Equal(s.Paths, []string{"messages", "users", "users/public"}) {
		t.Errorf("paths %v", s.Paths)
	}
	var specs []string
	for _, f := range s.Specs {
		specs = append(specs, f.Rel)
	}
	if !slices.Equal(specs, []string{"swagger.json", "api/openapi.yaml"}) {
		t.Errorf("specs %v", specs)
	}
	// A rules file that is not JSON gives no paths.
	if p := rulesPaths([]byte("{not json")); p != nil {
		t.Errorf("bad rules %v", p)
	}
}
