package checks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestStorageRuleFolders(t *testing.T) {
	for _, c := range []struct {
		name, rules string
		want        []string
	}{
		{"open root", `rules_version = '2';
service firebase.storage { match /b/{bucket}/o { match /{allPaths=**} { allow read, write: if true; } } }`, nil},
		{"uploads only", `rules_version = '2';
service firebase.storage { match /b/{bucket}/o { match /uploads/{allPaths=**} { allow read, write: if true; } } }`, []string{"uploads/"}},
		{"nested and siblings", `rules_version = '2';
// match /commented/{x} { }
service firebase.storage {
  match /b/{bucket}/o {
    function signedIn() { return request.auth != null; }
    match /users/{uid} {
      match /photos/{p} { allow read: if signedIn(); }
    }
    match /public/thumbs/{f} { allow read; }
    match /a/b/c/d/{f} { allow read; }
    match /logo.png { allow read; }
  }
  match /b/other-bucket/o/x/{f} { allow read; }
}`, []string{"a/b/c/", "public/thumbs/", "users/"}},
		{"firestore rules are not storage", `service cloud.firestore { match /databases/{db}/documents { match /users/{u} { allow read; } } }`, nil},
	} {
		if got := StorageRuleFolders([]byte(c.rules)); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestReadSourceStorage(t *testing.T) {
	root := t.TempDir()
	for rel, data := range map[string]string{
		"storage.rules":   `service firebase.storage { match /b/{bucket}/o { match /uploads/{f} { allow write: if true; } } }`,
		"firestore.rules": `service cloud.firestore { match /databases/{d}/documents { match /chats/{c} { allow read; } } }`,
		"supabase/migrations/1.sql": `insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
INSERT INTO storage.buckets ("id", "name") VALUES ('docs', 'docs');
-- insert into storage.buckets (id, name) values ('commented', 'commented');
create policy "own folder" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "uploads" on storage.objects for insert to anon
  with check (bucket_id = 'docs' and ( storage.foldername(objects.name) )[1] = 'uploads');`,
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := ReadSource(context.Background(), root)
	if err != nil || !slices.Equal(s.FirebaseFolders, []string{"uploads/"}) || !slices.Equal(s.SupabaseBuckets, []string{"avatars", "docs"}) || !slices.Equal(s.SupabaseFolders, []string{"uploads/"}) {
		t.Errorf("%+v %v", s, err)
	}
}

// FuzzStorageRuleFolders checks that every folder read from rules is
// plain: at most three segments, no dot segments, ending in "/".
func FuzzStorageRuleFolders(f *testing.F) {
	f.Add("service firebase.storage { match /b/{bucket}/o { match /uploads/{f} { match /x/{y} {} } } }")
	f.Add("service firebase.storage { match /b/{bucket}/o/../x/{f} { } }")
	f.Add("service firebase.storage { match /b/{b}/o { } } } } match /b/{c}/o/a/b/{d} {")
	f.Fuzz(func(t *testing.T, data string) {
		for _, d := range StorageRuleFolders([]byte(data)) {
			segs := strings.Split(strings.TrimSuffix(d, "/"), "/")
			if !strings.HasSuffix(d, "/") || len(segs) > 3 || slices.ContainsFunc(segs, func(s string) bool { return !literalFolder(s) }) {
				t.Errorf("%q", d)
			}
		}
	})
}

// TestReadSourceKind: which backend the repository is set up for (ADR 0061).
func TestReadSourceKind(t *testing.T) {
	for _, c := range []struct {
		name               string
		files              []string
		supabase, firebase bool
	}{
		{"config only", []string{"supabase/config.toml"}, true, false},
		{"migration only", []string{"supabase/migrations/1.sql"}, true, false},
		{"nested app", []string{"apps/web/supabase/config.toml"}, true, false},
		{"seed", []string{"supabase/seed.sql"}, true, false},
		{"firebase.json", []string{"firebase.json"}, false, true},
		{"rtdb rules", []string{"database.rules.json"}, false, true},
		{"firestore rules", []string{"firestore.rules"}, false, true},
		{"storage rules", []string{"storage.rules"}, false, true},
		{"both", []string{"supabase/config.toml", "firebase.json"}, true, true},
		// A test folder is never deployed (ADR 0064 item 1): it tells no kind.
		{"tests only", []string{"supabase/tests/rls.sql", "tests/fixture/supabase/config.toml", "test/firebase.json", "__tests__/storage.rules"}, false, false},
		{"neither", []string{"config.toml", "db/schema.sql", "supabase.js", "app.rules", "node_modules/x/supabase/config.toml", "node_modules/x/firebase.json"}, false, false},
	} {
		root := t.TempDir()
		for _, f := range c.files {
			p := filepath.Join(root, filepath.FromSlash(f))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		s, err := ReadSource(context.Background(), root)
		if err != nil || s.Supabase != c.supabase || s.Firebase != c.firebase {
			t.Errorf("%s: supabase %v firebase %v %v", c.name, s.Supabase, s.Firebase, err)
		}
	}
}
