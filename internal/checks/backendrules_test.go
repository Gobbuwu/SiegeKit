package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Gobbuwu/SiegeKit/internal/findings"
)

func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func key(f findings.Finding) string {
	return f.RuleID + "@" + f.Location.URI + ":" + strconv.Itoa(f.Location.StartLine) + "/" + f.Severity.String()
}

func TestBackendRules(t *testing.T) {
	root := tree(t, map[string]string{
		"firestore.rules": `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // allow read, write;  (commented out, must not count)
    match /public/{doc} {
      allow read: if true;
    }
    match /users/{uid} {
      allow read, write: if request.auth != null && request.auth.uid == uid;
    }
    match /{document=**} {
      allow read, write;
    }
  }
}
`,
		"storage.rules": "service firebase.storage {\n  match /b/{bucket}/o {\n    allow read, write: if request.auth != null;\n  }\n}\n",
		"database.rules.json": `{
  "rules": {
    ".read": true,
    "private": { ".write": "auth != null" },
    "open": { ".write": "true" }
  }
}`,
		"supabase/migrations/001_init.sql": `-- create table ignored_in_comment (id int);
create table public.profiles (id uuid primary key);
CREATE TABLE IF NOT EXISTS "Notes" (id int);
create table todos (id int);
create table private.audit (id int);
/* create table also_ignored (id int); */
insert into todos values ('create table not_a_table (x int)');
`,
		"supabase/migrations/002_rls.sql": "alter table public.profiles enable row level security;\nALTER TABLE ONLY \"Notes\" ENABLE ROW LEVEL SECURITY;\n",
		"db/schema.sql":                   "create table not_supabase (id int);\n",
		"node_modules/x/firestore.rules":  "service cloud.firestore { match /{d=**} { allow read; } }",
		"other.rules":                     "allow read;\n",
	})
	fs, err := backendRules.Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs {
		got = append(got, key(f))
		if f.Family != "iac" || len(f.Sources) != 1 || f.Fingerprint == "" || len(f.CWEs) == 0 {
			t.Errorf("incomplete finding %+v", f)
		}
	}
	want := []string{
		"firebase-rtdb-public-access@database.rules.json:3/high",
		"firebase-rtdb-public-access@database.rules.json:5/critical",
		"firebase-public-access@firestore.rules:6/high",
		"firebase-public-access@firestore.rules:12/critical",
		"supabase-table-without-rls@supabase/migrations/001_init.sql:4/high",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestWalkSkipsSymlinksAndLargeFiles(t *testing.T) {
	outside := tree(t, map[string]string{"database.rules.json": `{"rules":{".read":true}}`})
	root := tree(t, map[string]string{"big/database.rules.json": `{"rules":{".read":true}}` + strings.Repeat(" ", MaxFileSize)})
	if err := os.Symlink(filepath.Join(outside, "database.rules.json"), filepath.Join(root, "database.rules.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	fs, err := backendRules.Run(context.Background(), root)
	if err != nil || len(fs) != 0 {
		t.Fatalf("followed a symlink or read a large file: %+v %v", fs, err)
	}
}

func TestRunCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := backendRules.Run(ctx, tree(t, map[string]string{"a.rules": "x"})); err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestTableName(t *testing.T) {
	for in, want := range map[string]string{
		"todos": "todos", "public.todos": "todos", `"Todos"`: "Todos", `public . "X"`: "X",
		"TODOS": "todos", "auth.users": "", "a.b.c": "",
	} {
		if got := tableName(in); got != want {
			t.Errorf("tableName(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzBackendRules(f *testing.F) {
	f.Add([]byte("service cloud.firestore { allow read, write; }"), []byte("create table t (x int); -- c\n/* x */"))
	f.Fuzz(func(t *testing.T, rules, sql []byte) {
		firebaseRules("a.rules", rules)
		realtimeRules("database.rules.json", rules)
		supabaseRLS(map[string][]byte{"supabase/m.sql": sql})
	})
}

func TestHasFile(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"vendor/x.go", "node_modules/y.py", "docs/a.md"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, p), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Files in skipped directories do not count.
	if ok, err := HasFile(context.Background(), root, []string{"*.go", "*.py"}); ok || err != nil {
		t.Errorf("skipped directories: %v %v", ok, err)
	}
	if err := os.Symlink(filepath.Join(root, "vendor/x.go"), filepath.Join(root, "link.go")); err != nil {
		t.Fatal(err)
	}
	if ok, err := HasFile(context.Background(), root, []string{"*.go"}); ok || err != nil {
		t.Errorf("symlink counted: %v %v", ok, err)
	}
	if ok, err := HasFile(context.Background(), root, []string{"*.go", "*.md"}); !ok || err != nil {
		t.Errorf("docs/a.md not found: %v %v", ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HasFile(ctx, root, []string{"*.go"}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}
